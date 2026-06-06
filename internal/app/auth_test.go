package app

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/ssrf"
)

func TestMultiAuthenticatorUsesDatabaseBeforeBootstrap(t *testing.T) {
	db := &fakeAPIKeyLookup{actor: authz.Actor{ID: "usr_db", TenantID: "ten_db", Role: authz.RoleOperator, Scopes: []string{"events:read"}}}
	authn := MultiAuthenticator{
		Authenticators: []Authenticator{
			APIKeyAuthenticator{Lookup: db},
			NewStaticAuthenticator("bootstrap", authz.Actor{ID: "bootstrap", TenantID: "ten_bootstrap", Role: authz.RoleOwner, Scopes: []string{"*"}}),
		},
	}
	actor, err := authn.Authenticate(context.Background(), "db-token")
	if err != nil {
		t.Fatal(err)
	}
	if actor.ID != "usr_db" || db.hash == "" {
		t.Fatalf("expected database actor and token hash, actor=%+v hash=%q", actor, db.hash)
	}
}

func TestBearerTokenParsesOnlyBearerScheme(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{header: "Bearer token", want: "token"},
		{header: "bearer   token  ", want: "token"},
		{header: "Basic token", want: ""},
		{header: "Bearer", want: ""},
		{header: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			if got := BearerToken(tt.header); got != tt.want {
				t.Fatalf("BearerToken(%q)=%q want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestStaticAuthenticatorRejectsMissingAndWrongTokens(t *testing.T) {
	authn := NewStaticAuthenticator("raw-token", authz.Actor{ID: "usr_1", TenantID: "ten_1"})
	if _, err := authn.Authenticate(context.Background(), ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected empty token rejection, got %v", err)
	}
	if _, err := authn.Authenticate(context.Background(), "wrong-token"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected wrong token rejection, got %v", err)
	}
	actor, err := authn.Authenticate(context.Background(), "raw-token")
	if err != nil {
		t.Fatal(err)
	}
	if actor.ID != "usr_1" {
		t.Fatalf("unexpected actor: %+v", actor)
	}
	if _, err := (StaticAuthenticator{}).Authenticate(context.Background(), "raw-token"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected missing hash rejection, got %v", err)
	}
}

func TestLookupAuthenticatorsHashSecretsAndRejectMissingInputs(t *testing.T) {
	ctx := context.Background()
	if _, err := (APIKeyAuthenticator{}).Authenticate(ctx, "key"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected missing API key lookup rejection, got %v", err)
	}
	if _, err := (APIKeyAuthenticator{Lookup: &fakeAPIKeyLookup{}}).Authenticate(ctx, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected empty API key rejection, got %v", err)
	}

	session := &fakeSessionLookup{actor: authz.Actor{ID: "usr_session"}}
	actor, err := (SessionAuthenticator{Lookup: session}).Authenticate(ctx, "session-token")
	if err != nil {
		t.Fatal(err)
	}
	if actor.ID != "usr_session" || session.hash != HashToken("session-token") {
		t.Fatalf("session authenticator did not hash token: actor=%+v hash=%q", actor, session.hash)
	}
	if _, err := (SessionAuthenticator{}).Authenticate(ctx, "session-token"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected missing session lookup rejection, got %v", err)
	}

	producer := &fakeProducerAccessTokenLookup{actor: authz.Actor{ID: "producer"}}
	actor, err = (ProducerTokenAuthenticator{Lookup: producer}).Authenticate(ctx, "producer-token")
	if err != nil {
		t.Fatal(err)
	}
	if actor.ID != "producer" || producer.hash != HashToken("producer-token") {
		t.Fatalf("producer token authenticator did not hash token: actor=%+v hash=%q", actor, producer.hash)
	}
	if _, err := (ProducerTokenAuthenticator{}).Authenticate(ctx, "producer-token"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected missing producer lookup rejection, got %v", err)
	}
}

func TestProducerMTLSAuthenticatorUsesCertificateFingerprint(t *testing.T) {
	ctx := context.Background()
	lookup := &fakeProducerMTLSLookup{actor: authz.Actor{ID: "producer_mtls"}}
	cert := &x509.Certificate{Raw: []byte("certificate bytes")}
	actor, err := (ProducerMTLSAuthenticator{Lookup: lookup}).AuthenticateCertificate(ctx, cert)
	if err != nil {
		t.Fatal(err)
	}
	if actor.ID != "producer_mtls" || lookup.fingerprint != CertificateFingerprintSHA256(cert) {
		t.Fatalf("mTLS authenticator did not use certificate fingerprint: actor=%+v fingerprint=%q", actor, lookup.fingerprint)
	}
	if CertificateFingerprintSHA256(nil) != "" {
		t.Fatal("nil certificate fingerprint should be empty")
	}
	if _, err := (ProducerMTLSAuthenticator{}).AuthenticateCertificate(ctx, cert); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected missing mTLS lookup rejection, got %v", err)
	}
	if _, err := (ProducerMTLSAuthenticator{Lookup: lookup}).AuthenticateCertificate(ctx, nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected nil certificate rejection, got %v", err)
	}
}

func TestMultiAuthenticatorSkipsNilAndStopsOnNonUnauthorized(t *testing.T) {
	expectedErr := errors.New("lookup unavailable")
	authn := MultiAuthenticator{Authenticators: []Authenticator{
		nil,
		stubAuthenticator{err: ErrUnauthorized},
		stubAuthenticator{err: expectedErr},
		stubAuthenticator{actor: authz.Actor{ID: "must_not_run"}},
	}}
	_, err := authn.Authenticate(context.Background(), "token")
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected non-unauthorized error to stop chain, got %v", err)
	}
}

func TestCreateAPIKeyReturnsTokenOnlyOnce(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_owner", TenantID: "ten_a", Role: authz.RoleOwner, Scopes: []string{"*"}}

	created, err := svc.CreateAPIKey(context.Background(), actor, CreateAPIKeyRequest{
		Name:   "worker",
		UserID: "usr_worker",
		Role:   authz.RoleOperator,
		Scopes: []string{"events:read", "deliveries:read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Token == "" {
		t.Fatal("new API key response must include the one-time token")
	}
	if created.Key.Last4 == "" || created.Key.Hash != "" {
		t.Fatalf("public API key metadata must include last4 but not hash: %+v", created.Key)
	}
	if store.apiKeyInput.Key.Hash == "" || store.apiKeyInput.Key.TenantID != "ten_a" {
		t.Fatalf("store must receive tenant-scoped hashed key metadata: %+v", store.apiKeyInput)
	}
}

func TestIssueProducerTokenHashesSecretAndStoresOpaqueToken(t *testing.T) {
	store := &fakeProducerTokenStore{
		client: domain.ProducerClient{
			ID:              "pcl_1",
			TenantID:        "ten_a",
			SourceID:        "src_1",
			Scopes:          []string{"events:write"},
			TokenTTLSeconds: 7200,
			State:           domain.StateActive,
		},
	}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})

	result, err := svc.IssueProducerToken(context.Background(), "pcl_1", "client-secret")
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessToken == "" || result.TokenType != "Bearer" || result.ExpiresIn != 3600 || result.Scope != "events:write" {
		t.Fatalf("unexpected token response: %+v", result)
	}
	if store.secretHash != HashToken("client-secret") {
		t.Fatalf("client secret must be hashed before lookup, got %q", store.secretHash)
	}
	stored := store.tokenInput.Token
	if stored.Hash == "" || stored.Hash == result.AccessToken || stored.TenantID != "ten_a" || stored.ClientID != "pcl_1" {
		t.Fatalf("store must receive hashed tenant-scoped access token metadata: %+v", stored)
	}
}

type fakeAPIKeyLookup struct {
	actor authz.Actor
	hash  string
}

func (f *fakeAPIKeyLookup) AuthenticateAPIKey(_ context.Context, hash string) (authz.Actor, error) {
	f.hash = hash
	return f.actor, nil
}

type fakeSessionLookup struct {
	actor authz.Actor
	hash  string
}

func (f *fakeSessionLookup) AuthenticateSession(_ context.Context, hash string) (authz.Actor, error) {
	f.hash = hash
	return f.actor, nil
}

type fakeProducerAccessTokenLookup struct {
	actor authz.Actor
	hash  string
}

func (f *fakeProducerAccessTokenLookup) AuthenticateProducerAccessToken(_ context.Context, hash string) (authz.Actor, error) {
	f.hash = hash
	return f.actor, nil
}

type fakeProducerMTLSLookup struct {
	actor       authz.Actor
	fingerprint string
}

func (f *fakeProducerMTLSLookup) AuthenticateProducerMTLSIdentity(_ context.Context, fingerprintSHA256 string) (authz.Actor, error) {
	f.fingerprint = fingerprintSHA256
	return f.actor, nil
}

type stubAuthenticator struct {
	actor authz.Actor
	err   error
}

func (s stubAuthenticator) Authenticate(context.Context, string) (authz.Actor, error) {
	if s.err != nil {
		return authz.Actor{}, s.err
	}
	return s.actor, nil
}

type fakeProducerTokenStore struct {
	fakeControlStore
	client     domain.ProducerClient
	secretHash string
	tokenInput ProducerAccessTokenCreateInput
}

func (f *fakeProducerTokenStore) AuthenticateProducerClient(_ context.Context, clientID, secretHash string) (domain.ProducerClient, error) {
	f.secretHash = secretHash
	if clientID != f.client.ID {
		return domain.ProducerClient{}, ErrUnauthorized
	}
	return f.client, nil
}

func (f *fakeProducerTokenStore) CreateProducerAccessToken(_ context.Context, input ProducerAccessTokenCreateInput) (domain.ProducerAccessToken, error) {
	f.tokenInput = input
	return input.Token, nil
}
