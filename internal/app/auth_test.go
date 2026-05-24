package app

import (
	"context"
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
