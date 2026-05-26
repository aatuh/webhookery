package app

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/ssrf"
)

func TestEnterpriseIdentityProviderRequiresSecurityWrite(t *testing.T) {
	store := &enterpriseFakeStore{}
	svc := NewControlService(store, ssrf.Validator{})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAuditor, Scopes: []string{"security:read"}}

	_, err := svc.CreateIdentityProvider(context.Background(), actor, CreateIdentityProviderRequest{
		Name:         "Okta",
		IssuerURL:    "https://idp.example.com",
		ClientID:     "client",
		ClientSecret: "secret",
	})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden identity provider create, got %v", err)
	}
	if store.identityTenantID != "" {
		t.Fatal("store must not be called before authorization")
	}
}

func TestCreateSCIMTokenPersistsHashOnlyAndReturnsValueOnce(t *testing.T) {
	store := &enterpriseFakeStore{}
	svc := NewControlService(store, ssrf.Validator{})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleSecurity, Scopes: []string{"security:write"}}

	created, err := svc.CreateSCIMToken(context.Background(), actor, CreateSCIMTokenRequest{Name: "Azure AD"})
	if err != nil {
		t.Fatal(err)
	}
	if created.Value == "" {
		t.Fatal("raw SCIM token was not returned on create")
	}
	if store.scimToken.Hash == "" || !strings.HasPrefix(store.scimToken.Hash, "sha256:") {
		t.Fatalf("SCIM token was not hashed at persistence boundary: %+v", store.scimToken)
	}
	if strings.Contains(store.scimToken.Hash, created.Value) {
		t.Fatal("raw SCIM token leaked into persisted hash")
	}
	if created.Token.Hash != "" {
		t.Fatal("SCIM token hash must not be exposed in create response")
	}
}

func TestCompleteOIDCCallbackValidatesIDTokenNonce(t *testing.T) {
	issuer := newFakeOIDCIssuer(t, "client", "wrong-nonce")
	store := &enterpriseFakeStore{
		idp: domain.IdentityProvider{
			ID:           "idp_1",
			TenantID:     "ten_1",
			IssuerURL:    issuer.URL,
			ClientID:     "client",
			ClientSecret: []byte("secret"),
			RedirectURI:  "https://webhookery.example/v1/auth/oidc/callback",
			State:        domain.StateActive,
		},
		loginState: domain.OIDCLoginState{
			TenantID:           "ten_1",
			IdentityProviderID: "idp_1",
			StateHash:          HashToken("state"),
			NonceHash:          HashToken("expected-nonce"),
			PKCEVerifier:       []byte("verifier"),
			ExpiresAt:          time.Now().Add(time.Hour),
		},
	}
	svc := NewControlService(store, ssrf.Validator{})

	_, err := svc.CompleteOIDCCallback(context.Background(), "state", "code", "user-agent", "127.0.0.1")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected nonce mismatch to be unauthorized, got %v", err)
	}
	if store.createdSession.SessionHash != "" {
		t.Fatal("OIDC session must not be created when nonce validation fails")
	}
}

func TestCompleteOIDCCallbackCreatesHashedSession(t *testing.T) {
	issuer := newFakeOIDCIssuer(t, "client", "expected-nonce")
	store := &enterpriseFakeStore{
		idp: domain.IdentityProvider{
			ID:                  "idp_1",
			TenantID:            "ten_1",
			IssuerURL:           issuer.URL,
			ClientID:            "client",
			ClientSecret:        []byte("secret"),
			RedirectURI:         "https://webhookery.example/v1/auth/oidc/callback",
			AllowedEmailDomains: []string{"example.com"},
			State:               domain.StateActive,
		},
		loginState: domain.OIDCLoginState{
			TenantID:           "ten_1",
			IdentityProviderID: "idp_1",
			StateHash:          HashToken("state"),
			NonceHash:          HashToken("expected-nonce"),
			PKCEVerifier:       []byte("verifier"),
			ExpiresAt:          time.Now().Add(time.Hour),
		},
	}
	svc := NewControlService(store, ssrf.Validator{})

	result, err := svc.CompleteOIDCCallback(context.Background(), "state", "code", "user-agent", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionToken == "" || store.createdSession.SessionHash == "" || !strings.HasPrefix(store.createdSession.SessionHash, "sha256:") {
		t.Fatalf("session token/hash not created correctly: result=%+v input=%+v", result, store.createdSession)
	}
	if strings.Contains(store.createdSession.SessionHash, result.SessionToken) {
		t.Fatal("raw session token leaked into persisted session hash")
	}
}

type enterpriseFakeStore struct {
	fakeControlStore
	identityTenantID string
	scimToken        domain.SCIMToken
	idp              domain.IdentityProvider
	loginState       domain.OIDCLoginState
	createdSession   OIDCSessionInput
}

func (s *enterpriseFakeStore) CreateIdentityProvider(_ context.Context, tenantID, actorID string, req CreateIdentityProviderRequest) (domain.IdentityProvider, error) {
	s.identityTenantID = tenantID
	return domain.IdentityProvider{ID: "idp_1", TenantID: tenantID, Name: req.Name, CreatedBy: actorID, State: domain.StateActive}, nil
}
func (s *enterpriseFakeStore) ListIdentityProviders(context.Context, string, int) ([]domain.IdentityProvider, error) {
	return nil, nil
}
func (s *enterpriseFakeStore) GetIdentityProvider(context.Context, string, string) (domain.IdentityProvider, error) {
	return s.idp, nil
}
func (s *enterpriseFakeStore) UpdateIdentityProvider(context.Context, string, string, string, UpdateIdentityProviderRequest) (domain.IdentityProvider, error) {
	return domain.IdentityProvider{}, nil
}
func (s *enterpriseFakeStore) DisableIdentityProvider(context.Context, string, string, string, string) (domain.IdentityProvider, error) {
	return domain.IdentityProvider{}, nil
}
func (s *enterpriseFakeStore) TestIdentityProvider(context.Context, string, string, string, string) (domain.IdentityProvider, error) {
	return domain.IdentityProvider{}, nil
}
func (s *enterpriseFakeStore) CreateOIDCLoginState(context.Context, domain.OIDCLoginState) error {
	return nil
}
func (s *enterpriseFakeStore) ConsumeOIDCLoginState(context.Context, string) (domain.OIDCLoginState, domain.IdentityProvider, error) {
	return s.loginState, s.idp, nil
}
func (s *enterpriseFakeStore) CreateOIDCSession(_ context.Context, input OIDCSessionInput) (domain.AuthSession, authz.Actor, error) {
	s.createdSession = input
	return domain.AuthSession{ID: "ses_1", TenantID: input.TenantID, UserID: "usr_1", SessionHash: input.SessionHash, State: domain.StateActive, ExpiresAt: input.ExpiresAt}, authz.Actor{ID: "usr_1", TenantID: input.TenantID, Role: authz.RoleSupport}, nil
}
func (s *enterpriseFakeStore) ListAuthSessions(context.Context, string, int) ([]domain.AuthSession, error) {
	return nil, nil
}
func (s *enterpriseFakeStore) RevokeAuthSessionByID(context.Context, string, string, string, string) (domain.AuthSession, error) {
	return domain.AuthSession{}, nil
}
func (s *enterpriseFakeStore) RevokeAuthSession(context.Context, string, string, string, string) error {
	return nil
}
func (s *enterpriseFakeStore) CurrentAuthSession(context.Context, string, string, string) (domain.AuthSession, error) {
	return domain.AuthSession{}, nil
}
func (s *enterpriseFakeStore) AuthenticateSCIMTokenHash(context.Context, string) (authz.Actor, error) {
	return authz.Actor{}, nil
}
func (s *enterpriseFakeStore) CreateSCIMToken(_ context.Context, tenantID, actorID string, token domain.SCIMToken) (domain.SCIMToken, error) {
	s.scimToken = token
	token.Hash = ""
	token.TenantID = tenantID
	token.CreatedBy = actorID
	return token, nil
}
func (s *enterpriseFakeStore) ListSCIMTokens(context.Context, string, int) ([]domain.SCIMToken, error) {
	return nil, nil
}
func (s *enterpriseFakeStore) RevokeSCIMToken(context.Context, string, string, string, string) (domain.SCIMToken, error) {
	return domain.SCIMToken{}, nil
}
func (s *enterpriseFakeStore) SCIMCreateOrReplaceUser(context.Context, string, string, SCIMUserRequest, bool) (SCIMUser, error) {
	return SCIMUser{}, nil
}
func (s *enterpriseFakeStore) SCIMListUsers(context.Context, string, int) ([]SCIMUser, error) {
	return nil, nil
}
func (s *enterpriseFakeStore) SCIMGetUser(context.Context, string, string) (SCIMUser, error) {
	return SCIMUser{}, nil
}
func (s *enterpriseFakeStore) SCIMPatchUser(context.Context, string, string, string, SCIMPatchRequest) (SCIMUser, error) {
	return SCIMUser{}, nil
}
func (s *enterpriseFakeStore) SCIMDeactivateUser(context.Context, string, string, string) (SCIMUser, error) {
	return SCIMUser{}, nil
}
func (s *enterpriseFakeStore) SCIMCreateOrReplaceGroup(context.Context, string, string, SCIMGroupRequest, bool) (SCIMGroup, error) {
	return SCIMGroup{}, nil
}
func (s *enterpriseFakeStore) SCIMListGroups(context.Context, string, int) ([]SCIMGroup, error) {
	return nil, nil
}
func (s *enterpriseFakeStore) SCIMGetGroup(context.Context, string, string) (SCIMGroup, error) {
	return SCIMGroup{}, nil
}
func (s *enterpriseFakeStore) SCIMPatchGroup(context.Context, string, string, string, SCIMPatchRequest) (SCIMGroup, error) {
	return SCIMGroup{}, nil
}
func (s *enterpriseFakeStore) SCIMDeactivateGroup(context.Context, string, string, string) (SCIMGroup, error) {
	return SCIMGroup{}, nil
}
func (s *enterpriseFakeStore) CreateRoleBinding(context.Context, string, string, CreateRoleBindingRequest) (domain.RoleBinding, error) {
	return domain.RoleBinding{}, nil
}
func (s *enterpriseFakeStore) ListRoleBindings(context.Context, string, int) ([]domain.RoleBinding, error) {
	return nil, nil
}
func (s *enterpriseFakeStore) UpdateRoleBinding(context.Context, string, string, string, UpdateRoleBindingRequest) (domain.RoleBinding, error) {
	return domain.RoleBinding{}, nil
}
func (s *enterpriseFakeStore) DisableRoleBinding(context.Context, string, string, string, string) (domain.RoleBinding, error) {
	return domain.RoleBinding{}, nil
}
func (s *enterpriseFakeStore) CreateAccessPolicyRule(context.Context, string, string, CreateAccessPolicyRuleRequest) (domain.AccessPolicyRule, error) {
	return domain.AccessPolicyRule{}, nil
}
func (s *enterpriseFakeStore) ListAccessPolicyRules(context.Context, string, int) ([]domain.AccessPolicyRule, error) {
	return nil, nil
}
func (s *enterpriseFakeStore) UpdateAccessPolicyRule(context.Context, string, string, string, UpdateAccessPolicyRuleRequest) (domain.AccessPolicyRule, error) {
	return domain.AccessPolicyRule{}, nil
}
func (s *enterpriseFakeStore) DisableAccessPolicyRule(context.Context, string, string, string, string) (domain.AccessPolicyRule, error) {
	return domain.AccessPolicyRule{}, nil
}
func (s *enterpriseFakeStore) ExplainAuthorization(context.Context, string, string, AuthzExplainRequest) (authz.Decision, error) {
	return authz.Decision{}, ErrNotFound
}

func newFakeOIDCIssuer(t *testing.T, clientID, nonce string) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuerURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(t, w, map[string]any{
			"issuer":                 issuerURL,
			"authorization_endpoint": issuerURL + "/authorize",
			"token_endpoint":         issuerURL + "/token",
			"jwks_uri":               issuerURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(t, w, map[string]any{"keys": []map[string]any{rsaJWK(&key.PublicKey, "kid-1")}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := map[string]any{
			"iss":            issuerURL,
			"sub":            "sub_123",
			"aud":            clientID,
			"nonce":          nonce,
			"email":          "person@example.com",
			"email_verified": true,
			"name":           "Person Example",
			"iat":            time.Now().Add(-time.Minute).Unix(),
			"exp":            time.Now().Add(time.Hour).Unix(),
		}
		writeTestJSON(t, w, map[string]any{
			"access_token": "access",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     signedJWT(t, key, "kid-1", claims),
		})
	})
	server := httptest.NewServer(mux)
	issuerURL = server.URL
	t.Cleanup(server.Close)
	return server
}

func signedJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	encodedHeader := encodeJWTPart(t, header)
	encodedClaims := encodeJWTPart(t, claims)
	signingInput := encodedHeader + "." + encodedClaims
	sum := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func encodeJWTPart(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func rsaJWK(key *rsa.PublicKey, kid string) map[string]any {
	exponent := big.NewInt(int64(key.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"kid": kid,
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(exponent),
	}
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}
