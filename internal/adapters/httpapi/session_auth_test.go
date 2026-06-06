package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/ssrf"
)

func TestControlRoutesAcceptSessionCookieWhenBearerMissing(t *testing.T) {
	server := NewServer(ServerConfig{
		Control:     NewNoopControl(),
		Auth:        app.NewStaticAuthenticator("api-key", authz.Actor{ID: "usr_api", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"*"}}),
		SessionAuth: app.NewStaticAuthenticator("session-token", authz.Actor{ID: "usr_session", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"events:read"}}),
		OpenAPI:     []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected session cookie auth to pass, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionAuthenticatorHashesRawCookieBeforeLookup(t *testing.T) {
	lookup := sessionLookupFunc(func(_ context.Context, hash string) (authz.Actor, error) {
		if hash == "raw-session" || hash == "" {
			t.Fatalf("session authenticator passed raw token to lookup: %q", hash)
		}
		return authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleSupport}, nil
	})
	_, err := (app.SessionAuthenticator{Lookup: lookup}).Authenticate(context.Background(), "raw-session")
	if err != nil {
		t.Fatal(err)
	}
}

func TestOIDCLoginRedirectsAndSetsStateCookie(t *testing.T) {
	issuer := newHTTPTestOIDCIssuer(t)
	store := &identityHTTPStore{
		idp: domain.IdentityProvider{
			ID:           "idp_1",
			TenantID:     "ten_1",
			IssuerURL:    issuer.URL,
			ClientID:     "client",
			RedirectURI:  "https://webhookery.example/v1/auth/oidc/callback",
			ClientSecret: []byte("secret"),
			State:        domain.StateActive,
		},
	}
	server := NewServer(ServerConfig{Control: app.NewControlService(store, ssrf.Validator{})})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/oidc/login?tenant_id=ten_1&provider_id=idp_1&redirect_after=https://evil.example/path", nil)

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected OIDC redirect, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.gotIdentityTenantID != "ten_1" || store.gotIdentityProviderID != "idp_1" {
		t.Fatalf("identity provider lookup tenant/provider=%q/%q", store.gotIdentityTenantID, store.gotIdentityProviderID)
	}
	cookie := responseCookie(t, rec, "webhookery_oidc_state")
	if cookie.Value == "" {
		t.Fatal("OIDC state cookie value was empty")
	}
	rawSetCookie := strings.Join(rec.Result().Header.Values("Set-Cookie"), "\n")
	for _, want := range []string{"webhookery_oidc_state=", "Path=/v1/auth/oidc", "Max-Age=600", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(rawSetCookie, want) {
			t.Fatalf("OIDC state cookie missing %q in %q", want, rawSetCookie)
		}
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Path != "/authorize" {
		t.Fatalf("redirect path=%q want /authorize", location.Path)
	}
	if got := location.Query().Get("state"); got != cookie.Value {
		t.Fatalf("redirect state=%q did not match state cookie", got)
	}
	if location.Query().Get("code_challenge") == "" {
		t.Fatal("OIDC login redirect did not include PKCE challenge")
	}
	if store.createdLoginState.StateHash == "" || strings.Contains(store.createdLoginState.StateHash, cookie.Value) {
		t.Fatalf("state was not hashed before persistence: %+v", store.createdLoginState)
	}
	if store.createdLoginState.RedirectAfter != "/" {
		t.Fatalf("unsafe redirect_after was not sanitized, got %q", store.createdLoginState.RedirectAfter)
	}
}

func TestOIDCCallbackRejectsMissingOrMismatchedStateCookie(t *testing.T) {
	store := &identityHTTPStore{}
	server := NewServer(ServerConfig{Control: app.NewControlService(store, ssrf.Validator{})})

	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
	}{
		{name: "missing cookie"},
		{name: "mismatched cookie", cookie: &http.Cookie{Name: "webhookery_oidc_state", Value: "wrong-state"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/v1/auth/oidc/callback?state=good-state&code=code", nil)
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}

			server.Routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected state mismatch to be unauthorized, got %d body=%s", rec.Code, rec.Body.String())
			}
			if store.consumedStateHash != "" {
				t.Fatalf("OIDC state was consumed before cookie validation: %q", store.consumedStateHash)
			}
		})
	}
}

func TestLogoutRevokesHashedSessionAndClearsCookie(t *testing.T) {
	store := &identityHTTPStore{}
	actor := authz.Actor{ID: "usr_session", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"security:write"}}
	server := NewServer(ServerConfig{
		Control:     app.NewControlService(store, ssrf.Validator{}),
		Auth:        app.NewStaticAuthenticator("api-token", actor),
		SessionAuth: app.NewStaticAuthenticator("raw-session-token", actor),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "raw-session-token"})

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected logout 204, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.revokedTenantID != "ten_1" || store.revokedActorID != "usr_session" || store.revokedReason != "logout" {
		t.Fatalf("unexpected revoke fields tenant=%q actor=%q reason=%q", store.revokedTenantID, store.revokedActorID, store.revokedReason)
	}
	if store.revokedSessionHash == "" || store.revokedSessionHash == "raw-session-token" || !strings.HasPrefix(store.revokedSessionHash, "sha256:") {
		t.Fatalf("raw session token reached revoke boundary: %q", store.revokedSessionHash)
	}
	rawSetCookie := strings.Join(rec.Result().Header.Values("Set-Cookie"), "\n")
	for _, want := range []string{sessionCookieName + "=", "Path=/", "Max-Age=0", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(rawSetCookie, want) {
			t.Fatalf("logout cookie missing %q in %q", want, rawSetCookie)
		}
	}
}

func TestLogoutRejectsBearerAuthWithoutSessionCookie(t *testing.T) {
	store := &identityHTTPStore{}
	actor := authz.Actor{ID: "usr_api", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"*"}}
	server := NewServer(ServerConfig{
		Control: app.NewControlService(store, ssrf.Validator{}),
		Auth:    app.NewStaticAuthenticator("api-token", actor),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer api-token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected logout without session cookie to be unauthorized, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.revokedSessionHash != "" {
		t.Fatalf("session revoke should not run without session cookie, got %q", store.revokedSessionHash)
	}
}

func TestRevokeAuthSessionUsesActorTenantAndReason(t *testing.T) {
	store := &identityHTTPStore{}
	actor := authz.Actor{ID: "usr_security", TenantID: "ten_1", Role: authz.RoleSecurity, Scopes: []string{"security:write"}}
	server := NewServer(ServerConfig{
		Control: app.NewControlService(store, ssrf.Validator{}),
		Auth:    app.NewStaticAuthenticator("api-token", actor),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/sessions/ses_2:revoke", strings.NewReader(`{"reason":"suspected compromise"}`))
	req.Header.Set("Authorization", "Bearer api-token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected session revoke 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.revokedByIDTenantID != "ten_1" || store.revokedByIDActorID != "usr_security" || store.revokedByIDSessionID != "ses_2" || store.revokedByIDReason != "suspected compromise" {
		t.Fatalf("unexpected revoke-by-id fields tenant=%q actor=%q session=%q reason=%q", store.revokedByIDTenantID, store.revokedByIDActorID, store.revokedByIDSessionID, store.revokedByIDReason)
	}
	if strings.Contains(rec.Body.String(), "suspected compromise") {
		t.Fatalf("session revoke response leaked operator reason: %s", rec.Body.String())
	}
}

func TestSCIMListUsersRequiresBearerBeforeStore(t *testing.T) {
	store := &identityHTTPStore{}
	server := NewServer(ServerConfig{Control: app.NewControlService(store, ssrf.Validator{})})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/scim/v2/Users", nil)

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing SCIM bearer token to be unauthorized, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.scimAuthCalls != 0 {
		t.Fatalf("SCIM store auth should not run for missing bearer token, calls=%d", store.scimAuthCalls)
	}
}

func TestSCIMListUsersUsesHashedBearerAndActorTenant(t *testing.T) {
	store := &identityHTTPStore{
		scimActor: authz.Actor{ID: "scim_sync", TenantID: "ten_scim", Role: authz.RoleDeveloper, Scopes: []string{"*"}},
		scimUsers: []app.SCIMUser{{
			ID:       "usr_scim",
			UserName: "person@example.com",
			Active:   true,
		}},
	}
	server := NewServer(ServerConfig{Control: app.NewControlService(store, ssrf.Validator{})})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/scim/v2/Users?limit=7", nil)
	req.Header.Set("Authorization", "Bearer raw-scim-token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected SCIM users 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.scimTokenHash == "" || store.scimTokenHash == "raw-scim-token" || !strings.HasPrefix(store.scimTokenHash, "sha256:") {
		t.Fatalf("raw SCIM token reached store boundary: %q", store.scimTokenHash)
	}
	if store.scimListTenantID != "ten_scim" || store.scimListLimit != 7 {
		t.Fatalf("SCIM list tenant/limit=%q/%d", store.scimListTenantID, store.scimListLimit)
	}
	var body struct {
		TotalResults int            `json:"totalResults"`
		Resources    []app.SCIMUser `json:"Resources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.TotalResults != 1 || len(body.Resources) != 1 || body.Resources[0].UserName != "person@example.com" {
		t.Fatalf("unexpected SCIM ListResponse: %s", rec.Body.String())
	}
}

func TestSCIMCreateUserUsesActorTenantAndID(t *testing.T) {
	store := &identityHTTPStore{
		scimActor: authz.Actor{ID: "scim_sync", TenantID: "ten_scim", Role: authz.RoleDeveloper, Scopes: []string{"*"}},
	}
	server := NewServer(ServerConfig{Control: app.NewControlService(store, ssrf.Validator{})})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scim/v2/Users", strings.NewReader(`{"userName":"new@example.com","active":true}`))
	req.Header.Set("Authorization", "Bearer raw-scim-token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected SCIM create 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.scimCreatedTenantID != "ten_scim" || store.scimCreatedActorID != "scim_sync" || store.scimCreatedReq.UserName != "new@example.com" || store.scimReplace {
		t.Fatalf("unexpected SCIM create fields tenant=%q actor=%q req=%+v replace=%v", store.scimCreatedTenantID, store.scimCreatedActorID, store.scimCreatedReq, store.scimReplace)
	}
}

func TestSCIMUserRoutesUseActorTenantAndResourceIDs(t *testing.T) {
	store := &identityHTTPStore{
		scimActor: authz.Actor{ID: "scim_sync", TenantID: "ten_scim", Role: authz.RoleDeveloper, Scopes: []string{"*"}},
	}
	server := NewServer(ServerConfig{Control: app.NewControlService(store, ssrf.Validator{})})

	req := httptest.NewRequest(http.MethodGet, "/v1/scim/v2/Users/usr_1", nil)
	req.Header.Set("Authorization", "Bearer raw-scim-token")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected SCIM get 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.scimUserTenantID != "ten_scim" || store.scimUserID != "usr_1" {
		t.Fatalf("unexpected SCIM get fields tenant=%q user=%q", store.scimUserTenantID, store.scimUserID)
	}

	req = httptest.NewRequest(http.MethodPut, "/v1/scim/v2/Users/usr_1", strings.NewReader(`{"userName":"updated@example.com","active":false}`))
	req.Header.Set("Authorization", "Bearer raw-scim-token")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected SCIM replace 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.scimCreatedTenantID != "ten_scim" || store.scimCreatedActorID != "scim_sync" || store.scimCreatedReq.ID != "usr_1" || store.scimCreatedReq.UserName != "updated@example.com" || !store.scimReplace {
		t.Fatalf("unexpected SCIM replace fields tenant=%q actor=%q req=%+v replace=%v", store.scimCreatedTenantID, store.scimCreatedActorID, store.scimCreatedReq, store.scimReplace)
	}

	req = httptest.NewRequest(http.MethodPatch, "/v1/scim/v2/Users/usr_1", strings.NewReader(`{"Operations":[{"op":"replace","path":"active","value":true}]}`))
	req.Header.Set("Authorization", "Bearer raw-scim-token")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected SCIM patch 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.scimUserTenantID != "ten_scim" || store.scimUserActorID != "scim_sync" || store.scimUserID != "usr_1" || len(store.scimUserPatchReq.Operations) != 1 {
		t.Fatalf("unexpected SCIM patch fields tenant=%q actor=%q user=%q req=%+v", store.scimUserTenantID, store.scimUserActorID, store.scimUserID, store.scimUserPatchReq)
	}

	req = httptest.NewRequest(http.MethodDelete, "/v1/scim/v2/Users/usr_1", nil)
	req.Header.Set("Authorization", "Bearer raw-scim-token")
	rec = httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected SCIM delete 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.scimUserTenantID != "ten_scim" || store.scimUserActorID != "scim_sync" || store.scimUserID != "usr_1" || !store.scimUserDeactivated {
		t.Fatalf("unexpected SCIM delete fields tenant=%q actor=%q user=%q deactivated=%v", store.scimUserTenantID, store.scimUserActorID, store.scimUserID, store.scimUserDeactivated)
	}
}

func TestSCIMGroupRoutesUseActorTenantAndResourceIDs(t *testing.T) {
	store := &identityHTTPStore{
		scimActor: authz.Actor{ID: "scim_sync", TenantID: "ten_scim", Role: authz.RoleDeveloper, Scopes: []string{"*"}},
		scimGroups: []app.SCIMGroup{{
			ID:          "grp_1",
			DisplayName: "Finance",
			Active:      true,
		}},
	}
	server := NewServer(ServerConfig{Control: app.NewControlService(store, ssrf.Validator{})})

	req := httptest.NewRequest(http.MethodGet, "/v1/scim/v2/Groups?limit=3", nil)
	req.Header.Set("Authorization", "Bearer raw-scim-token")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected SCIM groups list 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.scimGroupListTenantID != "ten_scim" || store.scimGroupListLimit != 3 {
		t.Fatalf("unexpected SCIM groups list fields tenant=%q limit=%d", store.scimGroupListTenantID, store.scimGroupListLimit)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/scim/v2/Groups", strings.NewReader(`{"displayName":"Support","members":[{"value":"usr_1"}]}`))
	req.Header.Set("Authorization", "Bearer raw-scim-token")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected SCIM group create 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.scimGroupTenantID != "ten_scim" || store.scimGroupActorID != "scim_sync" || store.scimGroupReq.DisplayName != "Support" || store.scimGroupReplace {
		t.Fatalf("unexpected SCIM group create fields tenant=%q actor=%q req=%+v replace=%v", store.scimGroupTenantID, store.scimGroupActorID, store.scimGroupReq, store.scimGroupReplace)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/scim/v2/Groups/grp_1", nil)
	req.Header.Set("Authorization", "Bearer raw-scim-token")
	rec = httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected SCIM group get 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.scimGroupTenantID != "ten_scim" || store.scimGroupID != "grp_1" {
		t.Fatalf("unexpected SCIM group get fields tenant=%q group=%q", store.scimGroupTenantID, store.scimGroupID)
	}

	req = httptest.NewRequest(http.MethodPut, "/v1/scim/v2/Groups/grp_1", strings.NewReader(`{"displayName":"Support Updated"}`))
	req.Header.Set("Authorization", "Bearer raw-scim-token")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected SCIM group replace 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.scimGroupTenantID != "ten_scim" || store.scimGroupActorID != "scim_sync" || store.scimGroupReq.ID != "grp_1" || store.scimGroupReq.DisplayName != "Support Updated" || !store.scimGroupReplace {
		t.Fatalf("unexpected SCIM group replace fields tenant=%q actor=%q req=%+v replace=%v", store.scimGroupTenantID, store.scimGroupActorID, store.scimGroupReq, store.scimGroupReplace)
	}

	req = httptest.NewRequest(http.MethodPatch, "/v1/scim/v2/Groups/grp_1", strings.NewReader(`{"Operations":[{"op":"add","path":"members","value":[{"value":"usr_2"}]}]}`))
	req.Header.Set("Authorization", "Bearer raw-scim-token")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected SCIM group patch 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.scimGroupTenantID != "ten_scim" || store.scimGroupActorID != "scim_sync" || store.scimGroupID != "grp_1" || len(store.scimGroupPatchReq.Operations) != 1 {
		t.Fatalf("unexpected SCIM group patch fields tenant=%q actor=%q group=%q req=%+v", store.scimGroupTenantID, store.scimGroupActorID, store.scimGroupID, store.scimGroupPatchReq)
	}

	req = httptest.NewRequest(http.MethodDelete, "/v1/scim/v2/Groups/grp_1", nil)
	req.Header.Set("Authorization", "Bearer raw-scim-token")
	rec = httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected SCIM group delete 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.scimGroupTenantID != "ten_scim" || store.scimGroupActorID != "scim_sync" || store.scimGroupID != "grp_1" || !store.scimGroupDeactivated {
		t.Fatalf("unexpected SCIM group delete fields tenant=%q actor=%q group=%q deactivated=%v", store.scimGroupTenantID, store.scimGroupActorID, store.scimGroupID, store.scimGroupDeactivated)
	}
}

type sessionLookupFunc func(context.Context, string) (authz.Actor, error)

func (f sessionLookupFunc) AuthenticateSession(ctx context.Context, hash string) (authz.Actor, error) {
	return f(ctx, hash)
}

func responseCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("response did not include cookie %q; set-cookie=%q", name, rec.Result().Header.Values("Set-Cookie"))
	return nil
}

func newHTTPTestOIDCIssuer(t *testing.T) *httptest.Server {
	t.Helper()
	var issuerURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                 issuerURL,
			"authorization_endpoint": issuerURL + "/authorize",
			"token_endpoint":         issuerURL + "/token",
			"jwks_uri":               issuerURL + "/jwks",
		})
	})
	server := httptest.NewServer(mux)
	issuerURL = server.URL
	t.Cleanup(server.Close)
	return server
}

type identityHTTPStore struct {
	noopControlStore

	idp                   domain.IdentityProvider
	gotIdentityTenantID   string
	gotIdentityProviderID string
	createdLoginState     domain.OIDCLoginState
	consumedStateHash     string
	createdSession        app.OIDCSessionInput

	revokedTenantID      string
	revokedActorID       string
	revokedSessionHash   string
	revokedReason        string
	revokedByIDTenantID  string
	revokedByIDActorID   string
	revokedByIDSessionID string
	revokedByIDReason    string

	currentTenantID    string
	currentActorID     string
	currentSessionHash string

	scimAuthCalls       int
	scimTokenHash       string
	scimActor           authz.Actor
	scimUsers           []app.SCIMUser
	scimListTenantID    string
	scimListLimit       int
	scimCreatedTenantID string
	scimCreatedActorID  string
	scimCreatedReq      app.SCIMUserRequest
	scimReplace         bool
	scimUserTenantID    string
	scimUserActorID     string
	scimUserID          string
	scimUserPatchReq    app.SCIMPatchRequest
	scimUserDeactivated bool

	scimGroups            []app.SCIMGroup
	scimGroupListTenantID string
	scimGroupListLimit    int
	scimGroupTenantID     string
	scimGroupActorID      string
	scimGroupID           string
	scimGroupReq          app.SCIMGroupRequest
	scimGroupReplace      bool
	scimGroupPatchReq     app.SCIMPatchRequest
	scimGroupDeactivated  bool
}

var _ app.EnterpriseIdentityStore = (*identityHTTPStore)(nil)

func (s *identityHTTPStore) CreateIdentityProvider(_ context.Context, tenantID, actorID string, req app.CreateIdentityProviderRequest) (domain.IdentityProvider, error) {
	return domain.IdentityProvider{ID: "idp_created", TenantID: tenantID, Name: req.Name, CreatedBy: actorID, State: domain.StateActive}, nil
}

func (s *identityHTTPStore) ListIdentityProviders(context.Context, string, int) ([]domain.IdentityProvider, error) {
	return nil, nil
}

func (s *identityHTTPStore) GetIdentityProvider(_ context.Context, tenantID, providerID string) (domain.IdentityProvider, error) {
	s.gotIdentityTenantID = tenantID
	s.gotIdentityProviderID = providerID
	return s.idp, nil
}

func (s *identityHTTPStore) UpdateIdentityProvider(context.Context, string, string, string, app.UpdateIdentityProviderRequest) (domain.IdentityProvider, error) {
	return domain.IdentityProvider{}, nil
}

func (s *identityHTTPStore) DisableIdentityProvider(context.Context, string, string, string, string) (domain.IdentityProvider, error) {
	return domain.IdentityProvider{}, nil
}

func (s *identityHTTPStore) TestIdentityProvider(context.Context, string, string, string, string) (domain.IdentityProvider, error) {
	return domain.IdentityProvider{}, nil
}

func (s *identityHTTPStore) CreateOIDCLoginState(_ context.Context, state domain.OIDCLoginState) error {
	s.createdLoginState = state
	return nil
}

func (s *identityHTTPStore) ConsumeOIDCLoginState(_ context.Context, stateHash string) (domain.OIDCLoginState, domain.IdentityProvider, error) {
	s.consumedStateHash = stateHash
	return domain.OIDCLoginState{TenantID: s.idp.TenantID, IdentityProviderID: s.idp.ID, ExpiresAt: time.Now().Add(time.Hour)}, s.idp, nil
}

func (s *identityHTTPStore) CreateOIDCSession(_ context.Context, input app.OIDCSessionInput) (domain.AuthSession, authz.Actor, error) {
	s.createdSession = input
	session := domain.AuthSession{ID: "ses_oidc", TenantID: input.TenantID, UserID: "usr_oidc", SessionHash: input.SessionHash, State: domain.StateActive, ExpiresAt: input.ExpiresAt}
	actor := authz.Actor{ID: "usr_oidc", TenantID: input.TenantID, Role: authz.RoleSupport, Scopes: []string{"events:read"}}
	return session, actor, nil
}

func (s *identityHTTPStore) ListAuthSessions(context.Context, string, int) ([]domain.AuthSession, error) {
	return nil, nil
}

func (s *identityHTTPStore) RevokeAuthSessionByID(_ context.Context, tenantID, sessionID, actorID, reason string) (domain.AuthSession, error) {
	s.revokedByIDTenantID = tenantID
	s.revokedByIDSessionID = sessionID
	s.revokedByIDActorID = actorID
	s.revokedByIDReason = reason
	return domain.AuthSession{ID: sessionID, TenantID: tenantID, UserID: actorID, State: "revoked", RevokedAt: time.Now().UTC()}, nil
}

func (s *identityHTTPStore) RevokeAuthSession(_ context.Context, tenantID, actorID, sessionHash, reason string) error {
	s.revokedTenantID = tenantID
	s.revokedActorID = actorID
	s.revokedSessionHash = sessionHash
	s.revokedReason = reason
	return nil
}

func (s *identityHTTPStore) CurrentAuthSession(_ context.Context, tenantID, actorID, sessionHash string) (domain.AuthSession, error) {
	s.currentTenantID = tenantID
	s.currentActorID = actorID
	s.currentSessionHash = sessionHash
	return domain.AuthSession{ID: "ses_current", TenantID: tenantID, UserID: actorID, SessionHash: sessionHash, State: domain.StateActive, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (s *identityHTTPStore) AuthenticateSCIMTokenHash(_ context.Context, tokenHash string) (authz.Actor, error) {
	s.scimAuthCalls++
	s.scimTokenHash = tokenHash
	if s.scimActor.TenantID == "" {
		return authz.Actor{}, app.ErrUnauthorized
	}
	return s.scimActor, nil
}

func (s *identityHTTPStore) CreateSCIMToken(_ context.Context, tenantID, actorID string, token domain.SCIMToken) (domain.SCIMToken, error) {
	token.Hash = ""
	token.TenantID = tenantID
	token.CreatedBy = actorID
	token.ID = "sct_1"
	return token, nil
}

func (s *identityHTTPStore) ListSCIMTokens(context.Context, string, int) ([]domain.SCIMToken, error) {
	return nil, nil
}

func (s *identityHTTPStore) RevokeSCIMToken(context.Context, string, string, string, string) (domain.SCIMToken, error) {
	return domain.SCIMToken{}, nil
}

func (s *identityHTTPStore) SCIMCreateOrReplaceUser(_ context.Context, tenantID, actorID string, req app.SCIMUserRequest, replace bool) (app.SCIMUser, error) {
	s.scimCreatedTenantID = tenantID
	s.scimCreatedActorID = actorID
	s.scimCreatedReq = req
	s.scimReplace = replace
	active := true
	if req.Active != nil {
		active = *req.Active
	}
	return app.SCIMUser{ID: "usr_created", UserName: req.UserName, DisplayName: req.DisplayName, Active: active}, nil
}

func (s *identityHTTPStore) SCIMListUsers(_ context.Context, tenantID string, limit int) ([]app.SCIMUser, error) {
	s.scimListTenantID = tenantID
	s.scimListLimit = limit
	return s.scimUsers, nil
}

func (s *identityHTTPStore) SCIMGetUser(_ context.Context, tenantID, userID string) (app.SCIMUser, error) {
	s.scimUserTenantID = tenantID
	s.scimUserID = userID
	return app.SCIMUser{ID: userID, UserName: "person@example.com", Active: true}, nil
}

func (s *identityHTTPStore) SCIMPatchUser(_ context.Context, tenantID, actorID, userID string, req app.SCIMPatchRequest) (app.SCIMUser, error) {
	s.scimUserTenantID = tenantID
	s.scimUserActorID = actorID
	s.scimUserID = userID
	s.scimUserPatchReq = req
	return app.SCIMUser{ID: userID, UserName: "person@example.com", Active: true}, nil
}

func (s *identityHTTPStore) SCIMDeactivateUser(_ context.Context, tenantID, actorID, userID string) (app.SCIMUser, error) {
	s.scimUserTenantID = tenantID
	s.scimUserActorID = actorID
	s.scimUserID = userID
	s.scimUserDeactivated = true
	return app.SCIMUser{ID: userID, UserName: "person@example.com", Active: false}, nil
}

func (s *identityHTTPStore) SCIMCreateOrReplaceGroup(_ context.Context, tenantID, actorID string, req app.SCIMGroupRequest, replace bool) (app.SCIMGroup, error) {
	s.scimGroupTenantID = tenantID
	s.scimGroupActorID = actorID
	s.scimGroupReq = req
	s.scimGroupReplace = replace
	id := req.ID
	if id == "" {
		id = "grp_created"
	}
	return app.SCIMGroup{ID: id, DisplayName: req.DisplayName, Members: req.Members, Active: true}, nil
}

func (s *identityHTTPStore) SCIMListGroups(_ context.Context, tenantID string, limit int) ([]app.SCIMGroup, error) {
	s.scimGroupListTenantID = tenantID
	s.scimGroupListLimit = limit
	return s.scimGroups, nil
}

func (s *identityHTTPStore) SCIMGetGroup(_ context.Context, tenantID, groupID string) (app.SCIMGroup, error) {
	s.scimGroupTenantID = tenantID
	s.scimGroupID = groupID
	return app.SCIMGroup{ID: groupID, DisplayName: "Finance", Active: true}, nil
}

func (s *identityHTTPStore) SCIMPatchGroup(_ context.Context, tenantID, actorID, groupID string, req app.SCIMPatchRequest) (app.SCIMGroup, error) {
	s.scimGroupTenantID = tenantID
	s.scimGroupActorID = actorID
	s.scimGroupID = groupID
	s.scimGroupPatchReq = req
	return app.SCIMGroup{ID: groupID, DisplayName: "Finance", Active: true}, nil
}

func (s *identityHTTPStore) SCIMDeactivateGroup(_ context.Context, tenantID, actorID, groupID string) (app.SCIMGroup, error) {
	s.scimGroupTenantID = tenantID
	s.scimGroupActorID = actorID
	s.scimGroupID = groupID
	s.scimGroupDeactivated = true
	return app.SCIMGroup{ID: groupID, DisplayName: "Finance", Active: false}, nil
}

func (s *identityHTTPStore) CreateRoleBinding(context.Context, string, string, app.CreateRoleBindingRequest) (domain.RoleBinding, error) {
	return domain.RoleBinding{}, nil
}

func (s *identityHTTPStore) ListRoleBindings(context.Context, string, int) ([]domain.RoleBinding, error) {
	return nil, nil
}

func (s *identityHTTPStore) UpdateRoleBinding(context.Context, string, string, string, app.UpdateRoleBindingRequest) (domain.RoleBinding, error) {
	return domain.RoleBinding{}, nil
}

func (s *identityHTTPStore) DisableRoleBinding(context.Context, string, string, string, string) (domain.RoleBinding, error) {
	return domain.RoleBinding{}, nil
}

func (s *identityHTTPStore) CreateAccessPolicyRule(context.Context, string, string, app.CreateAccessPolicyRuleRequest) (domain.AccessPolicyRule, error) {
	return domain.AccessPolicyRule{}, nil
}

func (s *identityHTTPStore) ListAccessPolicyRules(context.Context, string, int) ([]domain.AccessPolicyRule, error) {
	return nil, nil
}

func (s *identityHTTPStore) UpdateAccessPolicyRule(context.Context, string, string, string, app.UpdateAccessPolicyRuleRequest) (domain.AccessPolicyRule, error) {
	return domain.AccessPolicyRule{}, nil
}

func (s *identityHTTPStore) DisableAccessPolicyRule(context.Context, string, string, string, string) (domain.AccessPolicyRule, error) {
	return domain.AccessPolicyRule{}, nil
}

func (s *identityHTTPStore) ExplainAuthorization(context.Context, string, string, app.AuthzExplainRequest) (authz.Decision, error) {
	return authz.Decision{}, app.ErrNotFound
}
