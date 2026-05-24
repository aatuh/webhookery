package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"webhookery/internal/app"
	"webhookery/internal/authz"
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

type sessionLookupFunc func(context.Context, string) (authz.Actor, error)

func (f sessionLookupFunc) AuthenticateSession(ctx context.Context, hash string) (authz.Actor, error) {
	return f(ctx, hash)
}
