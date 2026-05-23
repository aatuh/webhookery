package app

import (
	"context"
	"testing"

	"webhookery/internal/authz"
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

type fakeAPIKeyLookup struct {
	actor authz.Actor
	hash  string
}

func (f *fakeAPIKeyLookup) AuthenticateAPIKey(_ context.Context, hash string) (authz.Actor, error) {
	f.hash = hash
	return f.actor, nil
}
