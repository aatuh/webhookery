package postgres

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"webhookery/internal/adapters/crypto"
	"webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/domain"
)

func TestPostgresMigrationAndAPIKeyAuthentication(t *testing.T) {
	databaseURL := os.Getenv("RANDONNEE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("RANDONNEE_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	migrationsDir := filepath.Join("..", "..", "..", "migrations")
	if err := MigrateUp(ctx, databaseURL, migrationsDir); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	box, err := crypto.NewEnvelope(key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(ctx, databaseURL, box)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	rawToken := "whkey_integration_" + time.Now().UTC().Format("20060102150405")
	tenantID := "ten_it_" + time.Now().UTC().Format("150405")
	created, err := store.CreateAPIKey(ctx, app.APIKeyCreateInput{
		Key: domain.APIKey{
			TenantID: tenantID,
			UserID:   "usr_it",
			Name:     "integration",
			Prefix:   "whkey_in",
			Last4:    "0405",
			Hash:     app.HashToken(rawToken),
			Scopes:   []string{"events:read"},
			State:    domain.StateActive,
		},
		Role:    authz.RoleOperator,
		ActorID: "usr_it",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" {
		t.Fatal("expected created API key id")
	}
	actor, err := store.AuthenticateAPIKey(ctx, app.HashToken(rawToken))
	if err != nil {
		t.Fatal(err)
	}
	if actor.TenantID != tenantID || actor.Role != authz.RoleOperator {
		t.Fatalf("unexpected actor: %+v", actor)
	}
}
