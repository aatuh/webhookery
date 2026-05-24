package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestProducerOAuthMigrationAndStoreProtectCredentials(t *testing.T) {
	up, err := os.ReadFile("../../../migrations/024_producer_trust.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(up) + "\n" + string(store)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS producer_clients",
		"tenant_id text NOT NULL REFERENCES tenants(id)",
		"CREATE TABLE IF NOT EXISTS producer_client_secrets",
		"secret_hash text NOT NULL UNIQUE",
		"CREATE TABLE IF NOT EXISTS producer_access_tokens",
		"token_hash text NOT NULL UNIQUE",
		"func (s *Store) CreateProducerClient",
		"func (s *Store) AuthenticateProducerClient",
		"func (s *Store) CreateProducerAccessToken",
		"func (s *Store) AuthenticateProducerAccessToken",
		"WHERE pc.tenant_id=$1",
		"pat.state='active'",
		"pat.expires_at > now()",
		"UPDATE producer_access_tokens SET state='revoked'",
		"producer_client.created",
		"producer_client.secret_rotated",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("producer oauth persistence missing %q", want)
		}
	}
	for _, forbidden := range []string{"client_secret text", "access_token text", "secret text NOT NULL", "token text NOT NULL"} {
		if strings.Contains(string(up), forbidden) {
			t.Fatalf("producer oauth migration contains unsafe storage marker %q", forbidden)
		}
	}
}
