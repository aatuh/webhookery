package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestEnterpriseIdentityMigrationStoresSecretsAndSessionsSafely(t *testing.T) {
	body, err := os.ReadFile("../../../migrations/022_enterprise_identity.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	for _, want := range []string{
		"identity_providers",
		"encrypted_client_secret bytea NOT NULL",
		"external_identities",
		"auth_sessions",
		"session_hash text NOT NULL UNIQUE",
		"scim_tokens",
		"token_hash text NOT NULL UNIQUE",
		"scim_groups",
		"role_bindings",
		"access_policy_rules",
		"authz_decision_logs",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("enterprise identity migration missing %q", want)
		}
	}
	for _, forbidden := range []string{"session_token", "plaintext", "client_secret text", "token text NOT NULL"} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("enterprise identity migration contains unsafe storage marker %q", forbidden)
		}
	}
}
