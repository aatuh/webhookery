package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestAdapterRegistryMigrationDefinesTenantScopedGovernance(t *testing.T) {
	body, err := os.ReadFile("../../../migrations/023_adapter_registry.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	for _, want := range []string{
		"ALTER TABLE provider_adapters ADD COLUMN IF NOT EXISTS tenant_id",
		"ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS definition_json",
		"adapter_test_vectors",
		"adapter_version_reviews",
		"provider_adapters_scope_name_idx",
		"adapter_versions_scope_name_version_idx",
		"adapter_versions_scope_name_state_idx",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("adapter registry migration missing %q", want)
		}
	}
	for _, forbidden := range []string{"encrypted_secret", "client_secret", "token_hash"} {
		if strings.Contains(strings.ToLower(sql), forbidden) {
			t.Fatalf("adapter registry migration should not introduce secret storage field %q", forbidden)
		}
	}
}
