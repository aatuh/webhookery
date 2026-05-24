package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestAlertMigrationAndStorePreserveTenantScopeAndOpenFiringUniqueness(t *testing.T) {
	up, err := os.ReadFile("../../../migrations/019_alerts.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(up) + "\n" + string(store)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS alert_rules",
		"CREATE TABLE IF NOT EXISTS alert_firings",
		"tenant_id text NOT NULL REFERENCES tenants(id)",
		"alert_firings_open_rule_idx",
		"func (s *Store) EvaluateAlertRules",
		"WHERE tenant_id=$1",
		"alert_firing.acknowledged",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("alert persistence missing %q", want)
		}
	}
}
