package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestNotificationSignalMigrationAndStoreProtectTenantAndSecrets(t *testing.T) {
	up, err := os.ReadFile("../../../migrations/020_notification_signal.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(up) + "\n" + string(store)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS notification_channels",
		"tenant_id text NOT NULL REFERENCES tenants(id)",
		"encrypted_secret bytea NOT NULL",
		"CREATE TABLE IF NOT EXISTS alert_rule_channels",
		"CREATE TABLE IF NOT EXISTS notification_deliveries",
		"notification_deliveries_transition_unique_idx",
		"func (s *Store) CreateNotificationChannel",
		"WHERE tenant_id=$1",
		"notification_channel.created",
		"notification_delivery.retry_requested",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("notification signal persistence missing %q", want)
		}
	}
}
