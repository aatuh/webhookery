package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestSIEMSignalMigrationAndStoreProtectCursorAndSecrets(t *testing.T) {
	up, err := os.ReadFile("../../../migrations/021_siem_signal.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(up) + "\n" + string(store)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS siem_sinks",
		"encrypted_secret bytea NOT NULL",
		"cursor_sequence bigint NOT NULL DEFAULT 0",
		"CREATE TABLE IF NOT EXISTS siem_deliveries",
		"func (s *Store) EnqueueSIEMDeliveries",
		"UPDATE siem_sinks",
		"GREATEST(cursor_sequence",
		"siem_sink.created",
		"siem_delivery.retry_requested",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("SIEM signal persistence missing %q", want)
		}
	}
}
