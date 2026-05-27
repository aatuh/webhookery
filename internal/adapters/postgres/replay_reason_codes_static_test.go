package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestReplayReasonCodeMigrationAddsGovernanceColumn(t *testing.T) {
	body, err := os.ReadFile("../../../migrations/027_replay_reason_codes.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration := string(body)
	for _, want := range []string{"reason_code", "operator_requested"} {
		if !strings.Contains(migration, want) {
			t.Fatalf("migration missing replay reason-code evidence %q", want)
		}
	}
}
