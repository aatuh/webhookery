package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestRetryJitterEvidenceSchemaAndScheduling(t *testing.T) {
	migration, err := os.ReadFile("../../../migrations/013_retry_jitter_evidence.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	migrationText := string(migration)
	for _, want := range []string{"retry_seed", "retry_delay_ms", "next_retry_at"} {
		if !strings.Contains(migrationText, want) {
			t.Fatalf("migration must add %s evidence", want)
		}
	}

	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	storeText := string(store)
	if !strings.Contains(storeText, "NextDeterministicDelay") {
		t.Fatal("delivery retry scheduling must use deterministic jitter")
	}
	if strings.Contains(storeText, "NextDelay(attemptNo, nil)") {
		t.Fatal("delivery retry scheduling must not use ambient randomness")
	}
	if !strings.Contains(storeText, "retry_delay_ms") || !strings.Contains(storeText, "next_retry_at") {
		t.Fatal("delivery attempts must record retry schedule evidence")
	}
}
