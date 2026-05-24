package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestOpsVisibilityQueriesUseLeasesAndTenantScopedQueues(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"FROM worker_leases",
		"FROM outbox",
		"WHERE tenant_id=$1",
		"FROM deliveries",
		"state='in_progress'",
		"func (s *Store) OpsStorage",
		"FROM raw_payloads",
		"FROM evidence_exports",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("ops visibility store missing worker/tenant queue evidence %q", want)
		}
	}
}
