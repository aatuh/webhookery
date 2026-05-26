package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestStoreDoesNotOwnProviderReconciliationOrchestration(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, forbidden := range []string{
		"func (s *Store) RunReconciliationJob",
		"func (s *Store) DryRunReconciliation",
		"reconcileProviderObject",
		"adapter.Scan(",
		"adapter.Lookup(",
		"RequestRedelivery(",
		"reconcile.ProviderObject",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("provider reconciliation orchestration must stay out of postgres.Store; found %q", forbidden)
		}
	}
}
