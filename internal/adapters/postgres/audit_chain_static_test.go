package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestAuditEventsAreWrittenThroughChainHelper(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(body), "INSERT INTO audit_events"); got != 1 {
		t.Fatalf("audit_events inserts must stay centralized in recordAuditEventTx, got %d direct inserts", got)
	}
}
