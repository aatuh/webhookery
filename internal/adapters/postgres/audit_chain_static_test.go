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

func TestAuditRetentionTombstonesChainEntriesBeforeDeletingRows(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	tombstone := strings.Index(source, "UPDATE audit_chain_entries")
	deleteAudit := strings.Index(source, "DELETE FROM audit_events")
	if tombstone == -1 || deleteAudit == -1 || tombstone > deleteAudit {
		t.Fatal("audit retention must tombstone audit_chain_entries before deleting audit_events")
	}
}
