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

func TestStoreConstructionDoesNotBackfillAuditChain(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	start := strings.Index(source, "func NewWithOptions(")
	end := strings.Index(source, "func (s *Store) Close()")
	if start == -1 || end == -1 || end <= start {
		t.Fatal("could not locate store construction body")
	}
	if strings.Contains(source[start:end], "BackfillAuditChain") {
		t.Fatal("store construction must not run audit-chain backfill")
	}
}
