package auditchain

import (
	"testing"
	"time"

	"webhookery/internal/domain"
)

func TestAuditEventHashIsDeterministic(t *testing.T) {
	event := domain.AuditEvent{
		ID:         "aud_1",
		TenantID:   "ten_1",
		ActorID:    "usr_1",
		Action:     "delivery.retry_requested",
		Resource:   "delivery",
		ResourceID: "del_1",
		Reason:     "repair",
		OccurredAt: time.Date(2026, 5, 25, 12, 0, 0, 123456789, time.UTC),
	}

	first, err := EventHash(event)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EventHash(event)
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("hash is not deterministic: %q %q", first, second)
	}
}

func TestChainHashDependsOnPreviousHash(t *testing.T) {
	eventHash := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	first := ChainHash("", eventHash)
	second := ChainHash("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", eventHash)
	if first == "" || second == "" || first == second {
		t.Fatalf("chain hash must include previous hash, got %q %q", first, second)
	}
	if got := PreviousHashForSequence(1, "ignored"); got != "" {
		t.Fatalf("sequence 1 previous hash must be empty, got %q", got)
	}
	if got := PreviousHashForSequence(2, second); got != second {
		t.Fatalf("sequence >1 previous hash mismatch: %q", got)
	}
}

func TestComputeEntryUsesEventAndPreviousHash(t *testing.T) {
	event := domain.AuditEvent{
		ID:         "aud_1",
		TenantID:   "ten_1",
		ActorID:    "usr_1",
		Action:     "audit_export.created",
		Resource:   "audit_export",
		ResourceID: "exp_1",
		Reason:     "evidence",
		OccurredAt: time.Date(2026, 5, 25, 12, 1, 0, 0, time.UTC),
	}
	createdAt := time.Date(2026, 5, 25, 12, 2, 0, 0, time.UTC)

	entry, err := ComputeEntry("ace_1", event, 2, "sha256:previous", domain.AuditChainEntrySourceBackfill, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if entry.ID != "ace_1" || entry.Sequence != 2 || entry.AuditEventID != event.ID {
		t.Fatalf("unexpected entry identifiers: %+v", entry)
	}
	if entry.EventHash == "" || entry.ChainHash == "" || entry.PreviousChainHash != "sha256:previous" {
		t.Fatalf("unexpected hashes: %+v", entry)
	}
	if entry.Source != domain.AuditChainEntrySourceBackfill || entry.State != domain.AuditChainEntryStateActive {
		t.Fatalf("unexpected state/source: %+v", entry)
	}
}
