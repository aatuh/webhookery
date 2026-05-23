package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestReplayApprovalMigrationAddsGateColumns(t *testing.T) {
	body, err := os.ReadFile("../../..//migrations/015_replay_approval.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"approval_required", "approved_by", "approved_at", "approval_reason"} {
		if !strings.Contains(text, want) {
			t.Fatalf("migration missing replay approval column %q", want)
		}
	}
}

func TestReplayApprovalStoreQueuesOnlyAfterApproval(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"pending_approval", "ApproveReplayJob", "INSERT INTO outbox", "state='pending_approval'", "state='scheduled'"} {
		if !strings.Contains(text, want) {
			t.Fatalf("store missing replay approval evidence %q", want)
		}
	}
}
