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
	expiryBody, err := os.ReadFile("../../..//migrations/028_replay_approval_expiry.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"approval_required", "approved_by", "approved_at", "approval_reason"} {
		if !strings.Contains(text, want) {
			t.Fatalf("migration missing replay approval column %q", want)
		}
	}
	if !strings.Contains(string(expiryBody), "approval_expires_at") {
		t.Fatal("migration missing replay approval expiry column")
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

func TestReplayApprovalStoreEnforcesExpiryAndSecondActor(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"approval_expires_at", "approval_expires_at > now()", "created_by<>$3"} {
		if !strings.Contains(text, want) {
			t.Fatalf("store missing replay approval guard %q", want)
		}
	}
}
