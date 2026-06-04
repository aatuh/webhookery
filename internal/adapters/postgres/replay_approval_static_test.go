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

func TestReplayApprovalPolicyMigrationAndStoreLookup(t *testing.T) {
	migration, err := os.ReadFile("../../..//migrations/029_replay_approval_policies.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	migrationText := string(migration)
	for _, want := range []string{"replay_approval_policies", "scope_type", "scope_id", "default_expiry_seconds", "UNIQUE (tenant_id, scope_type, scope_id)"} {
		if !strings.Contains(migrationText, want) {
			t.Fatalf("migration missing replay approval policy evidence %q", want)
		}
	}

	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"replayApprovalPolicyForReplay", "scope_type='tenant'", "scope_type='source'", "scope_type='route'", "req.RequireApproval = true"} {
		if !strings.Contains(text, want) {
			t.Fatalf("store missing replay approval policy lookup %q", want)
		}
	}
}
