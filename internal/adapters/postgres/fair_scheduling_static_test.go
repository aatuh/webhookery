package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestStoreClaimSQLUsesTenantFairOutboxOrdering(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"row_number() OVER (PARTITION BY priority, tenant_id ORDER BY available_at ASC, id ASC)",
		"ORDER BY r.priority ASC, r.tenant_rank ASC, r.available_at ASC, r.tenant_id ASC, r.id ASC",
		"CASE kind WHEN 'route_event' THEN 0 WHEN 'replay_job' THEN 1 ELSE 2 END AS priority",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("store claim SQL must include tenant-fair outbox ordering evidence %q", want)
		}
	}
}

func TestStoreClaimSQLUsesTenantFairDeliveryOrdering(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"row_number() OVER (PARTITION BY is_replay, d.tenant_id ORDER BY d.next_attempt_at ASC, d.id ASC)",
		"ORDER BY r.is_replay ASC, r.tenant_rank ASC, r.next_attempt_at ASC, r.tenant_id ASC, r.id ASC",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("store claim SQL must include tenant-fair delivery ordering evidence %q", want)
		}
	}
}
