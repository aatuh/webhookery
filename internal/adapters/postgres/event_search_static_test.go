package postgres

import (
	"strings"
	"testing"
	"time"

	"webhookery/internal/app"
)

func TestEventSearchQueryKeepsTenantPredicatesAndBoundArgs(t *testing.T) {
	query, args := eventSearchQuery("ten_1", app.EventSearchRequest{
		Limit:         25,
		Provider:      "stripe",
		ExternalID:    "evt_external",
		DeliveryID:    "del_1",
		Status:        "dlq",
		Verification:  "invalid",
		ReceivedAfter: time.Date(2026, 6, 4, 10, 0, 0, 0, time.UTC),
		RouteID:       "rte_1",
	})
	for _, want := range []string{
		"FROM events e WHERE e.tenant_id=$1",
		"e.provider=$2",
		"e.provider_event_id=$3",
		"deliveries d WHERE d.tenant_id=e.tenant_id AND d.event_id=e.id AND d.id=$4",
		"dead_letter_entries dlq WHERE dlq.tenant_id=e.tenant_id AND dlq.event_id=e.id",
		"e.signature_verified=false",
		"e.received_at >= $5",
		"deliveries d WHERE d.tenant_id=e.tenant_id AND d.event_id=e.id AND d.route_id=$6",
		"LIMIT $7",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("event search query missing %q:\n%s", want, query)
		}
	}
	if len(args) != 7 || args[0] != "ten_1" || args[1] != "stripe" || args[2] != "evt_external" || args[3] != "del_1" || args[5] != "rte_1" || args[6] != 25 {
		t.Fatalf("unexpected event search args: %#v", args)
	}
}
