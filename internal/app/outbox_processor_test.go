package app

import (
	"context"
	"testing"

	"webhookery/internal/worker"
)

func TestOutboxProcessorNoopsWhenOptionalProcessorsAreUnavailable(t *testing.T) {
	processor := NewOutboxProcessorService(nil, nil)
	for _, item := range []worker.OutboxItem{
		{TenantID: "ten_1", Kind: OutboxKindRouteEvent, ResourceID: "evt_1"},
		{TenantID: "ten_1", Kind: OutboxKindRouteRecoveredEvent, ResourceID: "evt_2"},
		{TenantID: "ten_1", Kind: OutboxKindReplayJob, ResourceID: "rpl_1"},
		{TenantID: "ten_1", Kind: OutboxKindReconciliationJob, ResourceID: "rcj_1"},
		{TenantID: "ten_1", Kind: "unknown", ResourceID: "noop"},
	} {
		t.Run(item.Kind, func(t *testing.T) {
			if err := processor.ProcessOutbox(context.Background(), item); err != nil {
				t.Fatalf("expected missing optional processor to no-op, got %v", err)
			}
		})
	}
}
