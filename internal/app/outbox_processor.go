package app

import (
	"context"

	"webhookery/internal/worker"
)

type OutboxProcessorService struct {
	fanout         *DeliveryFanoutService
	reconciliation *ReconciliationService
}

func NewOutboxProcessorService(fanout *DeliveryFanoutService, reconciliation *ReconciliationService) *OutboxProcessorService {
	return &OutboxProcessorService{fanout: fanout, reconciliation: reconciliation}
}

func (s *OutboxProcessorService) ProcessOutbox(ctx context.Context, item worker.OutboxItem) error {
	switch item.Kind {
	case OutboxKindRouteEvent, OutboxKindRouteRecoveredEvent, OutboxKindReplayJob:
		if s.fanout == nil {
			return nil
		}
		return s.fanout.ProcessOutbox(ctx, item)
	case OutboxKindReconciliationJob:
		if s.reconciliation == nil {
			return nil
		}
		return s.reconciliation.RunReconciliationJob(ctx, item.TenantID, item.ResourceID)
	default:
		return nil
	}
}
