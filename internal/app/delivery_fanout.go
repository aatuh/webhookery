package app

import (
	"context"
	"time"

	"webhookery/internal/domain"
	"webhookery/internal/worker"
)

const (
	OutboxKindRouteEvent          = "route_event"
	OutboxKindRouteRecoveredEvent = "route_recovered_event"
	OutboxKindReplayJob           = "replay_job"
	OutboxKindReconciliationJob   = "reconciliation_job"
)

type DeliveryFanoutStore interface {
	GetEvent(ctx context.Context, tenantID, eventID string) (domain.Event, error)
	ListDeliveryFanoutTargets(ctx context.Context, tenantID, sourceID, eventType string) ([]DeliveryFanoutTarget, error)
	CreateDeliverySnapshot(ctx context.Context, req DeliverySnapshotRequest) (DeliverySnapshotResult, error)
	GetReplayJobWork(ctx context.Context, tenantID, replayJobID string) (ReplayJobWork, error)
	StartReplayJob(ctx context.Context, tenantID, replayJobID string) (bool, error)
	ListOriginalDeliveryReplaySources(ctx context.Context, tenantID, eventID string) ([]DeliveryReplaySource, error)
	GetDeliveryReplaySource(ctx context.Context, tenantID, deliveryID string) (DeliveryReplaySource, error)
	GetCurrentDeliveryFanoutTarget(ctx context.Context, tenantID, routeID, subscriptionID string) (DeliveryFanoutTarget, bool, error)
	InsertReplayNoopItem(ctx context.Context, tenantID, replayJobID, eventID, configMode, errorText string) error
	CompleteReplayJob(ctx context.Context, tenantID, replayJobID string, processedItems int) error
	RunReconciliationJob(ctx context.Context, tenantID, jobID string) error
}

type DeliveryFanoutService struct {
	store DeliveryFanoutStore
	clock Clock
}

func NewDeliveryFanoutService(store DeliveryFanoutStore, clock Clock) *DeliveryFanoutService {
	if clock == nil {
		clock = SystemClock{}
	}
	return &DeliveryFanoutService{store: store, clock: clock}
}

type DeliveryFanoutTarget struct {
	EndpointID              string
	RouteID                 string
	RouteVersionID          string
	SubscriptionID          string
	SubscriptionVersionID   string
	RouteRetryPolicyID      string
	EndpointRetryPolicyID   string
	TransformationVersionID string
}

func (t DeliveryFanoutTarget) retryPolicyID() string {
	return firstNonEmpty(t.RouteRetryPolicyID, t.EndpointRetryPolicyID)
}

type DeliveryPayloadMode string

const (
	DeliveryPayloadMaterialize DeliveryPayloadMode = "materialize"
	DeliveryPayloadClone       DeliveryPayloadMode = "clone"
)

type DeliverySnapshotRequest struct {
	TenantID                string
	EventID                 string
	EndpointID              string
	RouteID                 string
	RouteVersionID          string
	SubscriptionID          string
	SubscriptionVersionID   string
	RetryPolicyID           string
	ReplayJobID             string
	OriginalDeliveryID      string
	AdapterVersionID        string
	NormalizedEnvelopeID    string
	TransformationVersionID string
	DeliveryPayloadMode     DeliveryPayloadMode
	SourceDeliveryPayloadID string
	RetrySeed               string
	NextAttemptAt           time.Time
	ConfigMode              string
}

type DeliverySnapshotResult struct {
	DeliveryID              string
	DeliveryPayloadID       string
	DeliveryPayloadSHA256   string
	AdapterVersionID        string
	NormalizedEnvelopeID    string
	TransformationVersionID string
}

type DeliveryReplaySource struct {
	ID                      string
	EventID                 string
	EndpointID              string
	RouteID                 string
	RouteVersionID          string
	SubscriptionID          string
	SubscriptionVersionID   string
	RetryPolicyID           string
	AdapterVersionID        string
	NormalizedEnvelopeID    string
	TransformationVersionID string
	DeliveryPayloadID       string
}

type ReplayDecisionEvidence struct {
	TenantID                string
	ReplayJobID             string
	EventID                 string
	OriginalDeliveryID      string
	NewDeliveryID           string
	ConfigMode              string
	RouteVersionID          string
	SubscriptionVersionID   string
	RetryPolicyID           string
	AdapterVersionID        string
	NormalizedEnvelopeID    string
	TransformationVersionID string
	DeliveryPayloadID       string
	DeliveryPayloadSHA256   string
}

type ReplayJobWork struct {
	Request            ReplayRequest
	State              string
	ConfigMode         string
	RateLimitPerMinute int
}

type DeliveryFanoutOptions struct {
	ReplayJobID        string
	ConfigMode         string
	RateLimitPerMinute int
	AllowRecovered     bool
}

func (s *DeliveryFanoutService) ProcessOutbox(ctx context.Context, item worker.OutboxItem) error {
	switch item.Kind {
	case OutboxKindRouteEvent:
		_, err := s.CreateDeliveriesForEvent(ctx, item.TenantID, item.ResourceID, DeliveryFanoutOptions{})
		return err
	case OutboxKindRouteRecoveredEvent:
		_, err := s.CreateDeliveriesForEvent(ctx, item.TenantID, item.ResourceID, DeliveryFanoutOptions{AllowRecovered: true})
		return err
	case OutboxKindReplayJob:
		return s.CreateReplayDeliveries(ctx, item.TenantID, item.ResourceID)
	case OutboxKindReconciliationJob:
		return s.store.RunReconciliationJob(ctx, item.TenantID, item.ResourceID)
	default:
		return nil
	}
}

func (s *DeliveryFanoutService) CreateDeliveriesForEvent(ctx context.Context, tenantID, eventID string, opts DeliveryFanoutOptions) (int, error) {
	event, err := s.store.GetEvent(ctx, tenantID, eventID)
	if err != nil {
		return 0, err
	}
	if !event.Verified && (!opts.AllowRecovered || event.VerifyReason != domain.VerificationReasonProviderAPIReconcile) {
		return 0, nil
	}
	targets, err := s.store.ListDeliveryFanoutTargets(ctx, tenantID, event.SourceID, event.Type)
	if err != nil {
		return 0, err
	}
	created := 0
	for _, target := range targets {
		if _, err := s.createDeliveryFromTarget(ctx, tenantID, eventID, target, created, opts); err != nil {
			return created, err
		}
		created++
	}
	return created, nil
}

func (s *DeliveryFanoutService) CreateReplayDeliveries(ctx context.Context, tenantID, replayJobID string) error {
	work, err := s.store.GetReplayJobWork(ctx, tenantID, replayJobID)
	if err != nil {
		return err
	}
	if work.State == "paused" || work.State == "pending_approval" {
		return worker.ErrDeferred
	}
	if work.State != "scheduled" {
		return nil
	}
	started, err := s.store.StartReplayJob(ctx, tenantID, replayJobID)
	if err != nil {
		return err
	}
	if !started {
		return worker.ErrDeferred
	}
	configMode := firstNonEmpty(work.ConfigMode, work.Request.ConfigMode, ReplayConfigCurrent)
	rateLimitPerMinute := work.RateLimitPerMinute
	if rateLimitPerMinute == 0 {
		rateLimitPerMinute = work.Request.RateLimitPerMinute
	}
	created := 0
	if work.Request.EventID != "" {
		var count int
		var createErr error
		if configMode == ReplayConfigOriginal {
			count, createErr = s.createDeliveriesFromOriginalEvent(ctx, tenantID, work.Request.EventID, DeliveryFanoutOptions{
				ReplayJobID: replayJobID, ConfigMode: configMode, RateLimitPerMinute: rateLimitPerMinute,
			})
			if createErr != nil {
				return createErr
			}
			if count == 0 {
				if err := s.store.InsertReplayNoopItem(ctx, tenantID, replayJobID, work.Request.EventID, configMode, "no original deliveries found"); err != nil {
					return err
				}
			}
		} else {
			count, createErr = s.CreateDeliveriesForEvent(ctx, tenantID, work.Request.EventID, DeliveryFanoutOptions{
				ReplayJobID: replayJobID, ConfigMode: configMode, RateLimitPerMinute: rateLimitPerMinute,
			})
			if createErr != nil {
				return createErr
			}
			if count == 0 {
				if err := s.store.InsertReplayNoopItem(ctx, tenantID, replayJobID, work.Request.EventID, configMode, "no current route or subscription matched"); err != nil {
					return err
				}
			}
		}
		created += count
	}
	if work.Request.DeliveryID != "" {
		count, err := s.createDeliveryFromExisting(ctx, tenantID, work.Request.DeliveryID, DeliveryFanoutOptions{
			ReplayJobID: replayJobID, ConfigMode: configMode, RateLimitPerMinute: rateLimitPerMinute,
		})
		if err != nil {
			return err
		}
		created += count
	}
	return s.store.CompleteReplayJob(ctx, tenantID, replayJobID, created)
}

func (s *DeliveryFanoutService) createDeliveriesFromOriginalEvent(ctx context.Context, tenantID, eventID string, opts DeliveryFanoutOptions) (int, error) {
	originals, err := s.store.ListOriginalDeliveryReplaySources(ctx, tenantID, eventID)
	if err != nil {
		return 0, err
	}
	for i, original := range originals {
		req := deliverySnapshotRequestFromSource(tenantID, original, opts)
		req.OriginalDeliveryID = original.ID
		req.DeliveryPayloadMode = DeliveryPayloadClone
		req.SourceDeliveryPayloadID = original.DeliveryPayloadID
		req.NextAttemptAt = s.scheduledDeliveryAt(i, opts.RateLimitPerMinute)
		if _, err := s.createDeliverySnapshot(ctx, req); err != nil {
			return i, err
		}
	}
	return len(originals), nil
}

func (s *DeliveryFanoutService) createDeliveryFromExisting(ctx context.Context, tenantID, deliveryID string, opts DeliveryFanoutOptions) (int, error) {
	source, err := s.store.GetDeliveryReplaySource(ctx, tenantID, deliveryID)
	if err != nil {
		return 0, err
	}
	req := deliverySnapshotRequestFromSource(tenantID, source, opts)
	req.OriginalDeliveryID = deliveryID
	req.NextAttemptAt = s.scheduledDeliveryAt(0, opts.RateLimitPerMinute)
	if opts.ConfigMode != ReplayConfigOriginal && (source.RouteID != "" || source.SubscriptionID != "") {
		current, ok, err := s.store.GetCurrentDeliveryFanoutTarget(ctx, tenantID, source.RouteID, source.SubscriptionID)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, nil
		}
		req.EndpointID = current.EndpointID
		req.RouteVersionID = current.RouteVersionID
		req.SubscriptionVersionID = current.SubscriptionVersionID
		req.RetryPolicyID = current.retryPolicyID()
		req.TransformationVersionID = current.TransformationVersionID
		req.AdapterVersionID = ""
		req.NormalizedEnvelopeID = ""
		req.SourceDeliveryPayloadID = ""
	}
	if source.DeliveryPayloadID != "" && opts.ConfigMode == ReplayConfigOriginal {
		req.DeliveryPayloadMode = DeliveryPayloadClone
		req.SourceDeliveryPayloadID = source.DeliveryPayloadID
	} else {
		req.DeliveryPayloadMode = DeliveryPayloadMaterialize
	}
	if _, err := s.createDeliverySnapshot(ctx, req); err != nil {
		return 0, err
	}
	return 1, nil
}

func (s *DeliveryFanoutService) createDeliveryFromTarget(ctx context.Context, tenantID, eventID string, target DeliveryFanoutTarget, index int, opts DeliveryFanoutOptions) (DeliverySnapshotResult, error) {
	req := DeliverySnapshotRequest{
		TenantID:                tenantID,
		EventID:                 eventID,
		EndpointID:              target.EndpointID,
		RouteID:                 target.RouteID,
		RouteVersionID:          target.RouteVersionID,
		SubscriptionID:          target.SubscriptionID,
		SubscriptionVersionID:   target.SubscriptionVersionID,
		RetryPolicyID:           target.retryPolicyID(),
		ReplayJobID:             opts.ReplayJobID,
		TransformationVersionID: target.TransformationVersionID,
		DeliveryPayloadMode:     DeliveryPayloadMaterialize,
		NextAttemptAt:           s.scheduledDeliveryAt(index, opts.RateLimitPerMinute),
		ConfigMode:              firstNonEmpty(opts.ConfigMode, ReplayConfigCurrent),
	}
	return s.createDeliverySnapshot(ctx, req)
}

func (s *DeliveryFanoutService) createDeliverySnapshot(ctx context.Context, req DeliverySnapshotRequest) (DeliverySnapshotResult, error) {
	if req.ConfigMode == "" {
		req.ConfigMode = ReplayConfigCurrent
	}
	if req.DeliveryPayloadMode == "" {
		req.DeliveryPayloadMode = DeliveryPayloadMaterialize
	}
	return s.store.CreateDeliverySnapshot(ctx, req)
}

func deliverySnapshotRequestFromSource(tenantID string, source DeliveryReplaySource, opts DeliveryFanoutOptions) DeliverySnapshotRequest {
	return DeliverySnapshotRequest{
		TenantID:                tenantID,
		EventID:                 source.EventID,
		EndpointID:              source.EndpointID,
		RouteID:                 source.RouteID,
		RouteVersionID:          source.RouteVersionID,
		SubscriptionID:          source.SubscriptionID,
		SubscriptionVersionID:   source.SubscriptionVersionID,
		RetryPolicyID:           source.RetryPolicyID,
		ReplayJobID:             opts.ReplayJobID,
		AdapterVersionID:        source.AdapterVersionID,
		NormalizedEnvelopeID:    source.NormalizedEnvelopeID,
		TransformationVersionID: source.TransformationVersionID,
		SourceDeliveryPayloadID: source.DeliveryPayloadID,
		ConfigMode:              firstNonEmpty(opts.ConfigMode, ReplayConfigCurrent),
	}
}

func (s *DeliveryFanoutService) scheduledDeliveryAt(index, rateLimitPerMinute int) time.Time {
	return s.clock.Now().Add(replayScheduleDelay(index, rateLimitPerMinute))
}

func replayScheduleDelay(index, rateLimitPerMinute int) time.Duration {
	if index <= 0 || rateLimitPerMinute <= 0 {
		return 0
	}
	interval := time.Minute / time.Duration(rateLimitPerMinute)
	if interval <= 0 {
		return 0
	}
	return time.Duration(index) * interval
}
