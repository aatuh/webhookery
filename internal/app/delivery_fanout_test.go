package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"webhookery/internal/domain"
	"webhookery/internal/worker"
)

func TestReplayScheduleDelaySpacesItemsByRateLimit(t *testing.T) {
	if got := replayScheduleDelay(0, 60); got != 0 {
		t.Fatalf("first replay item should be immediately eligible, got %s", got)
	}
	if got := replayScheduleDelay(1, 60); got != time.Second {
		t.Fatalf("second item at 60/min should be delayed 1s, got %s", got)
	}
	if got := replayScheduleDelay(2, 30); got != 4*time.Second {
		t.Fatalf("third item at 30/min should be delayed 4s, got %s", got)
	}
}

func TestReplayScheduleDelayIgnoresInvalidRateLimit(t *testing.T) {
	if got := replayScheduleDelay(10, 0); got != 0 {
		t.Fatalf("zero rate limit should not delay replay, got %s", got)
	}
	if got := replayScheduleDelay(10, -1); got != 0 {
		t.Fatalf("negative rate limit should not delay replay, got %s", got)
	}
	if got := replayScheduleDelay(-1, 60); got != 0 {
		t.Fatalf("negative item index should not delay replay, got %s", got)
	}
}

func TestDeliveryFanoutSkipsUnverifiedEventsUnlessRecovered(t *testing.T) {
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	store := &fakeDeliveryFanoutStore{
		event: domain.Event{ID: "evt_1", TenantID: "ten_1", SourceID: "src_1", Type: "invoice.created", Verified: false, VerifyReason: "invalid_signature"},
		targets: []DeliveryFanoutTarget{{
			EndpointID: "end_1", RouteID: "rte_1", RouteVersionID: "rv_1",
		}},
	}
	svc := NewDeliveryFanoutService(store, fixedFanoutClock{now: now})

	created, err := svc.CreateDeliveriesForEvent(context.Background(), "ten_1", "evt_1", DeliveryFanoutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if created != 0 || len(store.creates) != 0 {
		t.Fatalf("unverified event should not fan out without recovered allowance, created=%d requests=%d", created, len(store.creates))
	}

	store.event.VerifyReason = domain.VerificationReasonProviderAPIReconcile
	created, err = svc.CreateDeliveriesForEvent(context.Background(), "ten_1", "evt_1", DeliveryFanoutOptions{AllowRecovered: true})
	if err != nil {
		t.Fatal(err)
	}
	if created != 1 || len(store.creates) != 1 {
		t.Fatalf("provider-recovered event should fan out when explicitly allowed, created=%d requests=%d", created, len(store.creates))
	}
}

func TestDeliveryFanoutCreatesSubscriptionThenRouteSnapshots(t *testing.T) {
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	store := &fakeDeliveryFanoutStore{
		event: domain.Event{ID: "evt_1", TenantID: "ten_1", SourceID: "src_1", Type: "invoice.created", Verified: true},
		targets: []DeliveryFanoutTarget{
			{EndpointID: "end_sub", SubscriptionID: "sub_1", SubscriptionVersionID: "sv_1", EndpointRetryPolicyID: "rtp_endpoint", TransformationVersionID: "trv_sub"},
			{EndpointID: "end_route", RouteID: "rte_1", RouteVersionID: "rv_1", RouteRetryPolicyID: "rtp_route", EndpointRetryPolicyID: "rtp_endpoint_2", TransformationVersionID: "trv_route"},
		},
	}
	svc := NewDeliveryFanoutService(store, fixedFanoutClock{now: now})

	created, err := svc.CreateDeliveriesForEvent(context.Background(), "ten_1", "evt_1", DeliveryFanoutOptions{ReplayJobID: "rpl_1", RateLimitPerMinute: 60})
	if err != nil {
		t.Fatal(err)
	}
	if created != 2 || len(store.creates) != 2 {
		t.Fatalf("expected two delivery snapshots, created=%d requests=%d", created, len(store.creates))
	}
	sub := store.creates[0]
	if sub.SubscriptionID != "sub_1" || sub.RetryPolicyID != "rtp_endpoint" || sub.TransformationVersionID != "trv_sub" || sub.DeliveryPayloadMode != DeliveryPayloadMaterialize {
		t.Fatalf("unexpected subscription snapshot request: %+v", sub)
	}
	if !sub.NextAttemptAt.Equal(now) {
		t.Fatalf("first snapshot should be immediately eligible, got %s", sub.NextAttemptAt)
	}
	route := store.creates[1]
	if route.RouteID != "rte_1" || route.RetryPolicyID != "rtp_route" || route.TransformationVersionID != "trv_route" {
		t.Fatalf("unexpected route snapshot request: %+v", route)
	}
	if !route.NextAttemptAt.Equal(now.Add(time.Second)) {
		t.Fatalf("second replay snapshot should be rate-limited by 1s, got %s", route.NextAttemptAt)
	}
}

func TestDeliveryFanoutReplayOriginalClonesPayloadsAndCompletesJob(t *testing.T) {
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	store := &fakeDeliveryFanoutStore{
		replayWork: ReplayJobWork{
			State:              "scheduled",
			ConfigMode:         ReplayConfigOriginal,
			RateLimitPerMinute: 30,
			Request:            ReplayRequest{EventID: "evt_1", ConfigMode: ReplayConfigOriginal},
		},
		originals: []DeliveryReplaySource{{
			ID: "del_original", EventID: "evt_1", EndpointID: "end_1", RouteID: "rte_1", RouteVersionID: "rv_1",
			RetryPolicyID: "rtp_1", AdapterVersionID: "adv_1", NormalizedEnvelopeID: "nenv_1", TransformationVersionID: "trv_1", DeliveryPayloadID: "dpl_1",
		}},
	}
	svc := NewDeliveryFanoutService(store, fixedFanoutClock{now: now})

	err := svc.ProcessOutbox(context.Background(), worker.OutboxItem{TenantID: "ten_1", Kind: OutboxKindReplayJob, ResourceID: "rpl_1"})
	if err != nil {
		t.Fatal(err)
	}
	if store.completedReplayItems != 1 {
		t.Fatalf("expected replay completion count 1, got %d", store.completedReplayItems)
	}
	if len(store.creates) != 1 {
		t.Fatalf("expected one cloned delivery snapshot, got %d", len(store.creates))
	}
	req := store.creates[0]
	if req.DeliveryPayloadMode != DeliveryPayloadClone || req.SourceDeliveryPayloadID != "dpl_1" || req.OriginalDeliveryID != "del_original" {
		t.Fatalf("expected original replay to clone payload evidence, got %+v", req)
	}
	if req.ConfigMode != ReplayConfigOriginal || req.ReplayJobID != "rpl_1" {
		t.Fatalf("expected original replay evidence context, got %+v", req)
	}
}

func TestDeliveryFanoutReplayCurrentUsesCurrentRouteConfig(t *testing.T) {
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	store := &fakeDeliveryFanoutStore{
		replayWork: ReplayJobWork{
			State:      "scheduled",
			ConfigMode: ReplayConfigCurrent,
			Request:    ReplayRequest{DeliveryID: "del_old", ConfigMode: ReplayConfigCurrent},
		},
		deliverySource: DeliveryReplaySource{
			ID: "del_old", EventID: "evt_1", EndpointID: "end_old", RouteID: "rte_1", RouteVersionID: "rv_old",
			RetryPolicyID: "rtp_old", AdapterVersionID: "adv_old", NormalizedEnvelopeID: "nenv_old", TransformationVersionID: "trv_old", DeliveryPayloadID: "dpl_old",
		},
		currentTarget: DeliveryFanoutTarget{
			EndpointID: "end_new", RouteID: "rte_1", RouteVersionID: "rv_new", RouteRetryPolicyID: "rtp_new", TransformationVersionID: "trv_new",
		},
		currentOK: true,
	}
	svc := NewDeliveryFanoutService(store, fixedFanoutClock{now: now})

	if err := svc.CreateReplayDeliveries(context.Background(), "ten_1", "rpl_1"); err != nil {
		t.Fatal(err)
	}
	if len(store.creates) != 1 {
		t.Fatalf("expected one replay snapshot, got %d", len(store.creates))
	}
	req := store.creates[0]
	if req.EndpointID != "end_new" || req.RouteVersionID != "rv_new" || req.RetryPolicyID != "rtp_new" || req.TransformationVersionID != "trv_new" {
		t.Fatalf("expected current route config, got %+v", req)
	}
	if req.DeliveryPayloadMode != DeliveryPayloadMaterialize || req.SourceDeliveryPayloadID != "" {
		t.Fatalf("current replay must materialize a fresh payload snapshot, got %+v", req)
	}
	if req.AdapterVersionID != "" || req.NormalizedEnvelopeID != "" {
		t.Fatalf("current replay should not reuse old envelope linkage before payload materialization, got %+v", req)
	}
}

func TestDeliveryFanoutDefersPausedReplay(t *testing.T) {
	store := &fakeDeliveryFanoutStore{replayWork: ReplayJobWork{State: "paused"}}
	svc := NewDeliveryFanoutService(store, fixedFanoutClock{now: time.Now().UTC()})

	err := svc.CreateReplayDeliveries(context.Background(), "ten_1", "rpl_1")
	if !errors.Is(err, worker.ErrDeferred) {
		t.Fatalf("expected paused replay to defer, got %v", err)
	}
	if len(store.creates) != 0 || store.completedReplayItems != 0 {
		t.Fatalf("deferred replay should not create or complete work, requests=%d completed=%d", len(store.creates), store.completedReplayItems)
	}
}

type fixedFanoutClock struct {
	now time.Time
}

func (c fixedFanoutClock) Now() time.Time {
	return c.now
}

type fakeDeliveryFanoutStore struct {
	event                domain.Event
	targets              []DeliveryFanoutTarget
	creates              []DeliverySnapshotRequest
	replayWork           ReplayJobWork
	originals            []DeliveryReplaySource
	deliverySource       DeliveryReplaySource
	currentTarget        DeliveryFanoutTarget
	currentOK            bool
	noopItems            []string
	completedReplayItems int
	reconciliationJobID  string
}

func (f *fakeDeliveryFanoutStore) GetEvent(context.Context, string, string) (domain.Event, error) {
	return f.event, nil
}

func (f *fakeDeliveryFanoutStore) ListDeliveryFanoutTargets(context.Context, string, string, string) ([]DeliveryFanoutTarget, error) {
	return append([]DeliveryFanoutTarget(nil), f.targets...), nil
}

func (f *fakeDeliveryFanoutStore) CreateDeliverySnapshot(_ context.Context, req DeliverySnapshotRequest) (DeliverySnapshotResult, error) {
	f.creates = append(f.creates, req)
	return DeliverySnapshotResult{
		DeliveryID:              "del_new",
		DeliveryPayloadID:       "dpl_new",
		DeliveryPayloadSHA256:   "sha256:new",
		AdapterVersionID:        firstNonEmpty(req.AdapterVersionID, "adv_new"),
		NormalizedEnvelopeID:    firstNonEmpty(req.NormalizedEnvelopeID, "nenv_new"),
		TransformationVersionID: req.TransformationVersionID,
	}, nil
}

func (f *fakeDeliveryFanoutStore) GetReplayJobWork(context.Context, string, string) (ReplayJobWork, error) {
	return f.replayWork, nil
}

func (f *fakeDeliveryFanoutStore) StartReplayJob(context.Context, string, string) (bool, error) {
	return true, nil
}

func (f *fakeDeliveryFanoutStore) ListOriginalDeliveryReplaySources(context.Context, string, string) ([]DeliveryReplaySource, error) {
	return append([]DeliveryReplaySource(nil), f.originals...), nil
}

func (f *fakeDeliveryFanoutStore) GetDeliveryReplaySource(context.Context, string, string) (DeliveryReplaySource, error) {
	return f.deliverySource, nil
}

func (f *fakeDeliveryFanoutStore) GetCurrentDeliveryFanoutTarget(context.Context, string, string, string) (DeliveryFanoutTarget, bool, error) {
	return f.currentTarget, f.currentOK, nil
}

func (f *fakeDeliveryFanoutStore) InsertReplayNoopItem(_ context.Context, _, _, eventID, _, errorText string) error {
	f.noopItems = append(f.noopItems, eventID+":"+errorText)
	return nil
}

func (f *fakeDeliveryFanoutStore) CompleteReplayJob(_ context.Context, _, _ string, processedItems int) error {
	f.completedReplayItems = processedItems
	return nil
}

func (f *fakeDeliveryFanoutStore) RunReconciliationJob(_ context.Context, _, jobID string) error {
	f.reconciliationJobID = jobID
	return nil
}
