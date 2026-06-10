package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"webhookery/internal/domain"
	"webhookery/internal/reconcile"
	"webhookery/internal/worker"
)

func TestNewReconciliationServiceDefaultsRegistry(t *testing.T) {
	service := NewReconciliationService(nil, nil)
	if service.registry == nil {
		t.Fatal("expected nil registry to be replaced with built-in registry")
	}
	if _, ok := service.registry.Adapter("stripe"); !ok {
		t.Fatal("expected built-in registry to include provider adapters")
	}
}

func TestReconciliationServiceCapturesMissingRecoverableObject(t *testing.T) {
	store := newFakeReconciliationStore()
	store.work.Job = domain.ReconciliationJob{
		ID: "rec_1", TenantID: "ten_1", ConnectionID: "pcn_1", Provider: "stripe", State: domain.ReconciliationJobStateScheduled,
		CaptureMissing: true, RouteRecovered: true,
	}
	store.work.Connection = domain.ProviderConnection{ID: "pcn_1", TenantID: "ten_1", Provider: "stripe", CredentialType: "api_key", Config: map[string]string{"source_id": "src_1"}}
	store.work.Credential = "sk_test_secret"
	adapter := &fakeReconciliationAdapter{
		capabilities: reconcile.Capabilities{Provider: "stripe", CanScanEvents: true},
		scanResult: reconcile.ScanResult{
			Objects:    []reconcile.ProviderObject{{ID: "evt_missing", ObjectType: "event", Recoverable: false, Metadata: map[string]any{"request_id": "req_1"}}},
			Evidence:   []reconcile.Evidence{{Method: "GET", URL: "https://api.stripe.com/v1/events", StatusCode: 200, Body: []byte(`{"ok":true}`)}},
			NextCursor: "cursor_2",
		},
		lookupObject:   reconcile.ProviderObject{ID: "evt_missing", ObjectType: "event", EventType: "invoice.created", Recoverable: true, RawBody: []byte(`{"id":"evt_missing"}`), RequestHeaders: map[string]string{"Stripe-Signature": "redacted"}},
		lookupEvidence: []reconcile.Evidence{{Method: "GET", URL: "https://api.stripe.com/v1/events/evt_missing", StatusCode: 200, Body: []byte(`{"id":"evt_missing"}`)}},
	}
	service := NewReconciliationService(store, fakeReconciliationRegistry{"stripe": adapter})

	if err := service.RunReconciliationJob(context.Background(), "ten_1", "rec_1"); err != nil {
		t.Fatal(err)
	}
	if !store.started || !store.completed {
		t.Fatalf("expected reconciliation job to start and complete, started=%v completed=%v", store.started, store.completed)
	}
	if store.cursor != "cursor_2" {
		t.Fatalf("expected cursor update, got %q", store.cursor)
	}
	if len(store.evidence) != 2 {
		t.Fatalf("expected scan and lookup evidence, got %d", len(store.evidence))
	}
	if len(store.captures) != 1 || string(store.captures[0].RawBody) != `{"id":"evt_missing"}` || !store.captures[0].RouteRecovered {
		t.Fatalf("expected recovered event capture with route flag, got %+v", store.captures)
	}
	if len(store.items) != 1 || store.items[0].Outcome != domain.ReconciliationOutcomeCaptured || store.items[0].RecoveredEventID != "evt_recovered" {
		t.Fatalf("expected captured reconciliation item, got %+v", store.items)
	}
}

func TestReconciliationServiceRequestsRedeliveryForFailedObject(t *testing.T) {
	store := newFakeReconciliationStore()
	store.work.Job = domain.ReconciliationJob{
		ID: "rec_1", TenantID: "ten_1", ConnectionID: "pcn_1", Provider: "github", State: domain.ReconciliationJobStateScheduled,
		RedeliverFailed: true,
	}
	store.work.Connection = domain.ProviderConnection{ID: "pcn_1", TenantID: "ten_1", Provider: "github", CredentialType: "api_key", Config: map[string]string{}}
	store.localEvents["evt_provider"] = "evt_local"
	adapter := &fakeReconciliationAdapter{
		capabilities: reconcile.Capabilities{Provider: "github", CanScanEvents: true},
		scanResult: reconcile.ScanResult{Objects: []reconcile.ProviderObject{{
			ID: "evt_provider", ObjectType: "delivery", Failed: true, Redeliverable: true, Metadata: map[string]any{"delivery_id": "delivery_1"},
		}}},
		redeliveryEvidence: []reconcile.Evidence{{Method: "POST", URL: "https://api.github.com/redeliver", StatusCode: 202}},
	}
	service := NewReconciliationService(store, fakeReconciliationRegistry{"github": adapter})

	if err := service.RunReconciliationJob(context.Background(), "ten_1", "rec_1"); err != nil {
		t.Fatal(err)
	}
	if adapter.redeliveryID != "delivery_1" {
		t.Fatalf("expected redelivery lookup id from delivery metadata, got %q", adapter.redeliveryID)
	}
	if len(store.items) != 1 || store.items[0].Outcome != domain.ReconciliationOutcomeRedeliveryRequested || !store.items[0].RedeliveryRequested {
		t.Fatalf("expected redelivery requested item, got %+v", store.items)
	}
	if len(store.evidence) != 1 || store.items[0].EvidenceID == "" {
		t.Fatalf("expected redelivery evidence linked to item, evidence=%+v item=%+v", store.evidence, store.items)
	}
}

func TestReconciliationServiceUnsupportedScanRecordsUnrecoverableItem(t *testing.T) {
	store := newFakeReconciliationStore()
	store.work.Job = domain.ReconciliationJob{ID: "rec_1", TenantID: "ten_1", ConnectionID: "pcn_1", Provider: "slack", State: domain.ReconciliationJobStateScheduled}
	store.work.Connection = domain.ProviderConnection{ID: "pcn_1", TenantID: "ten_1", Provider: "slack", Config: map[string]string{}}
	adapter := &fakeReconciliationAdapter{capabilities: reconcile.Capabilities{Provider: "slack", CanScanEvents: false, Limitations: []string{"scan unsupported"}}}
	service := NewReconciliationService(store, fakeReconciliationRegistry{"slack": adapter})

	if err := service.RunReconciliationJob(context.Background(), "ten_1", "rec_1"); err != nil {
		t.Fatal(err)
	}
	if adapter.scanCalled {
		t.Fatal("unsupported provider should not scan")
	}
	if len(store.items) != 1 || store.items[0].Outcome != domain.ReconciliationOutcomeUnrecoverable {
		t.Fatalf("expected unrecoverable capability item, got %+v", store.items)
	}
}

func TestReconciliationServiceFailsUnsupportedProviderWithoutStarting(t *testing.T) {
	store := newFakeReconciliationStore()
	store.work.Job = domain.ReconciliationJob{ID: "rec_unsupported", TenantID: "ten_1", ConnectionID: "pcn_1", Provider: "unknown", State: domain.ReconciliationJobStateScheduled}
	store.work.Connection = domain.ProviderConnection{ID: "pcn_1", TenantID: "ten_1", Provider: "unknown", Config: map[string]string{}}
	service := NewReconciliationService(store, fakeReconciliationRegistry{})

	if err := service.RunReconciliationJob(context.Background(), "ten_1", "rec_unsupported"); err != nil {
		t.Fatal(err)
	}
	if store.started {
		t.Fatal("unsupported provider must fail before starting job work")
	}
	if store.failed != reconcile.ErrorUnsupported {
		t.Fatalf("expected unsupported provider failure class, got %q", store.failed)
	}
}

func TestReconciliationServiceDefersWhenJobLeaseIsUnavailable(t *testing.T) {
	store := newFakeReconciliationStore()
	store.startAcquired = false
	store.work.Job = domain.ReconciliationJob{ID: "rec_deferred", TenantID: "ten_1", ConnectionID: "pcn_1", Provider: "stripe", State: domain.ReconciliationJobStateScheduled}
	store.work.Connection = domain.ProviderConnection{ID: "pcn_1", TenantID: "ten_1", Provider: "stripe", Config: map[string]string{}}
	adapter := &fakeReconciliationAdapter{capabilities: reconcile.Capabilities{Provider: "stripe", CanScanEvents: true}}
	service := NewReconciliationService(store, fakeReconciliationRegistry{"stripe": adapter})

	if err := service.RunReconciliationJob(context.Background(), "ten_1", "rec_deferred"); !errors.Is(err, worker.ErrDeferred) {
		t.Fatalf("expected deferred work when reconciliation lease is unavailable, got %v", err)
	}
	if adapter.scanCalled || store.completed || store.failed != "" {
		t.Fatalf("deferred job should not scan, complete, or fail: scan=%v completed=%v failed=%q", adapter.scanCalled, store.completed, store.failed)
	}
}

func TestReconciliationServiceIgnoresTerminalJobs(t *testing.T) {
	for _, state := range []string{domain.ReconciliationJobStateCanceled, domain.ReconciliationJobStateCompleted} {
		t.Run(state, func(t *testing.T) {
			store := newFakeReconciliationStore()
			store.work.Job = domain.ReconciliationJob{ID: "rec_terminal", TenantID: "ten_1", ConnectionID: "pcn_1", Provider: "stripe", State: state}
			store.work.Connection = domain.ProviderConnection{ID: "pcn_1", TenantID: "ten_1", Provider: "stripe", Config: map[string]string{}}
			adapter := &fakeReconciliationAdapter{capabilities: reconcile.Capabilities{Provider: "stripe", CanScanEvents: true}}
			service := NewReconciliationService(store, fakeReconciliationRegistry{"stripe": adapter})

			if err := service.RunReconciliationJob(context.Background(), "ten_1", "rec_terminal"); err != nil {
				t.Fatal(err)
			}
			if store.started || adapter.scanCalled {
				t.Fatalf("terminal job should not start or scan: started=%v scan=%v", store.started, adapter.scanCalled)
			}
		})
	}
}

func TestReconciliationServiceDryRunCountsProviderObjects(t *testing.T) {
	store := newFakeReconciliationStore()
	store.connection = domain.ProviderConnection{ID: "pcn_1", TenantID: "ten_1", Provider: "stripe", CredentialType: "api_key", Config: map[string]string{}}
	store.credential = "sk_test_secret"
	store.localEvents["evt_local"] = "evt_1"
	adapter := &fakeReconciliationAdapter{
		capabilities: reconcile.Capabilities{Provider: "stripe", CanScanEvents: true},
		scanResult: reconcile.ScanResult{Objects: []reconcile.ProviderObject{
			{ID: "evt_local", ObjectType: "event"},
			{ID: "evt_missing", ObjectType: "event", Failed: true, Redeliverable: true},
		}},
	}
	service := NewReconciliationService(store, fakeReconciliationRegistry{"stripe": adapter})

	job, err := service.DryRunReconciliation(context.Background(), "ten_1", ReconciliationJobRequest{ConnectionID: "pcn_1", RedeliverFailed: true})
	if err != nil {
		t.Fatal(err)
	}
	if job.TotalItems != 2 || job.MatchedItems != 1 || job.MissingItems != 1 || job.RedeliveredItems != 1 {
		t.Fatalf("unexpected dry-run counts: %+v", job)
	}
}

func TestReconciliationServiceDryRunReportsUnsupportedAndProviderFailure(t *testing.T) {
	unsupportedStore := newFakeReconciliationStore()
	unsupportedStore.connection = domain.ProviderConnection{ID: "pcn_unsupported", TenantID: "ten_1", Provider: "slack", Config: map[string]string{}}
	unsupportedAdapter := &fakeReconciliationAdapter{capabilities: reconcile.Capabilities{Provider: "slack", CanScanEvents: false, Limitations: []string{"provider API cannot replay webhooks"}}}
	service := NewReconciliationService(unsupportedStore, fakeReconciliationRegistry{"slack": unsupportedAdapter})

	job, err := service.DryRunReconciliation(context.Background(), "ten_1", ReconciliationJobRequest{ConnectionID: "pcn_unsupported"})
	if err != nil {
		t.Fatal(err)
	}
	if unsupportedAdapter.scanCalled || job.TotalItems != 1 || job.UnrecoverableItems != 1 || !strings.Contains(job.Error, "cannot replay") {
		t.Fatalf("unsupported dry run should report limitation without scanning: job=%+v scan=%v", job, unsupportedAdapter.scanCalled)
	}

	failedStore := newFakeReconciliationStore()
	failedStore.connection = domain.ProviderConnection{ID: "pcn_failed", TenantID: "ten_1", Provider: "stripe", Config: map[string]string{}}
	failedAdapter := &fakeReconciliationAdapter{
		capabilities: reconcile.Capabilities{Provider: "stripe", CanScanEvents: true},
		scanErr:      reconcile.ProviderError{Class: reconcile.ErrorRateLimited, Message: "rate limited with sk_live_secret"},
	}
	service = NewReconciliationService(failedStore, fakeReconciliationRegistry{"stripe": failedAdapter})

	job, err = service.DryRunReconciliation(context.Background(), "ten_1", ReconciliationJobRequest{ConnectionID: "pcn_failed"})
	if err != nil {
		t.Fatal(err)
	}
	if job.State != domain.ReconciliationJobStateFailed || job.Error != reconcile.ErrorRateLimited {
		t.Fatalf("provider dry-run failure should persist class without secret detail: %+v", job)
	}
}

func TestReconciliationServiceRecordsUnrecoverableMissingObject(t *testing.T) {
	store := newFakeReconciliationStore()
	store.work.Job = domain.ReconciliationJob{
		ID: "rec_missing", TenantID: "ten_1", ConnectionID: "pcn_1", Provider: "stripe", State: domain.ReconciliationJobStateScheduled,
		CaptureMissing: true,
	}
	store.work.Connection = domain.ProviderConnection{ID: "pcn_1", TenantID: "ten_1", Provider: "stripe", CredentialType: "api_key", Config: map[string]string{}}
	adapter := &fakeReconciliationAdapter{
		capabilities: reconcile.Capabilities{Provider: "stripe", CanScanEvents: true},
		scanResult: reconcile.ScanResult{Objects: []reconcile.ProviderObject{{
			ID: "evt_missing", ObjectType: "event", Recoverable: false,
		}}},
		lookupErr: reconcile.ErrUnsupported,
	}
	service := NewReconciliationService(store, fakeReconciliationRegistry{"stripe": adapter})

	if err := service.RunReconciliationJob(context.Background(), "ten_1", "rec_missing"); err != nil {
		t.Fatal(err)
	}
	if len(store.captures) != 0 {
		t.Fatalf("unrecoverable provider object must not be captured: %+v", store.captures)
	}
	if len(store.items) != 1 || store.items[0].Outcome != domain.ReconciliationOutcomeUnrecoverable || !strings.Contains(store.items[0].Error, "does not expose") {
		t.Fatalf("expected unrecoverable reconciliation item, got %+v", store.items)
	}
}

func TestReconciliationServiceFailsItemWhenRedeliveryRequestFails(t *testing.T) {
	store := newFakeReconciliationStore()
	store.work.Job = domain.ReconciliationJob{
		ID: "rec_redelivery", TenantID: "ten_1", ConnectionID: "pcn_1", Provider: "github", State: domain.ReconciliationJobStateScheduled,
		RedeliverFailed: true,
	}
	store.work.Connection = domain.ProviderConnection{ID: "pcn_1", TenantID: "ten_1", Provider: "github", CredentialType: "api_key", Config: map[string]string{}}
	store.localEvents["evt_provider"] = "evt_local"
	adapter := &fakeReconciliationAdapter{
		capabilities:       reconcile.Capabilities{Provider: "github", CanScanEvents: true},
		scanResult:         reconcile.ScanResult{Objects: []reconcile.ProviderObject{{ID: "evt_provider", ObjectType: "delivery", Failed: true, Redeliverable: true}}},
		redeliveryEvidence: []reconcile.Evidence{{Method: "POST", URL: "https://api.github.com/redeliver", StatusCode: 403}},
		redeliveryErr:      reconcile.ProviderError{Class: reconcile.ErrorForbidden, Message: "forbidden github_pat_secret"},
	}
	service := NewReconciliationService(store, fakeReconciliationRegistry{"github": adapter})

	if err := service.RunReconciliationJob(context.Background(), "ten_1", "rec_redelivery"); err != nil {
		t.Fatal(err)
	}
	if len(store.items) != 1 || store.items[0].Outcome != domain.ReconciliationOutcomeFailed || store.items[0].Error != reconcile.ErrorForbidden {
		t.Fatalf("expected failed redelivery item with redacted provider class, got %+v", store.items)
	}
	if len(store.evidence) != 1 || store.items[0].EvidenceID == "" {
		t.Fatalf("redelivery failure evidence should stay linked to item: evidence=%+v item=%+v", store.evidence, store.items)
	}
}

func TestProviderErrorForDBRedactsProviderSecrets(t *testing.T) {
	got := providerErrorForDB(errors.New("provider failed with sk_live_secret"))
	if got != "provider request failed" {
		t.Fatalf("expected redacted provider error, got %q", got)
	}
}

type fakeReconciliationRegistry map[string]reconcile.Adapter

func (r fakeReconciliationRegistry) Adapter(provider string) (reconcile.Adapter, bool) {
	adapter, ok := r[provider]
	return adapter, ok
}

type fakeReconciliationAdapter struct {
	capabilities       reconcile.Capabilities
	scanResult         reconcile.ScanResult
	scanErr            error
	scanCalled         bool
	lookupObject       reconcile.ProviderObject
	lookupEvidence     []reconcile.Evidence
	lookupErr          error
	lookupID           string
	redeliveryEvidence []reconcile.Evidence
	redeliveryErr      error
	redeliveryID       string
}

func (f *fakeReconciliationAdapter) Name() string { return "fake" }

func (f *fakeReconciliationAdapter) Capabilities(map[string]string) reconcile.Capabilities {
	return f.capabilities
}

func (f *fakeReconciliationAdapter) ValidateConnection(context.Context, reconcile.Connection) error {
	return nil
}

func (f *fakeReconciliationAdapter) Scan(context.Context, reconcile.ScanRequest) (reconcile.ScanResult, error) {
	f.scanCalled = true
	return f.scanResult, f.scanErr
}

func (f *fakeReconciliationAdapter) Lookup(_ context.Context, _ reconcile.Connection, objectID string) (reconcile.ProviderObject, []reconcile.Evidence, error) {
	f.lookupID = objectID
	return f.lookupObject, f.lookupEvidence, f.lookupErr
}

func (f *fakeReconciliationAdapter) RequestRedelivery(_ context.Context, _ reconcile.Connection, objectID string) ([]reconcile.Evidence, error) {
	f.redeliveryID = objectID
	return f.redeliveryEvidence, f.redeliveryErr
}

type fakeReconciliationStore struct {
	connection    domain.ProviderConnection
	credential    string
	work          ReconciliationWork
	workErr       error
	startErr      error
	startAcquired bool
	started       bool
	completed     bool
	failed        string
	cursor        string
	localEvents   map[string]string
	evidence      []ProviderAPIEvidenceRecord
	captures      []RecoveredProviderEventCapture
	items         []ReconciliationItemRecord
}

func newFakeReconciliationStore() *fakeReconciliationStore {
	return &fakeReconciliationStore{startAcquired: true, localEvents: map[string]string{}}
}

func (f *fakeReconciliationStore) GetReconciliationConnection(context.Context, string, string) (domain.ProviderConnection, string, error) {
	return f.connection, f.credential, nil
}

func (f *fakeReconciliationStore) GetReconciliationWork(context.Context, string, string) (ReconciliationWork, error) {
	return f.work, f.workErr
}

func (f *fakeReconciliationStore) StartReconciliationJob(context.Context, string, string) (bool, error) {
	f.started = true
	return f.startAcquired, f.startErr
}

func (f *fakeReconciliationStore) RecordProviderAPIEvidence(_ context.Context, record ProviderAPIEvidenceRecord) (string, error) {
	id := fmt.Sprintf("pae_%d", len(f.evidence)+1)
	f.evidence = append(f.evidence, record)
	return id, nil
}

func (f *fakeReconciliationStore) FindLocalProviderEvent(_ context.Context, _ string, _ domain.ProviderConnection, providerObjectID string) (string, error) {
	return f.localEvents[providerObjectID], nil
}

func (f *fakeReconciliationStore) CaptureRecoveredProviderEvent(_ context.Context, input RecoveredProviderEventCapture) (string, error) {
	f.captures = append(f.captures, input)
	return "evt_recovered", nil
}

func (f *fakeReconciliationStore) InsertReconciliationItem(_ context.Context, input ReconciliationItemRecord) (string, error) {
	if input.EvidenceID == "" && len(f.evidence) > 0 {
		input.EvidenceID = fmt.Sprintf("pae_%d", len(f.evidence))
	}
	f.items = append(f.items, input)
	return "rci_1", nil
}

func (f *fakeReconciliationStore) AttachProviderEvidenceToItem(context.Context, string, string, string) error {
	return nil
}

func (f *fakeReconciliationStore) UpdateReconciliationCursor(_ context.Context, _, _, cursor string) error {
	f.cursor = cursor
	return nil
}

func (f *fakeReconciliationStore) CompleteReconciliationJob(context.Context, string, string) error {
	f.completed = true
	return nil
}

func (f *fakeReconciliationStore) FailReconciliationJob(_ context.Context, _, _, errorText string) error {
	f.failed = errorText
	return nil
}

var _ = time.Now
