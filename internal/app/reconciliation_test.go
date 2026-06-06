package app

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"webhookery/internal/domain"
	"webhookery/internal/reconcile"
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
	connection  domain.ProviderConnection
	credential  string
	work        ReconciliationWork
	started     bool
	completed   bool
	failed      string
	cursor      string
	localEvents map[string]string
	evidence    []ProviderAPIEvidenceRecord
	captures    []RecoveredProviderEventCapture
	items       []ReconciliationItemRecord
}

func newFakeReconciliationStore() *fakeReconciliationStore {
	return &fakeReconciliationStore{localEvents: map[string]string{}}
}

func (f *fakeReconciliationStore) GetReconciliationConnection(context.Context, string, string) (domain.ProviderConnection, string, error) {
	return f.connection, f.credential, nil
}

func (f *fakeReconciliationStore) GetReconciliationWork(context.Context, string, string) (ReconciliationWork, error) {
	return f.work, nil
}

func (f *fakeReconciliationStore) StartReconciliationJob(context.Context, string, string) (bool, error) {
	f.started = true
	return true, nil
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
