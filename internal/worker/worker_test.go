package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRunOnceCompletesClaimedOutboxItems(t *testing.T) {
	store := &fakeWorkerStore{items: []OutboxItem{{ID: "out_1", Kind: "route_event", ResourceID: "evt_1"}}}
	w := Worker{Store: store, Processor: store, WorkerID: "worker_1", Limit: 10}
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.completed != "out_1" {
		t.Fatalf("expected completed outbox item, got %q", store.completed)
	}
	if store.processed != "out_1" {
		t.Fatalf("expected processed outbox item, got %q", store.processed)
	}
}

func TestRunOnceDoesNotCompleteDeferredOutboxItems(t *testing.T) {
	store := &fakeWorkerStore{items: []OutboxItem{{ID: "out_1", Kind: "replay_job", ResourceID: "rpl_1"}}, processErr: ErrDeferred}
	w := Worker{Store: store, Processor: store, WorkerID: "worker_1", Limit: 10}
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.completed != "" {
		t.Fatalf("deferred outbox item must not be completed, got %q", store.completed)
	}
}

func TestRunOnceDeliversClaimedDelivery(t *testing.T) {
	store := &fakeWorkerStore{deliveries: []DeliveryItem{{ID: "del_1", EndpointURL: "https://example.com/webhook", Body: []byte("{}"), MTLSClientCertPEM: []byte("cert"), MTLSClientKeyPEM: []byte("key")}}}
	client := &fakeDeliveryClient{}
	w := Worker{Store: store, DeliveryStore: store, DeliveryClient: client, WorkerID: "worker_1", Limit: 10}
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.recorded != "del_1" {
		t.Fatalf("expected recorded delivery attempt, got %q", store.recorded)
	}
	if string(client.certPEM) != "cert" || string(client.keyPEM) != "key" {
		t.Fatalf("expected mTLS material to reach delivery client, got cert=%q key=%q", client.certPEM, client.keyPEM)
	}
}

func TestRunOnceAppliesRetentionPolicies(t *testing.T) {
	store := &fakeWorkerStore{}
	w := Worker{Store: store, RetentionStore: store, WorkerID: "worker_1", Limit: 7}
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.retentionWorkerID != "worker_1" || store.retentionLimit != 7 {
		t.Fatalf("expected retention to run with worker id and limit, got worker=%q limit=%d", store.retentionWorkerID, store.retentionLimit)
	}
}

func TestRunOnceRefreshesMetricRollups(t *testing.T) {
	store := &fakeWorkerStore{}
	w := Worker{Store: store, MetricsStore: store, WorkerID: "worker_1", Limit: 5}
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.metricsWorkerID != "worker_1" || store.metricsLimit != 5 {
		t.Fatalf("expected metrics rollups to run with worker id and limit, got worker=%q limit=%d", store.metricsWorkerID, store.metricsLimit)
	}
}

func TestRunOnceEvaluatesAlertRules(t *testing.T) {
	store := &fakeWorkerStore{}
	w := Worker{Store: store, AlertStore: store, WorkerID: "worker_1", Limit: 6}
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.alertWorkerID != "worker_1" || store.alertLimit != 6 {
		t.Fatalf("expected alert evaluation to run with worker id and limit, got worker=%q limit=%d", store.alertWorkerID, store.alertLimit)
	}
}

func TestRunOnceDeliversClaimedNotificationSignal(t *testing.T) {
	store := &fakeWorkerStore{notificationDeliveries: []SignalDeliveryItem{{ID: "ndel_1", URL: "https://signals.example/hook", Body: []byte(`{"type":"alert.opened"}`), Secret: []byte("secret")}}}
	client := &fakeSignalClient{}
	w := Worker{Store: store, NotificationDeliveryStore: store, NotificationClient: client, WorkerID: "worker_1", Limit: 4}
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.notificationRecorded != "ndel_1" {
		t.Fatalf("expected notification attempt to be recorded, got %q", store.notificationRecorded)
	}
	if string(client.body) != `{"type":"alert.opened"}` || string(client.secret) != "secret" {
		t.Fatalf("expected exact signal body and secret to reach client, body=%q secret=%q", client.body, client.secret)
	}
}

func TestRunOnceEnqueuesAndDeliversClaimedSIEMSignal(t *testing.T) {
	store := &fakeWorkerStore{siemDeliveries: []SignalDeliveryItem{{ID: "sdel_1", URL: "https://siem.example/ingest", Body: []byte(`{"sequence":1}`), Secret: []byte("secret")}}}
	client := &fakeSignalClient{}
	w := Worker{Store: store, SIEMDeliveryStore: store, SIEMClient: client, WorkerID: "worker_1", Limit: 3}
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.siemEnqueueWorkerID != "worker_1" || store.siemRecorded != "sdel_1" {
		t.Fatalf("expected SIEM enqueue and record, enqueue=%q recorded=%q", store.siemEnqueueWorkerID, store.siemRecorded)
	}
	if string(client.body) != `{"sequence":1}` || string(client.secret) != "secret" {
		t.Fatalf("expected exact SIEM body and secret to reach client, body=%q secret=%q", client.body, client.secret)
	}
}

func TestRunOnceRunsAuditChainBackfillPhase(t *testing.T) {
	store := &fakeWorkerStore{auditBackfillResult: AuditChainBackfillResult{LeaseAcquired: true, EventsBackfilled: 3, More: true}}
	w := Worker{Store: store, AuditChainBackfillStore: store, WorkerID: "worker_1", Limit: 8}
	report := w.RunOnceReport(context.Background())
	if err := report.Err(); err != nil {
		t.Fatal(err)
	}
	if store.auditBackfillWorkerID != "worker_1" || store.auditBackfillLimit != 8 {
		t.Fatalf("expected audit-chain backfill to run with worker id and limit, got worker=%q limit=%d", store.auditBackfillWorkerID, store.auditBackfillLimit)
	}
	result, ok := report.Result(PhaseAuditChainBackfill)
	if !ok || result.Err != nil {
		t.Fatalf("expected successful audit-chain backfill phase result, got result=%+v ok=%v", result, ok)
	}
}

func TestRunOnceContinuesAcrossIndependentPhaseFailures(t *testing.T) {
	deliveryErr := errors.New("delivery claim failed")
	retentionErr := errors.New("retention failed")
	store := &fakeWorkerStore{
		claimDeliveriesErr: deliveryErr,
		retentionErr:       retentionErr,
	}
	w := Worker{
		Store:                     store,
		DeliveryStore:             store,
		DeliveryClient:            &fakeDeliveryClient{},
		RetentionStore:            store,
		MetricsStore:              store,
		AlertStore:                store,
		NotificationDeliveryStore: store,
		NotificationClient:        &fakeSignalClient{},
		SIEMDeliveryStore:         store,
		SIEMClient:                &fakeSignalClient{},
		WorkerID:                  "worker_1",
		Limit:                     2,
	}
	err := w.RunOnce(context.Background())
	if !errors.Is(err, deliveryErr) {
		t.Fatalf("expected delivery phase error, got %v", err)
	}
	if !errors.Is(err, retentionErr) {
		t.Fatalf("expected retention phase error, got %v", err)
	}
	if store.metricsWorkerID != "worker_1" || store.alertWorkerID != "worker_1" {
		t.Fatalf("expected metrics and alerts to run after earlier failures, metrics=%q alerts=%q", store.metricsWorkerID, store.alertWorkerID)
	}
	if !store.notificationClaimed || store.siemEnqueueWorkerID != "worker_1" || !store.siemClaimed {
		t.Fatalf("expected notification and SIEM phases to run after earlier failures, notification=%v siem_enqueued=%q siem_claimed=%v", store.notificationClaimed, store.siemEnqueueWorkerID, store.siemClaimed)
	}
}

func TestRunOnceReportRecordsPhaseResults(t *testing.T) {
	deliveryErr := errors.New("delivery claim failed")
	retentionErr := errors.New("retention failed")
	store := &fakeWorkerStore{
		claimDeliveriesErr: deliveryErr,
		retentionErr:       retentionErr,
	}
	w := Worker{
		Store:          store,
		DeliveryStore:  store,
		DeliveryClient: &fakeDeliveryClient{},
		RetentionStore: store,
		MetricsStore:   store,
		WorkerID:       "worker_1",
		Limit:          2,
	}
	report := w.RunOnceReport(context.Background())
	if !errors.Is(report.Err(), deliveryErr) || !errors.Is(report.Err(), retentionErr) {
		t.Fatalf("expected report to include delivery and retention errors, got %v", report.Err())
	}
	deliveryResult, ok := report.Result(PhaseDelivery)
	if !ok || !errors.Is(deliveryResult.Err, deliveryErr) {
		t.Fatalf("expected delivery phase result with error, got result=%+v ok=%v", deliveryResult, ok)
	}
	retentionResult, ok := report.Result(PhaseRetention)
	if !ok || !errors.Is(retentionResult.Err, retentionErr) {
		t.Fatalf("expected retention phase result with error, got result=%+v ok=%v", retentionResult, ok)
	}
	metricsResult, ok := report.Result(PhaseMetrics)
	if !ok || metricsResult.Err != nil {
		t.Fatalf("expected successful metrics phase result, got result=%+v ok=%v", metricsResult, ok)
	}
}

func TestRunReportErrorRedactsUnderlyingPhaseDetails(t *testing.T) {
	secretErr := errors.New("backend failed with whsec_secret and raw-body-secret")
	var report RunReport
	report.add(PhaseDelivery, secretErr)

	err := report.Err()
	if err == nil {
		t.Fatal("expected phase error")
	}
	if !errors.Is(err, secretErr) {
		t.Fatalf("phase error should preserve unwrap semantics, got %v", err)
	}
	if strings.Contains(err.Error(), "whsec_secret") || strings.Contains(err.Error(), "raw-body-secret") {
		t.Fatalf("worker phase error leaked underlying sensitive detail: %v", err)
	}
	if !strings.Contains(err.Error(), "delivery phase failed") {
		t.Fatalf("worker phase error should identify failed phase without details: %v", err)
	}
}

type fakeWorkerStore struct {
	items                  []OutboxItem
	processed              string
	completed              string
	deliveries             []DeliveryItem
	recorded               string
	processErr             error
	claimDeliveriesErr     error
	retentionWorkerID      string
	retentionLimit         int
	retentionErr           error
	metricsWorkerID        string
	metricsLimit           int
	alertWorkerID          string
	alertLimit             int
	notificationDeliveries []SignalDeliveryItem
	notificationClaimed    bool
	notificationRecorded   string
	siemDeliveries         []SignalDeliveryItem
	siemRecorded           string
	siemEnqueueWorkerID    string
	siemClaimed            bool
	auditBackfillWorkerID  string
	auditBackfillLimit     int
	auditBackfillResult    AuditChainBackfillResult
	auditBackfillErr       error
}

func (f *fakeWorkerStore) ClaimOutbox(context.Context, string, int) ([]OutboxItem, error) {
	return f.items, nil
}
func (f *fakeWorkerStore) ProcessOutbox(_ context.Context, item OutboxItem) error {
	f.processed = item.ID
	return f.processErr
}
func (f *fakeWorkerStore) CompleteOutbox(_ context.Context, outboxID string) error {
	f.completed = outboxID
	return nil
}
func (f *fakeWorkerStore) ClaimDueDeliveries(context.Context, string, int) ([]DeliveryItem, error) {
	if f.claimDeliveriesErr != nil {
		return nil, f.claimDeliveriesErr
	}
	return f.deliveries, nil
}
func (f *fakeWorkerStore) RecordDeliveryAttempt(_ context.Context, item DeliveryItem, _ DeliveryResult, _ error) error {
	f.recorded = item.ID
	return nil
}
func (f *fakeWorkerStore) ApplyRetentionPolicies(_ context.Context, workerID string, limit int) error {
	f.retentionWorkerID = workerID
	f.retentionLimit = limit
	return f.retentionErr
}
func (f *fakeWorkerStore) RefreshMetricsRollups(_ context.Context, workerID string, limit int) error {
	f.metricsWorkerID = workerID
	f.metricsLimit = limit
	return nil
}
func (f *fakeWorkerStore) EvaluateAlertRules(_ context.Context, workerID string, limit int) error {
	f.alertWorkerID = workerID
	f.alertLimit = limit
	return nil
}
func (f *fakeWorkerStore) ClaimNotificationDeliveries(context.Context, string, int) ([]SignalDeliveryItem, error) {
	f.notificationClaimed = true
	return f.notificationDeliveries, nil
}
func (f *fakeWorkerStore) RecordNotificationDeliveryAttempt(_ context.Context, item SignalDeliveryItem, _ SignalDeliveryResult, _ error) error {
	f.notificationRecorded = item.ID
	return nil
}
func (f *fakeWorkerStore) EnqueueSIEMDeliveries(_ context.Context, workerID string, limit int) error {
	f.siemEnqueueWorkerID = workerID
	return nil
}
func (f *fakeWorkerStore) ClaimSIEMDeliveries(context.Context, string, int) ([]SignalDeliveryItem, error) {
	f.siemClaimed = true
	return f.siemDeliveries, nil
}
func (f *fakeWorkerStore) RecordSIEMDeliveryAttempt(_ context.Context, item SignalDeliveryItem, _ SignalDeliveryResult, _ error) error {
	f.siemRecorded = item.ID
	return nil
}
func (f *fakeWorkerStore) BackfillAuditChain(_ context.Context, workerID string, limit int) (AuditChainBackfillResult, error) {
	f.auditBackfillWorkerID = workerID
	f.auditBackfillLimit = limit
	return f.auditBackfillResult, f.auditBackfillErr
}

type fakeDeliveryClient struct {
	certPEM []byte
	keyPEM  []byte
}

func (f *fakeDeliveryClient) Deliver(_ context.Context, _ string, _ []byte, _ []byte, _ string, _ int, certPEM, keyPEM []byte) (DeliveryResult, error) {
	f.certPEM = certPEM
	f.keyPEM = keyPEM
	return DeliveryResult{StatusCode: 200, FailureClass: "success"}, nil
}

type fakeSignalClient struct {
	body   []byte
	secret []byte
}

func (f *fakeSignalClient) Deliver(_ context.Context, _ string, body []byte, secret []byte) (SignalDeliveryResult, error) {
	f.body = body
	f.secret = secret
	return SignalDeliveryResult{StatusCode: 200, FailureClass: "success"}, nil
}
