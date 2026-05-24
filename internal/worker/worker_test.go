package worker

import (
	"context"
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

type fakeWorkerStore struct {
	items             []OutboxItem
	processed         string
	completed         string
	deliveries        []DeliveryItem
	recorded          string
	processErr        error
	retentionWorkerID string
	retentionLimit    int
	metricsWorkerID   string
	metricsLimit      int
	alertWorkerID     string
	alertLimit        int
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
	return f.deliveries, nil
}
func (f *fakeWorkerStore) RecordDeliveryAttempt(_ context.Context, item DeliveryItem, _ DeliveryResult, _ error) error {
	f.recorded = item.ID
	return nil
}
func (f *fakeWorkerStore) ApplyRetentionPolicies(_ context.Context, workerID string, limit int) error {
	f.retentionWorkerID = workerID
	f.retentionLimit = limit
	return nil
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

type fakeDeliveryClient struct {
	certPEM []byte
	keyPEM  []byte
}

func (f *fakeDeliveryClient) Deliver(_ context.Context, _ string, _ []byte, _ []byte, _ string, _ int, certPEM, keyPEM []byte) (DeliveryResult, error) {
	f.certPEM = certPEM
	f.keyPEM = keyPEM
	return DeliveryResult{StatusCode: 200, FailureClass: "success"}, nil
}
