package e2e

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webhookery/internal/adapters/crypto"
	"webhookery/internal/adapters/deliveryhttp"
	"webhookery/internal/adapters/postgres"
	"webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/ssrf"
	"webhookery/internal/worker"
	"webhookery/pkg/verifier"
)

var rcResolver = ssrf.StaticResolver{
	"receiver.example.com": {netip.MustParseAddr("93.184.216.34")},
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

type deliveryCall struct {
	rawURL     string
	body       []byte
	keyID      string
	keyVersion int
}

type recordingDeliveryClient struct {
	t      *testing.T
	now    time.Time
	result worker.DeliveryResult
	err    error
	calls  []deliveryCall
}

func (c *recordingDeliveryClient) Deliver(_ context.Context, rawURL string, body []byte, secret []byte, keyID string, keyVersion int, _, _ []byte) (worker.DeliveryResult, error) {
	c.t.Helper()
	if len(secret) == 0 {
		c.t.Fatal("expected signing secret for outbound delivery")
	}
	if keyID == "" {
		c.t.Fatal("expected endpoint signing key id")
	}
	if keyVersion <= 0 {
		c.t.Fatal("expected positive endpoint signing key version")
	}
	req, err := (deliveryhttp.Client{
		SSRF:              ssrf.Validator{Resolver: rcResolver},
		Secret:            secret,
		SigningKeyID:      keyID,
		SigningKeyVersion: keyVersion,
		Now: func() time.Time {
			return c.now
		},
	}).BuildRequest(rawURL, body)
	if err != nil {
		c.t.Fatalf("build signed delivery request: %v", err)
	}
	if req.Method != http.MethodPost {
		c.t.Fatalf("unexpected delivery method: %s", req.Method)
	}
	verification := verifier.VerifyWebhookerySignature(verifier.VerifyWebhookerySignatureInput{
		Secret:           secret,
		RawBody:          body,
		SignatureHeader:  req.Header.Get("Webhook-Signature"),
		KeyIDHeader:      req.Header.Get("Webhook-Signature-Key-Id"),
		KeyVersionHeader: req.Header.Get("Webhook-Signature-Key-Version"),
		Now:              c.now,
		Tolerance:        time.Minute,
	})
	if !verification.Valid {
		c.t.Fatalf("delivery signature did not verify: %s", verification.Reason)
	}
	c.calls = append(c.calls, deliveryCall{
		rawURL:     rawURL,
		body:       append([]byte(nil), body...),
		keyID:      keyID,
		keyVersion: keyVersion,
	})
	return c.result, c.err
}

func TestRCE2EProviderIngestToSignedDelivery(t *testing.T) {
	ctx, store, actor := openRCStore(t)
	defer store.Close()

	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	control := app.NewControlService(store, ssrf.Validator{Resolver: rcResolver})
	source, endpoint := createRCRoute(t, ctx, control, actor, "stripe", "stripe", "invoice.paid")

	body := []byte(`{"id":"evt_rc_valid_` + testSuffix(t) + `","type":"invoice.paid","account":"acct_rc","data":{"object":{"id":"in_rc"}}}`)
	ingest := app.NewIngestService(store, fixedClock{now: now})
	result, err := ingest.Ingest(ctx, app.IngestRequest{
		TenantID:    actor.TenantID,
		SourceID:    source.ID,
		Provider:    "stripe",
		RawBody:     body,
		Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: verifier.TimestampedHeader("v1", now, []byte("whsec_rc"), body)}},
		ContentType: "application/json",
		RemoteIP:    "198.51.100.10",
	})
	if err != nil {
		t.Fatalf("ingest valid provider event: %v", err)
	}
	if !result.Accepted {
		t.Fatalf("expected verified event to be accepted, reason=%s", result.VerifyReason)
	}
	if result.EventID == "" || result.ReceiptID == "" || result.RawPayloadID == "" {
		t.Fatalf("expected durable event, receipt, and raw payload ids: %+v", result)
	}

	delivery := &recordingDeliveryClient{
		t:   t,
		now: now.Add(time.Second),
		result: worker.DeliveryResult{
			StatusCode:   http.StatusAccepted,
			ResponseBody: []byte("ok"),
			FailureClass: "success",
		},
	}
	runWorkerOnce(t, ctx, store, delivery, "rc-valid-"+testSuffix(t))
	if len(delivery.calls) != 1 {
		t.Fatalf("expected exactly one outbound delivery, got %d", len(delivery.calls))
	}
	if delivery.calls[0].rawURL != endpoint.URL {
		t.Fatalf("unexpected delivery URL: %s", delivery.calls[0].rawURL)
	}
	if !strings.Contains(string(delivery.calls[0].body), `"invoice.paid"`) {
		t.Fatalf("expected delivery payload snapshot to contain event type, body=%s", string(delivery.calls[0].body))
	}

	deliveries, err := control.ListDeliveries(ctx, actor, 20)
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	foundDelivery := false
	deliveryID := ""
	for _, item := range deliveries {
		if item.EventID == result.EventID && item.State == "succeeded" && item.DeliveryPayloadID != "" && item.DeliveryPayloadSHA256 != "" {
			foundDelivery = true
			deliveryID = item.ID
			break
		}
	}
	if !foundDelivery {
		t.Fatalf("expected succeeded delivery with payload evidence for event %s: %+v", result.EventID, deliveries)
	}
	attempts, err := control.ListDeliveryAttempts(ctx, actor, deliveryID, 10)
	if err != nil {
		t.Fatalf("list delivery attempts: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected one delivery attempt, got %d: %+v", len(attempts), attempts)
	}
	if attempts[0].State != "succeeded" || attempts[0].ResponseStatus != http.StatusAccepted || attempts[0].RequestSHA256 == "" || attempts[0].ResponseSHA256 == "" {
		t.Fatalf("expected succeeded attempt with request/response hashes: %+v", attempts[0])
	}

	timeline, err := control.ListEventTimeline(ctx, actor, result.EventID, 50)
	if err != nil {
		t.Fatalf("list event timeline: %v", err)
	}
	assertTimelineKinds(t, timeline, "event", "receipt", "normalized", "delivery", "delivery_payload", "attempt")
	auditEvents, err := control.ListAuditEvents(ctx, actor, 50)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if !containsAuditAction(auditEvents, "source.created") || !containsAuditAction(auditEvents, "endpoint.created") || !containsAuditAction(auditEvents, "route.created") {
		t.Fatalf("expected setup audit evidence for source, endpoint, and route: %+v", auditEvents)
	}

	otherTenant := authz.Actor{ID: "usr_other", TenantID: actor.TenantID + "_other", Role: authz.RoleOwner, Scopes: []string{"*"}}
	if _, err := control.GetEvent(ctx, otherTenant, result.EventID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("expected wrong-tenant event read to be hidden as not found, got %v", err)
	}

	verification, err := control.VerifyAuditChain(ctx, actor, app.AuditChainVerifyRequest{})
	if err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if !verification.Valid || verification.CheckedEntries == 0 {
		t.Fatalf("expected valid non-empty audit chain verification: %+v", verification)
	}
}

func TestRCE2EInvalidProviderSignatureQuarantinesWithoutRouting(t *testing.T) {
	ctx, store, actor := openRCStore(t)
	defer store.Close()

	now := time.Date(2026, 5, 26, 13, 0, 0, 0, time.UTC)
	control := app.NewControlService(store, ssrf.Validator{Resolver: rcResolver})
	source, _ := createRCRoute(t, ctx, control, actor, "stripe", "stripe", "invoice.payment_failed")
	body := []byte(`{"id":"evt_rc_invalid_` + testSuffix(t) + `","type":"invoice.payment_failed","account":"acct_rc"}`)

	ingest := app.NewIngestService(store, fixedClock{now: now})
	result, err := ingest.Ingest(ctx, app.IngestRequest{
		TenantID:    actor.TenantID,
		SourceID:    source.ID,
		Provider:    "stripe",
		RawBody:     body,
		Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: verifier.TimestampedHeader("v1", now, []byte("wrong_secret"), body)}},
		ContentType: "application/json",
		RemoteIP:    "198.51.100.11",
	})
	if err != nil {
		t.Fatalf("ingest invalid provider event as evidence: %v", err)
	}
	if result.Accepted || !app.IsInvalidSignature(result) {
		t.Fatalf("expected invalid signature rejection with persisted evidence: %+v", result)
	}

	delivery := &recordingDeliveryClient{
		t:   t,
		now: now.Add(time.Second),
		result: worker.DeliveryResult{
			StatusCode:   http.StatusAccepted,
			ResponseBody: []byte("ok"),
			FailureClass: "success",
		},
	}
	runWorkerOnce(t, ctx, store, delivery, "rc-invalid-"+testSuffix(t))
	if len(delivery.calls) != 0 {
		t.Fatalf("invalid signature event routed unexpectedly: %d deliveries", len(delivery.calls))
	}

	quarantine, err := control.ListQuarantine(ctx, actor, 20)
	if err != nil {
		t.Fatalf("list quarantine: %v", err)
	}
	if !containsTimelineRef(quarantine, result.EventID, "event_id") {
		t.Fatalf("expected quarantine entry for invalid event %s: %+v", result.EventID, quarantine)
	}

	timeline, err := control.ListEventTimeline(ctx, actor, result.EventID, 50)
	if err != nil {
		t.Fatalf("list invalid event timeline: %v", err)
	}
	assertTimelineKinds(t, timeline, "event", "receipt")
	if containsKind(timeline, "delivery") {
		t.Fatalf("invalid signature timeline should not contain delivery evidence: %+v", timeline)
	}
}

func TestRCE2ERetryExhaustionDLQReleaseAndReplayModes(t *testing.T) {
	ctx, store, actor := openRCStore(t)
	defer store.Close()

	now := time.Date(2026, 5, 26, 14, 0, 0, 0, time.UTC)
	control := app.NewControlService(store, ssrf.Validator{Resolver: rcResolver})
	retryPolicy, err := control.CreateRetryPolicy(ctx, actor, app.CreateRetryPolicyRequest{
		Name:                "RC single attempt",
		MaxAttempts:         1,
		MaxDurationSeconds:  60,
		InitialDelaySeconds: 1,
		MaxDelaySeconds:     1,
		State:               domain.StateActive,
	})
	if err != nil {
		t.Fatalf("create single-attempt retry policy: %v", err)
	}
	source, _ := createRCRouteWithOptions(t, ctx, control, actor, "stripe", "stripe", "charge.failed", rcRouteOptions{RetryPolicyID: retryPolicy.ID})
	body := []byte(`{"id":"evt_rc_dlq_` + testSuffix(t) + `","type":"charge.failed","account":"acct_rc"}`)

	ingest := app.NewIngestService(store, fixedClock{now: now})
	result, err := ingest.Ingest(ctx, app.IngestRequest{
		TenantID:    actor.TenantID,
		SourceID:    source.ID,
		Provider:    "stripe",
		RawBody:     body,
		Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: verifier.TimestampedHeader("v1", now, []byte("whsec_rc"), body)}},
		ContentType: "application/json",
		RemoteIP:    "198.51.100.12",
	})
	if err != nil {
		t.Fatalf("ingest event for DLQ: %v", err)
	}
	if !result.Accepted {
		t.Fatalf("expected DLQ test event to be accepted before delivery failure: %+v", result)
	}

	failingDelivery := &recordingDeliveryClient{
		t:   t,
		now: now.Add(time.Second),
		result: worker.DeliveryResult{
			StatusCode:   http.StatusInternalServerError,
			ResponseBody: []byte("temporary receiver failure"),
			FailureClass: "temporary_http",
		},
	}
	runWorkerOnce(t, ctx, store, failingDelivery, "rc-dlq-"+testSuffix(t))
	if len(failingDelivery.calls) != 1 {
		t.Fatalf("expected one failed delivery attempt, got %d", len(failingDelivery.calls))
	}

	deadLetters, err := control.ListDeadLetter(ctx, actor, 20)
	if err != nil {
		t.Fatalf("list dead letters: %v", err)
	}
	dlqEntryID := findMapID(deadLetters, "event_id", result.EventID)
	if dlqEntryID == "" {
		t.Fatalf("expected open dead-letter entry for event %s: %+v", result.EventID, deadLetters)
	}
	deliveries, err := control.ListDeliveries(ctx, actor, 20)
	if err != nil {
		t.Fatalf("list DLQ deliveries: %v", err)
	}
	if !containsDeliveryState(deliveries, result.EventID, "dead_lettered") {
		t.Fatalf("expected dead-lettered delivery for event %s: %+v", result.EventID, deliveries)
	}

	released, err := control.ReleaseDeadLetter(ctx, actor, dlqEntryID, app.DeadLetterReleaseRequest{Reason: "RC release drill"})
	if err != nil {
		t.Fatalf("release dead letter: %v", err)
	}
	if released.ID == "" || released.ConfigMode != app.ReplayConfigCurrent {
		t.Fatalf("expected DLQ release to create current-config replay job: %+v", released)
	}
	runWorkerOnce(t, ctx, store, &recordingDeliveryClient{
		t:   t,
		now: now.Add(2 * time.Second),
		result: worker.DeliveryResult{
			StatusCode:   http.StatusAccepted,
			ResponseBody: []byte("ok"),
			FailureClass: "success",
		},
	}, "rc-dlq-release-"+testSuffix(t))
	deadLetters, err = control.ListDeadLetter(ctx, actor, 20)
	if err != nil {
		t.Fatalf("list released dead letters: %v", err)
	}
	if !containsMapState(deadLetters, dlqEntryID, "released") {
		t.Fatalf("expected released dead-letter state for %s: %+v", dlqEntryID, deadLetters)
	}

	replaySource, _ := createRCRoute(t, ctx, control, actor, "stripe", "stripe", "customer.updated")
	replayBody := []byte(`{"id":"evt_rc_replay_` + testSuffix(t) + `","type":"customer.updated","account":"acct_rc"}`)
	replayIngest, err := ingest.Ingest(ctx, app.IngestRequest{
		TenantID:    actor.TenantID,
		SourceID:    replaySource.ID,
		Provider:    "stripe",
		RawBody:     replayBody,
		Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: verifier.TimestampedHeader("v1", now, []byte("whsec_rc"), replayBody)}},
		ContentType: "application/json",
		RemoteIP:    "198.51.100.13",
	})
	if err != nil {
		t.Fatalf("ingest replay source event: %v", err)
	}
	successClient := &recordingDeliveryClient{
		t:   t,
		now: now.Add(3 * time.Second),
		result: worker.DeliveryResult{
			StatusCode:   http.StatusAccepted,
			ResponseBody: []byte("ok"),
			FailureClass: "success",
		},
	}
	runWorkerOnce(t, ctx, store, successClient, "rc-replay-original-"+testSuffix(t))
	if len(successClient.calls) != 1 {
		t.Fatalf("expected initial replay source delivery, got %d", len(successClient.calls))
	}

	currentReplay, err := control.CreateReplay(ctx, actor, app.ReplayRequest{EventID: replayIngest.EventID, Reason: "RC current replay", ConfigMode: app.ReplayConfigCurrent})
	if err != nil {
		t.Fatalf("create current-config replay: %v", err)
	}
	originalReplay, err := control.CreateReplay(ctx, actor, app.ReplayRequest{EventID: replayIngest.EventID, Reason: "RC original replay", ConfigMode: app.ReplayConfigOriginal})
	if err != nil {
		t.Fatalf("create original-config replay: %v", err)
	}
	runWorkerOnce(t, ctx, store, successClient, "rc-replay-jobs-"+testSuffix(t))
	if len(successClient.calls) != 3 {
		t.Fatalf("expected initial plus two replay deliveries, got %d", len(successClient.calls))
	}
	jobs, err := control.ListReplayJobs(ctx, actor, 20)
	if err != nil {
		t.Fatalf("list replay jobs: %v", err)
	}
	if !containsReplayJob(jobs, currentReplay.ID, app.ReplayConfigCurrent, "completed") || !containsReplayJob(jobs, originalReplay.ID, app.ReplayConfigOriginal, "completed") {
		t.Fatalf("expected completed current and original replay jobs: %+v", jobs)
	}
	deliveries, err = control.ListDeliveries(ctx, actor, 50)
	if err != nil {
		t.Fatalf("list replay deliveries: %v", err)
	}
	if countReplayDeliveries(deliveries, replayIngest.EventID) < 2 {
		t.Fatalf("expected replay deliveries linked to original event %s: %+v", replayIngest.EventID, deliveries)
	}
	auditEvents, err := control.ListAuditEvents(ctx, actor, 100)
	if err != nil {
		t.Fatalf("list replay audit events: %v", err)
	}
	if !containsAuditAction(auditEvents, "replay.created") || !containsAuditAction(auditEvents, "dead_letter.released") {
		t.Fatalf("expected replay and dead-letter audit evidence: %+v", auditEvents)
	}
}

func openRCStore(t *testing.T) (context.Context, *postgres.Store, authz.Actor) {
	t.Helper()
	databaseURL := os.Getenv("RANDONNEE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("RANDONNEE_TEST_DATABASE_URL is required for RC E2E tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	migrationsDir := filepath.Join("..", "..", "migrations")
	if err := postgres.MigrateUp(ctx, databaseURL, migrationsDir); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	box, err := crypto.NewEnvelope(key)
	if err != nil {
		t.Fatalf("create test envelope: %v", err)
	}
	store, err := postgres.New(ctx, databaseURL, box)
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	suffix := testSuffix(t)
	actor := authz.Actor{
		ID:       "usr_rc_" + suffix,
		TenantID: "ten_rc_" + suffix,
		Role:     authz.RoleOwner,
		Scopes:   []string{"*"},
	}
	return ctx, store, actor
}

func createRCRoute(t *testing.T, ctx context.Context, control *app.ControlService, actor authz.Actor, providerName, adapterName, eventType string) (domain.Source, domain.Endpoint) {
	t.Helper()
	return createRCRouteWithOptions(t, ctx, control, actor, providerName, adapterName, eventType, rcRouteOptions{})
}

type rcRouteOptions struct {
	RetryPolicyID string
}

func createRCRouteWithOptions(t *testing.T, ctx context.Context, control *app.ControlService, actor authz.Actor, providerName, adapterName, eventType string, opts rcRouteOptions) (domain.Source, domain.Endpoint) {
	t.Helper()
	source, err := control.CreateSource(ctx, actor, app.CreateSourceRequest{
		Name:               "RC " + providerName + " source",
		Provider:           providerName,
		Adapter:            adapterName,
		VerificationSecret: "whsec_rc",
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	endpoint, _, err := control.CreateEndpoint(ctx, actor, app.CreateEndpointRequest{
		Name: "RC receiver",
		URL:  "https://receiver.example.com/webhook",
	})
	if err != nil {
		t.Fatalf("create endpoint: %v", err)
	}
	route, err := control.CreateRoute(ctx, actor, app.CreateRouteRequest{
		SourceID:      source.ID,
		Name:          "RC route",
		Priority:      10,
		EventTypes:    []string{eventType},
		EndpointID:    endpoint.ID,
		RetryPolicyID: opts.RetryPolicyID,
		State:         domain.StateActive,
	})
	if err != nil {
		t.Fatalf("create route: %v", err)
	}
	if route.ID == "" {
		t.Fatal("expected route id")
	}
	return source, endpoint
}

func runWorkerOnce(t *testing.T, ctx context.Context, store *postgres.Store, delivery worker.DeliveryClient, workerID string) {
	t.Helper()
	err := (worker.Worker{
		Store:          store,
		Processor:      store,
		DeliveryStore:  store,
		DeliveryClient: delivery,
		WorkerID:       workerID,
		Limit:          20,
	}).RunOnce(ctx)
	if err != nil {
		t.Fatalf("run worker once: %v", err)
	}
}

func assertTimelineKinds(t *testing.T, timeline []map[string]any, expected ...string) {
	t.Helper()
	for _, kind := range expected {
		if !containsKind(timeline, kind) {
			t.Fatalf("timeline missing kind %q: %+v", kind, timeline)
		}
	}
}

func containsKind(items []map[string]any, kind string) bool {
	for _, item := range items {
		if item["kind"] == kind {
			return true
		}
	}
	return false
}

func containsTimelineRef(items []map[string]any, ref, key string) bool {
	for _, item := range items {
		if item[key] == ref {
			return true
		}
	}
	return false
}

func containsAuditAction(items []domain.AuditEvent, action string) bool {
	for _, item := range items {
		if item.Action == action {
			return true
		}
	}
	return false
}

func findMapID(items []map[string]any, key, value string) string {
	for _, item := range items {
		if item[key] == value {
			return stringValue(item["id"])
		}
	}
	return ""
}

func containsMapState(items []map[string]any, id, state string) bool {
	for _, item := range items {
		if item["id"] == id && item["state"] == state {
			return true
		}
	}
	return false
}

func stringValue(value any) string {
	out, _ := value.(string)
	return out
}

func containsDeliveryState(items []domain.Delivery, eventID, state string) bool {
	for _, item := range items {
		if item.EventID == eventID && item.State == state {
			return true
		}
	}
	return false
}

func containsReplayJob(items []app.ReplayJob, id, configMode, state string) bool {
	for _, item := range items {
		if item.ID == id && item.ConfigMode == configMode && item.State == state {
			return true
		}
	}
	return false
}

func countReplayDeliveries(items []domain.Delivery, eventID string) int {
	count := 0
	for _, item := range items {
		if item.EventID == eventID && item.ReplayJobID != "" {
			count++
		}
	}
	return count
}

func testSuffix(t *testing.T) string {
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	return name + "_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
}
