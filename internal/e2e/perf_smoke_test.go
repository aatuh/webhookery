package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"webhookery/internal/adapters/postgres"
	"webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/ssrf"
	"webhookery/internal/worker"
	"webhookery/pkg/verifier"
)

type perfSmokeReport struct {
	GeneratedAtUTC             string   `json:"generated_at_utc"`
	Scenario                   string   `json:"scenario"`
	EventCount                 int      `json:"event_count"`
	IngestP50MS                float64  `json:"ingest_p50_ms"`
	IngestP95MS                float64  `json:"ingest_p95_ms"`
	IngestP99MS                float64  `json:"ingest_p99_ms"`
	DeliveryDrainMS            float64  `json:"delivery_drain_ms"`
	DeliveryThroughputPerSec   float64  `json:"delivery_throughput_per_sec"`
	ReplayCreateAndDrainMS     float64  `json:"replay_create_and_drain_ms"`
	RetryScheduledDeliveries   int      `json:"retry_scheduled_deliveries"`
	SuccessfulDeliveries       int      `json:"successful_deliveries"`
	ErrorCount                 int      `json:"error_count"`
	SanitizedEvidenceStatement string   `json:"sanitized_evidence_statement"`
	Notes                      []string `json:"notes"`
}

func TestPerfSmoke(t *testing.T) {
	ctx, store, actor := openRCStore(t)
	defer store.Close()

	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	control := app.NewControlService(store, ssrf.Validator{Resolver: rcResolver})
	source, _ := createRCRoute(t, ctx, control, actor, "stripe", "stripe", "invoice.perf_smoke")
	ingest := app.NewIngestService(store, fixedClock{now: now})

	const eventCount = 25
	ingestDurations := make([]time.Duration, 0, eventCount)
	eventIDs := make([]string, 0, eventCount)
	for i := 0; i < eventCount; i++ {
		body := []byte(fmt.Sprintf(`{"id":"evt_perf_%s_%02d","type":"invoice.perf_smoke","data":{"object":{"id":"in_%02d"}}}`, testSuffix(t), i, i))
		start := time.Now()
		result, err := ingest.Ingest(ctx, app.IngestRequest{
			TenantID:    actor.TenantID,
			SourceID:    source.ID,
			Provider:    "stripe",
			RawBody:     body,
			Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: stripeSignature(now, body)}},
			ContentType: "application/json",
			RemoteIP:    "198.51.100.10",
		})
		ingestDurations = append(ingestDurations, time.Since(start))
		if err != nil {
			t.Fatalf("perf ingest event %d: %v", i, err)
		}
		if !result.Accepted || result.EventID == "" {
			t.Fatalf("perf ingest event %d was not accepted durably: %+v", i, result)
		}
		eventIDs = append(eventIDs, result.EventID)
	}

	delivery := &recordingDeliveryClient{
		t:      t,
		now:    now.Add(time.Second),
		result: workerSuccessResult(),
	}
	drainStart := time.Now()
	for i := 0; i < 4 && len(delivery.calls) < eventCount; i++ {
		runWorkerOnce(t, ctx, store, delivery, "perf-drain-"+testSuffix(t))
	}
	deliveryDrain := time.Since(drainStart)
	if len(delivery.calls) != eventCount {
		t.Fatalf("expected %d successful deliveries, got %d", eventCount, len(delivery.calls))
	}

	replayStart := time.Now()
	if _, err := control.CreateReplay(ctx, actor, app.ReplayRequest{
		EventID:    eventIDs[0],
		ReasonCode: app.ReplayReasonTestDrill,
		Reason:     "performance smoke replay",
		ConfigMode: app.ReplayConfigCurrent,
	}); err != nil {
		t.Fatalf("create perf replay: %v", err)
	}
	for i := 0; i < 3 && len(delivery.calls) < eventCount+1; i++ {
		runWorkerOnce(t, ctx, store, delivery, "perf-replay-"+testSuffix(t))
	}
	replayDrain := time.Since(replayStart)
	if len(delivery.calls) < eventCount+1 {
		t.Fatalf("expected replay delivery to drain, got %d calls", len(delivery.calls))
	}

	retryScheduled := scheduleOneRetry(t, ctx, store, control, actor, source.ID, now)
	report := perfSmokeReport{
		GeneratedAtUTC:             time.Now().UTC().Format(time.RFC3339),
		Scenario:                   "local-postgres-fake-provider-fake-receiver",
		EventCount:                 eventCount,
		IngestP50MS:                millis(percentileDuration(ingestDurations, 50)),
		IngestP95MS:                millis(percentileDuration(ingestDurations, 95)),
		IngestP99MS:                millis(percentileDuration(ingestDurations, 99)),
		DeliveryDrainMS:            millis(deliveryDrain),
		DeliveryThroughputPerSec:   safeRate(float64(eventCount), deliveryDrain),
		ReplayCreateAndDrainMS:     millis(replayDrain),
		RetryScheduledDeliveries:   retryScheduled,
		SuccessfulDeliveries:       len(delivery.calls),
		ErrorCount:                 0,
		SanitizedEvidenceStatement: "contains aggregate timings and counts only; no database URLs, endpoint URLs, secrets, signatures, raw payloads, tenant IDs, or customer data",
		Notes: []string{
			"local fake Stripe-style signatures only",
			"local fake receiver only",
			"smoke values are release evidence, not universal performance guarantees",
		},
	}
	writePerfSmokeReport(t, report)
}

func scheduleOneRetry(t *testing.T, ctx context.Context, store *postgres.Store, control *app.ControlService, actor authz.Actor, sourceID string, now time.Time) int {
	t.Helper()
	retryPolicy, err := control.CreateRetryPolicy(ctx, actor, app.CreateRetryPolicyRequest{
		Name:                "perf retry",
		MaxAttempts:         2,
		MaxDurationSeconds:  60,
		InitialDelaySeconds: 1,
		MaxDelaySeconds:     1,
	})
	if err != nil {
		t.Fatalf("create perf retry policy: %v", err)
	}
	endpoint, _, err := control.CreateEndpoint(ctx, actor, app.CreateEndpointRequest{
		Name: "Perf retry receiver",
		URL:  "https://receiver.example.com/retry",
	})
	if err != nil {
		t.Fatalf("create perf retry endpoint: %v", err)
	}
	if _, err := control.CreateRoute(ctx, actor, app.CreateRouteRequest{
		SourceID:      sourceID,
		Name:          "Perf retry route",
		Priority:      20,
		EventTypes:    []string{"invoice.perf_retry"},
		EndpointID:    endpoint.ID,
		RetryPolicyID: retryPolicy.ID,
		State:         domain.StateActive,
	}); err != nil {
		t.Fatalf("create perf retry route: %v", err)
	}
	ingest := app.NewIngestService(store, fixedClock{now: now})
	body := []byte(`{"id":"evt_perf_retry_` + testSuffix(t) + `","type":"invoice.perf_retry","data":{"object":{"id":"retry"}}}`)
	result, err := ingest.Ingest(ctx, app.IngestRequest{
		TenantID:    actor.TenantID,
		SourceID:    sourceID,
		Provider:    "stripe",
		RawBody:     body,
		Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: stripeSignature(now, body)}},
		ContentType: "application/json",
		RemoteIP:    "198.51.100.10",
	})
	if err != nil {
		t.Fatalf("ingest perf retry event: %v", err)
	}
	failingDelivery := &recordingDeliveryClient{
		t:   t,
		now: now.Add(2 * time.Second),
		result: worker.DeliveryResult{
			StatusCode:   http.StatusServiceUnavailable,
			ResponseBody: []byte("temporary failure"),
			FailureClass: "http_5xx",
		},
	}
	runWorkerOnce(t, ctx, store, failingDelivery, "perf-retry-"+testSuffix(t))
	deliveries, err := control.ListDeliveries(ctx, actor, 200)
	if err != nil {
		t.Fatalf("list perf retry deliveries: %v", err)
	}
	scheduled := 0
	for _, delivery := range deliveries {
		if delivery.EventID == result.EventID && delivery.State == "scheduled" && delivery.AttemptCount == 1 {
			scheduled++
		}
	}
	if scheduled == 0 {
		t.Fatalf("expected retry delivery to be rescheduled after first failure")
	}
	return scheduled
}

func workerSuccessResult() worker.DeliveryResult {
	return worker.DeliveryResult{
		StatusCode:   http.StatusAccepted,
		ResponseBody: []byte("ok"),
		FailureClass: "success",
	}
}

func stripeSignature(now time.Time, body []byte) string {
	return verifier.TimestampedHeader("v1", now, []byte("whsec_rc"), body)
}

func writePerfSmokeReport(t *testing.T, report perfSmokeReport) {
	t.Helper()
	outDir := os.Getenv("WEBHOOKERY_PERF_OUTPUT_DIR")
	if strings.TrimSpace(outDir) == "" {
		outDir = filepath.Join("..", "..", "tmp", "perf-smoke")
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil { // #nosec G703 -- perf smoke writes to an operator-selected local evidence directory.
		t.Fatalf("create perf smoke output dir: %v", err)
	}
	jsonBody, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal perf smoke report: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "perf-smoke.json"), append(jsonBody, '\n'), 0o600); err != nil { // #nosec G703 -- perf smoke writes sanitized evidence to an operator-selected local directory.
		t.Fatalf("write perf smoke json: %v", err)
	}
	markdown := fmt.Sprintf(`# Webhookery Performance Smoke

- Scenario: %s
- Events: %d
- Ingest p50/p95/p99: %.3f / %.3f / %.3f ms
- Delivery drain: %.3f ms
- Delivery throughput: %.3f deliveries/sec
- Replay create and drain: %.3f ms
- Retry scheduled deliveries: %d
- Successful deliveries: %d
- Errors: %d

%s.
`, report.Scenario, report.EventCount, report.IngestP50MS, report.IngestP95MS, report.IngestP99MS, report.DeliveryDrainMS, report.DeliveryThroughputPerSec, report.ReplayCreateAndDrainMS, report.RetryScheduledDeliveries, report.SuccessfulDeliveries, report.ErrorCount, report.SanitizedEvidenceStatement)
	if err := os.WriteFile(filepath.Join(outDir, "perf-smoke.md"), []byte(markdown), 0o600); err != nil { // #nosec G703 -- perf smoke writes sanitized evidence to an operator-selected local directory.
		t.Fatalf("write perf smoke markdown: %v", err)
	}
}

func percentileDuration(values []time.Duration, p float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	rank := int(math.Ceil((p/100)*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

func millis(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

func safeRate(count float64, d time.Duration) float64 {
	if d <= 0 {
		return count
	}
	return count / d.Seconds()
}
