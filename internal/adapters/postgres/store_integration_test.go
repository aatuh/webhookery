package postgres

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"webhookery/internal/adapters/crypto"
	"webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/evidence"
	"webhookery/internal/reconcile"
	"webhookery/internal/ssrf"
	"webhookery/internal/worker"
	"webhookery/pkg/verifier"
)

func TestPostgresMigrationAndAPIKeyAuthentication(t *testing.T) {
	databaseURL := os.Getenv("WEBHOOKERY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("WEBHOOKERY_TEST_DATABASE_URL is required to prove live Postgres migrations and API-key authentication")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	migrationsDir := filepath.Join("..", "..", "..", "migrations")
	if err := MigrateUp(ctx, databaseURL, migrationsDir); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	box, err := crypto.NewEnvelope(key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(ctx, databaseURL, box)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	rawToken := "whkey_integration_" + time.Now().UTC().Format("20060102150405")
	tenantID := "ten_it_" + time.Now().UTC().Format("150405")
	created, err := store.CreateAPIKey(ctx, app.APIKeyCreateInput{
		Key: domain.APIKey{
			TenantID: tenantID,
			UserID:   "usr_it",
			Name:     "integration",
			Prefix:   "whkey_in",
			Last4:    "0405",
			Hash:     app.HashToken(rawToken),
			Scopes:   []string{"events:read"},
			State:    domain.StateActive,
		},
		Role:    authz.RoleOperator,
		ActorID: "usr_it",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" {
		t.Fatal("expected created API key id")
	}
	actor, err := store.AuthenticateAPIKey(ctx, app.HashToken(rawToken))
	if err != nil {
		t.Fatal(err)
	}
	if actor.TenantID != tenantID || actor.Role != authz.RoleOperator {
		t.Fatalf("unexpected actor: %+v", actor)
	}
}

func TestPostgresWorkerLeaseRecoveryAndLivePriority(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	now := time.Date(2026, 5, 26, 16, 0, 0, 0, time.UTC)
	if _, err := store.pool.Exec(ctx, `UPDATE outbox SET state='completed', locked_by=NULL, lock_expires_at=NULL WHERE (tenant_id LIKE 'ten_it_%' OR tenant_id LIKE 'ten_rc_%') AND state <> 'completed'`); err != nil {
		t.Fatalf("clear prior integration outbox work: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE deliveries SET state='succeeded', locked_by=NULL, lock_expires_at=NULL WHERE (tenant_id LIKE 'ten_it_%' OR tenant_id LIKE 'ten_rc_%') AND state IN ('scheduled','in_progress')`); err != nil {
		t.Fatalf("clear prior integration delivery work: %v", err)
	}
	control := app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{"receiver.example.com": {netip.MustParseAddr("93.184.216.34")}}})
	fanout := app.NewDeliveryFanoutService(store, app.SystemClock{})
	source, _ := createPostgresIntegrationRoute(t, ctx, control, actor, "invoice.created")
	first := ingestPostgresIntegrationEvent(t, ctx, store, actor, source.ID, "invoice.created", "evt_it_recovery_"+time.Now().UTC().Format("150405.000000000"), now)

	stuckOutbox, err := store.ClaimOutbox(ctx, "it-stuck-outbox", 1)
	if err != nil {
		t.Fatalf("claim outbox before recovery: %v", err)
	}
	if len(stuckOutbox) != 1 || stuckOutbox[0].ResourceID != first.EventID {
		t.Fatalf("expected first outbox item for accepted event: %+v", stuckOutbox)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE outbox SET lock_expires_at=now() - interval '1 second' WHERE id=$1`, stuckOutbox[0].ID); err != nil {
		t.Fatalf("expire outbox lock: %v", err)
	}
	recoveredOutbox, err := store.ClaimOutbox(ctx, "it-recovered-outbox", 1)
	if err != nil {
		t.Fatalf("claim expired outbox: %v", err)
	}
	if len(recoveredOutbox) != 1 || recoveredOutbox[0].ID != stuckOutbox[0].ID {
		t.Fatalf("expected expired outbox to be reclaimed, got %+v", recoveredOutbox)
	}
	if err := fanout.ProcessOutbox(ctx, recoveredOutbox[0]); err != nil {
		t.Fatalf("process recovered outbox: %v", err)
	}
	if err := store.CompleteOutbox(ctx, recoveredOutbox[0].ID); err != nil {
		t.Fatalf("complete recovered outbox: %v", err)
	}

	stuckDelivery, err := store.ClaimDueDeliveries(ctx, "it-stuck-delivery", 1)
	if err != nil {
		t.Fatalf("claim delivery before recovery: %v", err)
	}
	if len(stuckDelivery) != 1 || stuckDelivery[0].EventID != first.EventID {
		t.Fatalf("expected first delivery for accepted event: %+v", stuckDelivery)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE deliveries SET lock_expires_at=now() - interval '1 second' WHERE tenant_id=$1 AND id=$2`, actor.TenantID, stuckDelivery[0].ID); err != nil {
		t.Fatalf("expire delivery lock: %v", err)
	}
	recoveredDelivery, err := store.ClaimDueDeliveries(ctx, "it-recovered-delivery", 1)
	if err != nil {
		t.Fatalf("claim expired delivery: %v", err)
	}
	if len(recoveredDelivery) != 1 || recoveredDelivery[0].ID != stuckDelivery[0].ID {
		t.Fatalf("expected expired delivery to be reclaimed, got %+v", recoveredDelivery)
	}
	if err := store.RecordDeliveryAttempt(ctx, recoveredDelivery[0], worker.DeliveryResult{StatusCode: 202, ResponseBody: []byte("ok"), FailureClass: "success"}, nil); err != nil {
		t.Fatalf("complete recovered delivery: %v", err)
	}

	second := ingestPostgresIntegrationEvent(t, ctx, store, actor, source.ID, "invoice.created", "evt_it_priority_"+time.Now().UTC().Format("150405.000000000"), now.Add(time.Second))
	if _, err := store.CreateReplay(ctx, actor.TenantID, actor.ID, app.ReplayRequest{EventID: second.EventID, Reason: "integration priority drill", ConfigMode: app.ReplayConfigCurrent}); err != nil {
		t.Fatalf("create replay for priority drill: %v", err)
	}
	outboxItems, err := store.ClaimOutbox(ctx, "it-priority-outbox", 10)
	if err != nil {
		t.Fatalf("claim priority outbox items: %v", err)
	}
	if len(outboxItems) < 2 {
		t.Fatalf("expected live and replay outbox work, got %+v", outboxItems)
	}
	for _, item := range outboxItems {
		if err := fanout.ProcessOutbox(ctx, item); err != nil {
			t.Fatalf("process priority outbox item %+v: %v", item, err)
		}
		if err := store.CompleteOutbox(ctx, item.ID); err != nil {
			t.Fatalf("complete priority outbox item %+v: %v", item, err)
		}
	}
	priorityDelivery, err := store.ClaimDueDeliveries(ctx, "it-priority-delivery", 1)
	if err != nil {
		t.Fatalf("claim priority delivery: %v", err)
	}
	if len(priorityDelivery) != 1 {
		t.Fatalf("expected one priority delivery, got %+v", priorityDelivery)
	}
	var replayJobID string
	if err := store.pool.QueryRow(ctx, `SELECT COALESCE(replay_job_id,'') FROM deliveries WHERE tenant_id=$1 AND id=$2`, actor.TenantID, priorityDelivery[0].ID).Scan(&replayJobID); err != nil {
		t.Fatalf("read claimed delivery replay marker: %v", err)
	}
	if replayJobID != "" {
		t.Fatalf("live delivery must be prioritized over replay delivery, claimed replay job %s", replayJobID)
	}
}

func TestPostgresDuplicateRawPayloadEvidenceRemainsLinkedAndExported(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	control := app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{"receiver.example.com": {netip.MustParseAddr("93.184.216.34")}}})
	source, _ := createPostgresIntegrationRoute(t, ctx, control, actor, "invoice.duplicate")
	providerID := "evt_it_duplicate_" + now.Format("150405.000000000")

	first := ingestPostgresIntegrationEvent(t, ctx, store, actor, source.ID, "invoice.duplicate", providerID, now)
	second := ingestPostgresIntegrationEvent(t, ctx, store, actor, source.ID, "invoice.duplicate", providerID, now.Add(time.Second))
	if second.EventID != first.EventID {
		t.Fatalf("duplicate receipt must link to original event: first=%s second=%s", first.EventID, second.EventID)
	}
	if second.DedupeStatus != domain.DedupeDuplicateSuppressed {
		t.Fatalf("expected duplicate_suppressed, got %s", second.DedupeStatus)
	}

	rows, err := store.pool.Query(ctx, `
		SELECT rp.id, rp.event_id, pr.id
		FROM raw_payloads rp
		JOIN provider_receipts pr ON pr.tenant_id=rp.tenant_id AND pr.raw_payload_id=rp.id
		WHERE rp.tenant_id=$1 AND rp.event_id=$2
		ORDER BY rp.created_at ASC, rp.id ASC`, actor.TenantID, first.EventID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	rawIDsByReceipt := map[string]string{}
	for rows.Next() {
		var rawID, eventID, receiptID string
		if err := rows.Scan(&rawID, &eventID, &receiptID); err != nil {
			t.Fatal(err)
		}
		if eventID != first.EventID {
			t.Fatalf("raw payload %s linked to %s, want %s", rawID, eventID, first.EventID)
		}
		rawIDsByReceipt[receiptID] = rawID
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(rawIDsByReceipt) != 2 {
		t.Fatalf("expected two receipt-linked raw payloads, got %+v", rawIDsByReceipt)
	}

	timeline, err := store.ListEventTimeline(ctx, actor.TenantID, first.EventID, 100)
	if err != nil {
		t.Fatal(err)
	}
	rawTimelineByID := map[string]string{}
	for _, item := range timeline {
		if item.Kind == "raw_payload" {
			rawTimelineByID[item.RefID] = item.Detail
		}
	}
	if len(rawTimelineByID) != 2 {
		t.Fatalf("expected duplicate raw payloads in timeline, got %+v", rawTimelineByID)
	}
	for receiptID, rawID := range rawIDsByReceipt {
		if !strings.Contains(rawTimelineByID[rawID], receiptID) {
			t.Fatalf("timeline detail for raw payload %s did not reference receipt %s: %q", rawID, receiptID, rawTimelineByID[rawID])
		}
	}

	export, err := store.CreateAuditExport(ctx, actor.TenantID, actor.ID, app.CreateAuditExportRequest{
		From:               now.Add(-time.Minute),
		To:                 now.Add(time.Minute),
		IncludeRawPayloads: true,
		IncludeTimelines:   true,
		Reason:             "duplicate raw evidence regression",
	})
	if err != nil {
		t.Fatal(err)
	}
	download, err := store.DownloadAuditExport(ctx, actor.TenantID, export.ID, actor.ID)
	if err != nil {
		t.Fatal(err)
	}
	files := readTestTarGzipFiles(t, download.Body)
	rawEntries := decodeTestJSONLines(t, files["raw_payloads.jsonl"])
	rawExportCount := 0
	for _, entry := range rawEntries {
		if entry["event_id"] != first.EventID {
			continue
		}
		rawExportCount++
		body, ok := entry["body_base64"].(string)
		if !ok || body == "" {
			t.Fatalf("raw payload export omitted body for %+v", entry)
		}
		receiptIDs, ok := entry["receipt_ids"].([]any)
		if !ok || len(receiptIDs) != 1 {
			t.Fatalf("raw payload export must include receipt_ids, got %+v", entry["receipt_ids"])
		}
	}
	if rawExportCount != 2 {
		t.Fatalf("expected two raw payload export rows for duplicate event, got %d from %+v", rawExportCount, rawEntries)
	}

	timelineEntries := decodeTestJSONLines(t, files["timelines.jsonl"])
	rawTimelineExportCount := 0
	for _, entry := range timelineEntries {
		if entry["event_id"] != first.EventID {
			continue
		}
		for _, item := range entry["timeline"].([]any) {
			timelineItem := item.(map[string]any)
			if timelineItem["kind"] == "raw_payload" {
				rawTimelineExportCount++
			}
		}
	}
	if rawTimelineExportCount != 2 {
		t.Fatalf("expected two raw payload timeline export rows, got %d", rawTimelineExportCount)
	}

	if _, err := store.pool.Exec(ctx, `UPDATE raw_payloads SET created_at=now() - interval '48 hours' WHERE tenant_id=$1 AND event_id=$2`, actor.TenantID, first.EventID); err != nil {
		t.Fatal(err)
	}
	policy, err := store.CreateRetentionPolicy(ctx, actor.TenantID, actor.ID, app.CreateRetentionPolicyRequest{
		ResourceType:  domain.RetentionResourceRawPayload,
		SourceID:      source.ID,
		RetentionDays: 1,
		State:         domain.StateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.applyRetentionPolicy(ctx, "worker_it", policy); err != nil {
		t.Fatal(err)
	}
	var retainedBodies int
	if err := store.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM raw_payloads
		WHERE tenant_id=$1 AND event_id=$2 AND storage_status='stored'`, actor.TenantID, first.EventID).Scan(&retainedBodies); err != nil {
		t.Fatal(err)
	}
	if retainedBodies != 0 {
		t.Fatalf("source-scoped retention left %d duplicate raw payload bodies stored", retainedBodies)
	}
}

func TestPostgresEventSearchDeliveryControlAndDeadLetterLifecycle(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	if _, err := store.pool.Exec(ctx, `UPDATE outbox SET state='completed', locked_by=NULL, lock_expires_at=NULL WHERE (tenant_id LIKE 'ten_it_%' OR tenant_id LIKE 'ten_rc_%') AND state <> 'completed'`); err != nil {
		t.Fatalf("clear prior integration outbox work: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE deliveries SET state='succeeded', locked_by=NULL, lock_expires_at=NULL WHERE (tenant_id LIKE 'ten_it_%' OR tenant_id LIKE 'ten_rc_%') AND state IN ('scheduled','in_progress')`); err != nil {
		t.Fatalf("clear prior integration delivery work: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	eventType := "invoice.delivery_controls"
	providerID := "evt_it_delivery_controls_" + now.Format("150405.000000000")
	control := app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{"receiver.example.com": {netip.MustParseAddr("93.184.216.34")}}})
	fanout := app.NewDeliveryFanoutService(store, app.SystemClock{})

	source, err := control.CreateSource(ctx, actor, app.CreateSourceRequest{Name: "delivery source", Provider: "stripe", Adapter: "stripe", VerificationSecret: "whsec_it"})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, _, err := control.CreateEndpoint(ctx, actor, app.CreateEndpointRequest{Name: "delivery endpoint", URL: "https://receiver.example.com/webhook"})
	if err != nil {
		t.Fatal(err)
	}
	retryPolicy, err := control.CreateRetryPolicy(ctx, actor, app.CreateRetryPolicyRequest{
		Name:                "single attempt",
		MaxAttempts:         1,
		MaxDurationSeconds:  60,
		InitialDelaySeconds: 1,
		MaxDelaySeconds:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	route, err := control.CreateRoute(ctx, actor, app.CreateRouteRequest{
		SourceID:      source.ID,
		Name:          "delivery controls route",
		Priority:      5,
		EventTypes:    []string{eventType},
		EndpointID:    endpoint.ID,
		RetryPolicyID: retryPolicy.ID,
		State:         domain.StateActive,
	})
	if err != nil {
		t.Fatal(err)
	}

	ingested := ingestPostgresIntegrationEvent(t, ctx, store, actor, source.ID, eventType, providerID, now)
	event, err := control.GetEvent(ctx, actor, ingested.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if event.ProviderID != providerID || !event.Verified || event.RawPayloadHash == "" {
		t.Fatalf("event evidence did not round trip: %+v", event)
	}
	if _, err := store.GetEvent(ctx, "ten_it_wrong_delivery_controls", ingested.EventID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("wrong-tenant event lookup must be hidden, got %v", err)
	}

	raw, err := control.GetRawPayload(ctx, actor, ingested.EventID, "delivery control evidence")
	if err != nil {
		t.Fatal(err)
	}
	if raw.EventID != ingested.EventID || raw.SHA256 != event.RawPayloadHash || !bytes.Contains(raw.Body, []byte(providerID)) {
		t.Fatalf("raw payload did not preserve event evidence: %+v body=%q", raw, string(raw.Body))
	}
	normalized, err := control.GetNormalizedEvent(ctx, actor, ingested.EventID, false)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.EventID != ingested.EventID || normalized.Data != nil || normalized.EnvelopeSHA256 == "" {
		t.Fatalf("normalized envelope metadata did not round trip without data: %+v", normalized)
	}
	normalizedWithData, err := control.GetNormalizedEvent(ctx, actor, ingested.EventID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalizedWithData.Data) == 0 || normalizedWithData.DataSHA256 == "" {
		t.Fatalf("normalized envelope data read omitted payload evidence: %+v", normalizedWithData)
	}

	searches := []app.EventSearchRequest{
		{Provider: "stripe", Limit: 10},
		{ExternalID: providerID, Limit: 10},
		{Verification: "valid", Limit: 10},
		{ReceivedAfter: now.Add(-time.Minute), Limit: 10},
	}
	for _, req := range searches {
		events, err := store.ListEvents(ctx, actor.TenantID, req)
		if err != nil {
			t.Fatalf("search %+v: %v", req, err)
		}
		if !containsPostgresEvent(events, ingested.EventID) {
			t.Fatalf("search %+v did not return event %s: %+v", req, ingested.EventID, events)
		}
	}
	controlEvents, err := control.ListEvents(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresEvent(controlEvents, ingested.EventID) {
		t.Fatalf("control list did not return event %s: %+v", ingested.EventID, controlEvents)
	}

	dryRun, err := control.DryRunRoute(ctx, actor, route.ID, ingested.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if !dryRun.Matched || len(dryRun.WouldCreateDeliveries) != 1 {
		t.Fatalf("expected route dry run to match one delivery, got %+v", dryRun)
	}

	outboxItems, err := store.ClaimOutbox(ctx, "it-delivery-controls-outbox", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(outboxItems) != 1 || outboxItems[0].ResourceID != ingested.EventID {
		t.Fatalf("expected one outbox item for event, got %+v", outboxItems)
	}
	if err := fanout.ProcessOutbox(ctx, outboxItems[0]); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteOutbox(ctx, outboxItems[0].ID); err != nil {
		t.Fatal(err)
	}

	claimed, err := store.ClaimDueDeliveries(ctx, "it-delivery-controls-worker", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].EventID != ingested.EventID || claimed[0].EndpointID != endpoint.ID {
		t.Fatalf("expected one due delivery for event, got %+v", claimed)
	}
	if len(claimed[0].Body) == 0 || len(claimed[0].SigningSecret) == 0 {
		t.Fatalf("claimed delivery did not include signed payload material: %+v", claimed[0])
	}
	if err := store.RecordDeliveryAttempt(ctx, claimed[0], worker.DeliveryResult{StatusCode: 503, ResponseBody: []byte("receiver unavailable")}, nil); err != nil {
		t.Fatal(err)
	}

	deliveries, err := control.ListDeliveries(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	delivery, ok := findPostgresDelivery(deliveries, claimed[0].ID)
	if !ok {
		t.Fatalf("delivery %s not listed: %+v", claimed[0].ID, deliveries)
	}
	if delivery.State != "dead_lettered" || delivery.AttemptCount != 1 || delivery.DeliveryPayloadID == "" || delivery.DeliveryPayloadSHA256 == "" {
		t.Fatalf("delivery did not retain terminal evidence fields: %+v", delivery)
	}
	searchesAfterDLQ := []app.EventSearchRequest{
		{DeliveryID: delivery.ID, Limit: 10},
		{RouteID: route.ID, Limit: 10},
		{Status: "dlq", Limit: 10},
	}
	for _, req := range searchesAfterDLQ {
		events, err := store.ListEvents(ctx, actor.TenantID, req)
		if err != nil {
			t.Fatalf("search %+v: %v", req, err)
		}
		if !containsPostgresEvent(events, ingested.EventID) {
			t.Fatalf("search %+v did not return dead-lettered event %s: %+v", req, ingested.EventID, events)
		}
	}

	attempts, err := control.ListDeliveryAttempts(ctx, actor, delivery.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 || attempts[0].State != "failed" || attempts[0].ResponseStatus != 503 || attempts[0].ResponseBodyTruncated != "receiver unavailable" {
		t.Fatalf("unexpected delivery attempts: %+v", attempts)
	}
	gotAttempt, err := control.GetDeliveryAttempt(ctx, actor, attempts[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotAttempt.ID != attempts[0].ID || gotAttempt.DeliveryID != delivery.ID {
		t.Fatalf("delivery attempt did not round trip: %+v", gotAttempt)
	}
	if _, err := store.GetDeliveryAttempt(ctx, "ten_it_wrong_delivery_controls", attempts[0].ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("wrong-tenant delivery attempt lookup must be hidden, got %v", err)
	}

	timeline, err := control.ListEventTimeline(ctx, actor, ingested.EventID, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresTimelineKind(timeline, "delivery") || !containsPostgresTimelineKind(timeline, "attempt") || !containsPostgresTimelineKind(timeline, "normalized") {
		t.Fatalf("timeline omitted delivery evidence: %+v", timeline)
	}

	deadLetters, err := control.ListDeadLetter(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	entryID := findPostgresDeadLetterEntry(deadLetters, delivery.ID)
	if entryID == "" {
		t.Fatalf("dead-letter entry for delivery %s not listed: %+v", delivery.ID, deadLetters)
	}
	replayJob, err := control.ReleaseDeadLetter(ctx, actor, entryID, app.DeadLetterReleaseRequest{ReasonCode: app.ReplayReasonReceiverFixed, Reason: "receiver recovered"})
	if err != nil {
		t.Fatal(err)
	}
	if replayJob.State != "scheduled" || replayJob.TotalItems != 1 || replayJob.ReasonCode != app.ReplayReasonReceiverFixed {
		t.Fatalf("dead-letter release did not create scheduled replay: %+v", replayJob)
	}
	if _, err := control.ReleaseDeadLetter(ctx, actor, entryID, app.DeadLetterReleaseRequest{ReasonCode: app.ReplayReasonReceiverFixed, Reason: "already released"}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("released dead-letter entry must not be reusable, got %v", err)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "dead_letter.released", "dead_letter_entry", entryID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "replay.created", "replay_job", replayJob.ID)
}

func TestPostgresReplayApprovalAndFanoutControls(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	if _, err := store.pool.Exec(ctx, `UPDATE outbox SET state='completed', locked_by=NULL, lock_expires_at=NULL WHERE (tenant_id LIKE 'ten_it_%' OR tenant_id LIKE 'ten_rc_%') AND state <> 'completed'`); err != nil {
		t.Fatalf("clear prior integration outbox work: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE deliveries SET state='succeeded', locked_by=NULL, lock_expires_at=NULL WHERE (tenant_id LIKE 'ten_it_%' OR tenant_id LIKE 'ten_rc_%') AND state IN ('scheduled','in_progress')`); err != nil {
		t.Fatalf("clear prior integration delivery work: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	eventType := "invoice.replay_controls"
	control := app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{"receiver.example.com": {netip.MustParseAddr("93.184.216.34")}}})
	fanout := app.NewDeliveryFanoutService(store, app.SystemClock{})

	source, err := control.CreateSource(ctx, actor, app.CreateSourceRequest{Name: "replay controls source", Provider: "stripe", Adapter: "stripe", VerificationSecret: "whsec_it"})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, _, err := control.CreateEndpoint(ctx, actor, app.CreateEndpointRequest{Name: "replay controls endpoint", URL: "https://receiver.example.com/webhook"})
	if err != nil {
		t.Fatal(err)
	}
	route, err := control.CreateRoute(ctx, actor, app.CreateRouteRequest{SourceID: source.ID, Name: "replay controls route", Priority: 3, EventTypes: []string{eventType}, EndpointID: endpoint.ID, State: domain.StateActive})
	if err != nil {
		t.Fatal(err)
	}
	ingested := ingestPostgresIntegrationEvent(t, ctx, store, actor, source.ID, eventType, "evt_it_replay_controls_"+now.Format("150405.000000000"), now)

	outboxItems, err := store.ClaimOutbox(ctx, "it-replay-controls-route-outbox", 10)
	if err != nil {
		t.Fatal(err)
	}
	routeOutbox := findPostgresOutboxItem(t, outboxItems, app.OutboxKindRouteEvent, ingested.EventID)
	if err := fanout.ProcessOutbox(ctx, routeOutbox); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteOutbox(ctx, routeOutbox.ID); err != nil {
		t.Fatal(err)
	}

	deliveries, err := control.ListDeliveries(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	originalDelivery := findPostgresDeliveryForEvent(t, deliveries, ingested.EventID)
	if originalDelivery.DeliveryPayloadID == "" || originalDelivery.DeliveryPayloadSHA256 == "" {
		t.Fatalf("original delivery did not preserve replayable payload evidence: %+v", originalDelivery)
	}
	canceledDelivery, err := control.CancelDelivery(ctx, actor, originalDelivery.ID, app.StateChangeRequest{Reason: "operator paused receiver"})
	if err != nil {
		t.Fatal(err)
	}
	if canceledDelivery.State != "canceled" {
		t.Fatalf("expected canceled delivery, got %+v", canceledDelivery)
	}
	if _, err := control.CancelDelivery(ctx, actor, originalDelivery.ID, app.StateChangeRequest{Reason: "already canceled"}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("canceled delivery must not be cancelable again, got %v", err)
	}
	retriedDelivery, err := control.RetryDelivery(ctx, actor, originalDelivery.ID, "receiver recovered")
	if err != nil {
		t.Fatal(err)
	}
	if retriedDelivery.State != "scheduled" || retriedDelivery.NextAttemptAt.IsZero() {
		t.Fatalf("expected manual retry to reschedule delivery, got %+v", retriedDelivery)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "delivery.canceled", "delivery", originalDelivery.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "delivery.retry_requested", "delivery", originalDelivery.ID)

	policy, err := control.CreateReplayApprovalPolicy(ctx, actor, app.CreateReplayApprovalPolicyRequest{
		ScopeType:            app.ReplayApprovalScopeRoute,
		ScopeID:              route.ID,
		RequireApproval:      true,
		DefaultExpirySeconds: 600,
		Reason:               "sensitive receiver route",
	})
	if err != nil {
		t.Fatal(err)
	}
	if policy.TenantID != actor.TenantID || policy.ScopeID != route.ID || !policy.RequireApproval || policy.State != domain.StateActive {
		t.Fatalf("replay approval policy did not persist route scope: %+v", policy)
	}
	policies, err := control.ListReplayApprovalPolicies(ctx, actor, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresReplayApprovalPolicy(policies, policy.ID, domain.StateActive) {
		t.Fatalf("expected replay approval policy in tenant list, got %+v", policies)
	}

	pendingReplay, err := control.CreateReplay(ctx, actor, app.ReplayRequest{
		EventID:            ingested.EventID,
		ReasonCode:         app.ReplayReasonTestDrill,
		Reason:             "route approval drill",
		ConfigMode:         app.ReplayConfigOriginal,
		RateLimitPerMinute: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pendingReplay.State != "pending_approval" || !pendingReplay.ApprovalRequired || pendingReplay.TotalItems != 1 || pendingReplay.ApprovalExpiresAt == nil {
		t.Fatalf("route-scoped replay policy did not require approval: %+v", pendingReplay)
	}
	assertPostgresNoOutboxItem(t, ctx, store, actor.TenantID, app.OutboxKindReplayJob, pendingReplay.ID)
	if _, err := control.ApproveReplayJob(ctx, actor, pendingReplay.ID, app.StateChangeRequest{Reason: "self approval must fail"}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("replay creator must not self-approve pending replay, got %v", err)
	}

	approver := actor
	approver.ID = actor.ID + "_approver"
	if _, err := store.CreateAPIKey(ctx, app.APIKeyCreateInput{
		Key: domain.APIKey{
			TenantID: actor.TenantID,
			UserID:   approver.ID,
			Name:     "replay approver",
			Prefix:   "it-appr",
			Last4:    "appr",
			Hash:     app.HashToken("integration-replay-approver-" + now.Format("150405.000000000")),
			Scopes:   []string{"*"},
			State:    domain.StateActive,
		},
		Role:    authz.RoleOwner,
		ActorID: actor.ID,
	}); err != nil {
		t.Fatal(err)
	}
	approvedReplay, err := control.ApproveReplayJob(ctx, approver, pendingReplay.ID, app.StateChangeRequest{Reason: "independent approval"})
	if err != nil {
		t.Fatal(err)
	}
	if approvedReplay.State != "scheduled" || approvedReplay.ApprovedBy != approver.ID || approvedReplay.ApprovedAt == nil {
		t.Fatalf("replay approval did not schedule durable work: %+v", approvedReplay)
	}
	pausedReplay, err := control.PauseReplayJob(ctx, actor, approvedReplay.ID, app.StateChangeRequest{Reason: "hold replay window"})
	if err != nil {
		t.Fatal(err)
	}
	if pausedReplay.State != "paused" {
		t.Fatalf("expected paused replay, got %+v", pausedReplay)
	}
	resumedReplay, err := control.ResumeReplayJob(ctx, actor, approvedReplay.ID, app.StateChangeRequest{Reason: "resume replay window"})
	if err != nil {
		t.Fatal(err)
	}
	if resumedReplay.State != "scheduled" {
		t.Fatalf("expected resumed replay, got %+v", resumedReplay)
	}
	replayJobs, err := control.ListReplayJobs(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresReplayJob(replayJobs, approvedReplay.ID, "scheduled") {
		t.Fatalf("expected scheduled replay job in tenant list, got %+v", replayJobs)
	}

	outboxItems, err = store.ClaimOutbox(ctx, "it-replay-controls-replay-outbox", 10)
	if err != nil {
		t.Fatal(err)
	}
	replayOutbox := findPostgresOutboxItem(t, outboxItems, app.OutboxKindReplayJob, approvedReplay.ID)
	if err := fanout.ProcessOutbox(ctx, replayOutbox); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteOutbox(ctx, replayOutbox.ID); err != nil {
		t.Fatal(err)
	}
	replayJobs, err = control.ListReplayJobs(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresReplayJob(replayJobs, approvedReplay.ID, "completed") {
		t.Fatalf("expected completed replay job after fanout, got %+v", replayJobs)
	}
	var originalDeliveryID, newDeliveryID, replayPayloadID, replayPayloadSHA256, configMode string
	if err := store.pool.QueryRow(ctx, `
		SELECT original_delivery_id, new_delivery_id, delivery_payload_id, delivery_payload_sha256, config_mode
		FROM replay_items
		WHERE tenant_id=$1 AND replay_job_id=$2 AND event_id=$3`,
		actor.TenantID, approvedReplay.ID, ingested.EventID,
	).Scan(&originalDeliveryID, &newDeliveryID, &replayPayloadID, &replayPayloadSHA256, &configMode); err != nil {
		t.Fatal(err)
	}
	if originalDeliveryID != originalDelivery.ID || newDeliveryID == "" || replayPayloadID == "" || replayPayloadSHA256 == "" || configMode != app.ReplayConfigOriginal {
		t.Fatalf("replay item did not preserve original decision evidence: original=%s new=%s payload=%s hash=%s mode=%s", originalDeliveryID, newDeliveryID, replayPayloadID, replayPayloadSHA256, configMode)
	}
	var replayDeliveryPayloadID, replayDeliveryState string
	if err := store.pool.QueryRow(ctx, `SELECT delivery_payload_id, state FROM deliveries WHERE tenant_id=$1 AND id=$2 AND replay_job_id=$3`, actor.TenantID, newDeliveryID, approvedReplay.ID).Scan(&replayDeliveryPayloadID, &replayDeliveryState); err != nil {
		t.Fatal(err)
	}
	if replayDeliveryPayloadID == "" || replayDeliveryState != "scheduled" {
		t.Fatalf("replay fanout did not create a scheduled delivery with payload evidence: payload=%s state=%s", replayDeliveryPayloadID, replayDeliveryState)
	}

	disabledPolicy, err := control.DisableReplayApprovalPolicy(ctx, actor, policy.ID, app.StateChangeRequest{Reason: "approval drill complete"})
	if err != nil {
		t.Fatal(err)
	}
	if disabledPolicy.State != domain.StateDisabled {
		t.Fatalf("expected disabled replay approval policy, got %+v", disabledPolicy)
	}
	directReplay, err := control.CreateReplay(ctx, actor, app.ReplayRequest{
		DeliveryID: originalDelivery.ID,
		ReasonCode: app.ReplayReasonOperatorRequested,
		Reason:     "cancel replay drill",
		ConfigMode: app.ReplayConfigCurrent,
		EndpointID: endpoint.ID,
		DryRun:     false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if directReplay.State != "scheduled" || directReplay.ApprovalRequired {
		t.Fatalf("disabled replay approval policy should allow direct scheduling, got %+v", directReplay)
	}
	canceledReplay, err := control.CancelReplayJob(ctx, actor, directReplay.ID, app.StateChangeRequest{Reason: "cancel replay drill"})
	if err != nil {
		t.Fatal(err)
	}
	if canceledReplay.State != "canceled" {
		t.Fatalf("expected canceled replay job, got %+v", canceledReplay)
	}
	outboxItems, err = store.ClaimOutbox(ctx, "it-replay-controls-canceled-outbox", 10)
	if err != nil {
		t.Fatal(err)
	}
	canceledOutbox := findPostgresOutboxItem(t, outboxItems, app.OutboxKindReplayJob, directReplay.ID)
	if err := fanout.ProcessOutbox(ctx, canceledOutbox); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteOutbox(ctx, canceledOutbox.ID); err != nil {
		t.Fatal(err)
	}
	var canceledReplayDeliveries int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM deliveries WHERE tenant_id=$1 AND replay_job_id=$2`, actor.TenantID, directReplay.ID).Scan(&canceledReplayDeliveries); err != nil {
		t.Fatal(err)
	}
	if canceledReplayDeliveries != 0 {
		t.Fatalf("canceled replay job must not create delivery work, got %d deliveries", canceledReplayDeliveries)
	}

	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "replay_approval_policy.upserted", "replay_approval_policy", policy.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "replay.approved", "replay_job", approvedReplay.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "replay.paused", "replay_job", approvedReplay.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "replay.resumed", "replay_job", approvedReplay.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "replay_approval_policy.disabled", "replay_approval_policy", policy.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "replay.canceled", "replay_job", directReplay.ID)
}

func TestPostgresConcurrentDuplicateCapturePreservesEvidence(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	control := app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{"receiver.example.com": {netip.MustParseAddr("93.184.216.34")}}})
	source, _ := createPostgresIntegrationRoute(t, ctx, control, actor, "invoice.concurrent_duplicate")
	providerID := "evt_it_concurrent_duplicate_" + now.Format("150405.000000000")
	body := []byte(`{"id":"` + providerID + `","type":"invoice.concurrent_duplicate","account":"acct_it"}`)
	signature := verifier.TimestampedHeader("v1", now, []byte("whsec_it"), body)

	const attempts = 8
	results := make([]app.IngestResult, attempts)
	errs := make([]error, attempts)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		i := i
		go func() {
			defer wg.Done()
			results[i], errs[i] = app.NewIngestService(store, fixedIntegrationClock{now: now}).Ingest(ctx, app.IngestRequest{
				TenantID:    actor.TenantID,
				SourceID:    source.ID,
				Provider:    "stripe",
				RawBody:     body,
				Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: signature}},
				ContentType: "application/json",
				RemoteIP:    "198.51.100.20",
			})
		}()
	}
	wg.Wait()

	eventID := ""
	uniqueCount := 0
	duplicateCount := 0
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent duplicate capture %d failed: %v", i, err)
		}
		if !results[i].Accepted || results[i].EventID == "" {
			t.Fatalf("concurrent duplicate capture %d was not accepted: %+v", i, results[i])
		}
		if eventID == "" {
			eventID = results[i].EventID
		}
		if results[i].EventID != eventID {
			t.Fatalf("duplicate capture %d linked to %s, want canonical event %s", i, results[i].EventID, eventID)
		}
		switch results[i].DedupeStatus {
		case domain.DedupeUnique:
			uniqueCount++
		case domain.DedupeDuplicateSuppressed:
			duplicateCount++
		default:
			t.Fatalf("unexpected dedupe status for capture %d: %s", i, results[i].DedupeStatus)
		}
	}
	if uniqueCount != 1 || duplicateCount != attempts-1 {
		t.Fatalf("expected one unique and %d duplicates, got unique=%d duplicate=%d", attempts-1, uniqueCount, duplicateCount)
	}

	var eventRows, rawRows, receiptRows, distinctReceiptRawRows, outboxRows int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE tenant_id=$1 AND source_id=$2 AND provider_event_id=$3`, actor.TenantID, source.ID, providerID).Scan(&eventRows); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM raw_payloads WHERE tenant_id=$1 AND event_id=$2`, actor.TenantID, eventID).Scan(&rawRows); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM provider_receipts WHERE tenant_id=$1 AND event_id=$2`, actor.TenantID, eventID).Scan(&receiptRows); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(DISTINCT raw_payload_id) FROM provider_receipts WHERE tenant_id=$1 AND event_id=$2`, actor.TenantID, eventID).Scan(&distinctReceiptRawRows); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND kind=$2 AND resource_id=$3`, actor.TenantID, app.OutboxKindRouteEvent, eventID).Scan(&outboxRows); err != nil {
		t.Fatal(err)
	}
	if eventRows != 1 || rawRows != attempts || receiptRows != attempts || distinctReceiptRawRows != attempts || outboxRows != 1 {
		t.Fatalf("unexpected concurrent duplicate evidence counts: events=%d raw=%d receipts=%d distinct_receipt_raw=%d outbox=%d", eventRows, rawRows, receiptRows, distinctReceiptRawRows, outboxRows)
	}
}

func TestPostgresEvidenceExportIncludesBodyArtifactsAndProofs(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	windowStart := time.Now().UTC().Add(-time.Minute)
	now := time.Now().UTC().Truncate(time.Second)
	control := app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{"receiver.example.com": {netip.MustParseAddr("93.184.216.34")}}})
	source, _ := createPostgresIntegrationRoute(t, ctx, control, actor, "invoice.exported")
	providerID := "evt_it_export_" + now.Format("150405.000000000")
	first := ingestPostgresIntegrationEvent(t, ctx, store, actor, source.ID, "invoice.exported", providerID, now)
	duplicate := ingestPostgresIntegrationEvent(t, ctx, store, actor, source.ID, "invoice.exported", providerID, now.Add(time.Second))
	if duplicate.EventID != first.EventID || duplicate.DedupeStatus != domain.DedupeDuplicateSuppressed {
		t.Fatalf("expected duplicate evidence linked to %s, got %+v", first.EventID, duplicate)
	}
	fanout := app.NewDeliveryFanoutService(store, app.SystemClock{})
	if created, err := fanout.CreateDeliveriesForEvent(ctx, actor.TenantID, first.EventID, app.DeliveryFanoutOptions{}); err != nil {
		t.Fatal(err)
	} else if created == 0 {
		t.Fatal("expected route fanout to create a delivery payload")
	}

	connection, err := store.CreateProviderConnection(ctx, actor.TenantID, actor.ID, app.CreateProviderConnectionRequest{
		Name:           "export evidence connection",
		Provider:       "stripe",
		CredentialType: "api_key",
		Credential:     "sk_test_placeholder",
		Config:         map[string]string{"source_id": source.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	reconciliationJob, err := store.CreateReconciliationJob(ctx, actor.TenantID, actor.ID, app.ReconciliationJobRequest{
		ConnectionID:   connection.ID,
		DryRun:         true,
		CaptureMissing: true,
		WindowStart:    windowStart,
		WindowEnd:      now.Add(time.Minute),
		Reason:         "export evidence regression",
	})
	if err != nil {
		t.Fatal(err)
	}
	providerEvidenceID, err := store.insertProviderAPIEvidence(ctx, actor.TenantID, reconciliationJob.ID, "", connection.ID, connection.Provider, reconcile.Evidence{
		Method:     "GET",
		URL:        "https://api.stripe.com/v1/events/" + providerID,
		StatusCode: 200,
		Body:       []byte(`{"id":"` + providerID + `","object":"event"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.insertReconciliationItem(ctx, reconciliationItemInput{
		tenantID: actor.TenantID, jobID: reconciliationJob.ID, provider: connection.Provider, objectID: providerID, objectType: "event",
		outcome: domain.ReconciliationOutcomeMatched, localEventID: first.EventID, evidenceID: providerEvidenceID, metadata: []byte(`{"test":"export"}`),
	}); err != nil {
		t.Fatal(err)
	}

	limitedActor := authz.Actor{ID: "usr_export_limited", TenantID: actor.TenantID, Role: authz.RoleAdmin, Scopes: []string{"audit:read"}}
	if _, err := control.CreateAuditExport(ctx, limitedActor, app.CreateAuditExportRequest{IncludeRawPayloads: true, Reason: "permission regression"}); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("expected raw-inclusive export to require events:raw, got %v", err)
	}
	if _, err := control.CreateAuditExport(ctx, limitedActor, app.CreateAuditExportRequest{IncludePayloadBodies: true, Reason: "permission regression"}); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("expected payload-inclusive export to require events:raw, got %v", err)
	}

	export, err := control.CreateAuditExport(ctx, actor, app.CreateAuditExportRequest{
		From:                 windowStart,
		To:                   now.Add(time.Minute),
		IncludeRawPayloads:   true,
		IncludeTimelines:     true,
		IncludePayloadBodies: true,
		Reason:               "body-inclusive export regression",
	})
	if err != nil {
		t.Fatal(err)
	}
	download, err := control.DownloadAuditExport(ctx, actor, export.ID)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := evidence.VerifyTarGzipBundle(download.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Valid || verification.CheckedChainEntries == 0 {
		t.Fatalf("expected valid bundle with audit chain proof, got %+v", verification)
	}
	files := readTestTarGzipFiles(t, download.Body)
	rawEntries := decodeTestJSONLines(t, files["raw_payloads.jsonl"])
	rawBodies, receiptRows := 0, 0
	for _, entry := range rawEntries {
		if entry["event_id"] != first.EventID {
			continue
		}
		if body, ok := entry["body_base64"].(string); ok && body != "" {
			rawBodies++
		}
		if receiptIDs, ok := entry["receipt_ids"].([]any); ok && len(receiptIDs) == 1 {
			receiptRows++
		}
	}
	if rawBodies != 2 || receiptRows != 2 {
		t.Fatalf("expected two duplicate raw bodies and receipt links, bodies=%d receipts=%d entries=%+v", rawBodies, receiptRows, rawEntries)
	}

	payloadEntries := decodeTestJSONLines(t, files["payload_evidence.jsonl"])
	var normalizedWithBody, deliveryWithBody bool
	for _, entry := range payloadEntries {
		switch entry["resource_type"] {
		case "normalized_envelope":
			_, hasEnvelope := entry["envelope"]
			_, hasData := entry["data"]
			normalizedWithBody = entry["event_id"] == first.EventID && entry["body_included"] == true && hasEnvelope && hasData
		case "delivery_payload":
			body, _ := entry["body_base64"].(string)
			deliveryWithBody = entry["event_id"] == first.EventID && entry["body_included"] == true && body != ""
		}
	}
	if !normalizedWithBody || !deliveryWithBody {
		t.Fatalf("expected normalized and delivery payload bodies in export, normalized=%v delivery=%v entries=%+v", normalizedWithBody, deliveryWithBody, payloadEntries)
	}

	reconciliationEntries := decodeTestJSONLines(t, files["reconciliation_evidence.jsonl"])
	providerBodyIncluded := false
	for _, entry := range reconciliationEntries {
		if entry["id"] != reconciliationJob.ID {
			continue
		}
		for _, rawEvidence := range entry["provider_api_evidence"].([]any) {
			apiEvidence := rawEvidence.(map[string]any)
			body, _ := apiEvidence["response_body_base64"].(string)
			if apiEvidence["id"] == providerEvidenceID && apiEvidence["body_included"] == true && body != "" {
				providerBodyIncluded = true
			}
		}
	}
	if !providerBodyIncluded {
		t.Fatalf("expected provider API evidence body in export, entries=%+v", reconciliationEntries)
	}

	if _, err := store.pool.Exec(ctx, `UPDATE raw_payloads SET body='', storage_status='deleted', storage_deleted_at=now() WHERE tenant_id=$1 AND event_id=$2`, actor.TenantID, first.EventID); err != nil {
		t.Fatal(err)
	}
	if _, err := control.GetRawPayload(ctx, actor, first.EventID, "verify retention tombstone"); !errors.Is(err, app.ErrGone) {
		t.Fatalf("expected retained raw body read to return gone after deletion, got %v", err)
	}
}

func TestPostgresAuditChainBackfillIsBoundedAndIdempotent(t *testing.T) {
	ctx, store, _ := openPostgresIntegrationStore(t)
	defer store.Close()
	for _, prefix := range []string{"ten_it_backfill_%", "ten_it_migration_%"} {
		if _, err := store.pool.Exec(ctx, `DELETE FROM audit_chain_entries WHERE tenant_id LIKE $1`, prefix); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `DELETE FROM audit_chain_heads WHERE tenant_id LIKE $1`, prefix); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `DELETE FROM audit_events WHERE tenant_id LIKE $1`, prefix); err != nil {
			t.Fatal(err)
		}
	}

	suffix := time.Now().UTC().Format("150405.000000000")
	tenantID := "ten_it_backfill_" + suffix
	base := time.Date(2026, 5, 26, 18, 0, 0, 0, time.UTC)
	if _, err := store.pool.Exec(ctx, `INSERT INTO tenants(id, name) VALUES($1, 'backfill integration') ON CONFLICT (id) DO NOTHING`, tenantID); err != nil {
		t.Fatal(err)
	}
	events := []struct {
		id         string
		occurredAt time.Time
	}{
		{id: "aud_it_backfill_b_" + suffix, occurredAt: base},
		{id: "aud_it_backfill_a_" + suffix, occurredAt: base},
		{id: "aud_it_backfill_c_" + suffix, occurredAt: base.Add(time.Second)},
	}
	for _, event := range events {
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason, occurred_at)
			VALUES($1,$2,'usr_it','integration.backfill','test',$1,'backfill integration',$3)`,
			event.id, tenantID, event.occurredAt); err != nil {
			t.Fatal(err)
		}
	}

	first, err := store.BackfillAuditChain(ctx, "it-backfill", 2)
	if err != nil {
		t.Fatal(err)
	}
	if !first.LeaseAcquired || first.EventsBackfilled != 2 || !first.More {
		t.Fatalf("expected first bounded backfill to claim two events and report more work, got %+v", first)
	}
	second, err := store.BackfillAuditChain(ctx, "it-backfill", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !second.LeaseAcquired || second.EventsBackfilled != 1 || second.More {
		t.Fatalf("expected second backfill to finish remaining event, got %+v", second)
	}
	third, err := store.BackfillAuditChain(ctx, "it-backfill", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !third.LeaseAcquired || third.EventsBackfilled != 0 || third.More {
		t.Fatalf("expected idempotent empty backfill, got %+v", third)
	}

	rows, err := store.pool.Query(ctx, `
		SELECT audit_event_id, sequence, source
		FROM audit_chain_entries
		WHERE tenant_id=$1
		ORDER BY sequence ASC`, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var orderedIDs []string
	var sequences []int64
	var sources []string
	for rows.Next() {
		var id, source string
		var sequence int64
		if err := rows.Scan(&id, &sequence, &source); err != nil {
			t.Fatal(err)
		}
		orderedIDs = append(orderedIDs, id)
		sequences = append(sequences, sequence)
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	expectedOrder := []string{events[1].id, events[0].id, events[2].id}
	if strings.Join(orderedIDs, ",") != strings.Join(expectedOrder, ",") {
		t.Fatalf("expected deterministic occurred_at/id order %v, got %v", expectedOrder, orderedIDs)
	}
	if strings.Join(sources, ",") != "backfill,backfill,backfill" {
		t.Fatalf("expected backfill chain entry sources, got %v", sources)
	}
	if len(sequences) != 3 || sequences[0] != 1 || sequences[1] != 2 || sequences[2] != 3 {
		t.Fatalf("expected sequential chain entries, got %v", sequences)
	}
}

func TestPostgresControlResourcesTenantIsolationAndEvidence(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	suffix := time.Now().UTC().Format("150405.000000000")
	other := authz.Actor{ID: "usr_it_other_" + suffix, TenantID: "ten_it_other_" + suffix, Role: authz.RoleOwner, Scopes: []string{"*"}}
	if _, err := store.CreateAPIKey(ctx, app.APIKeyCreateInput{
		Key: domain.APIKey{
			TenantID: other.TenantID,
			UserID:   other.ID,
			Name:     "integration other owner",
			Prefix:   "it-other",
			Last4:    "test",
			Hash:     app.HashToken("integration-other-" + suffix),
			Scopes:   []string{"*"},
			State:    domain.StateActive,
		},
		Role:    authz.RoleOwner,
		ActorID: other.ID,
	}); err != nil {
		t.Fatal(err)
	}
	control := app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{
		"receiver.example.com": {netip.MustParseAddr("93.184.216.34")},
		"signals.example.com":  {netip.MustParseAddr("93.184.216.34")},
	}})

	source, err := control.CreateSource(ctx, actor, app.CreateSourceRequest{Name: "tenant source", Provider: "stripe", Adapter: "stripe", VerificationSecret: "whsec_it"})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, _, err := control.CreateEndpoint(ctx, actor, app.CreateEndpointRequest{Name: "tenant endpoint", URL: "https://receiver.example.com/webhook"})
	if err != nil {
		t.Fatal(err)
	}
	retryPolicy, err := control.CreateRetryPolicy(ctx, actor, app.CreateRetryPolicyRequest{Name: "tenant retry", MaxAttempts: 3, MaxDurationSeconds: 3600, InitialDelaySeconds: 1, MaxDelaySeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	route, err := control.CreateRoute(ctx, actor, app.CreateRouteRequest{SourceID: source.ID, Name: "tenant route", Priority: 10, EventTypes: []string{"invoice.created"}, EndpointID: endpoint.ID, RetryPolicyID: retryPolicy.ID, State: domain.StateActive})
	if err != nil {
		t.Fatal(err)
	}
	subscription, err := control.CreateSubscription(ctx, actor, app.CreateSubscriptionRequest{EndpointID: endpoint.ID, EventTypes: []string{"invoice.created"}, PayloadFormat: "canonical_json"})
	if err != nil {
		t.Fatal(err)
	}
	channel, _, err := control.CreateNotificationChannel(ctx, actor, app.CreateNotificationChannelRequest{Name: "tenant notification", URL: "https://signals.example.com/notify", SigningSecret: "notify-secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	alert, err := control.CreateAlertRule(ctx, actor, app.CreateAlertRuleRequest{Name: "tenant alert", RuleType: domain.AlertRuleDeadLetterOpen, Threshold: 1, ChannelIDs: []string{channel.ID}})
	if err != nil {
		t.Fatal(err)
	}
	sink, _, err := control.CreateSIEMSink(ctx, actor, app.CreateSIEMSinkRequest{Name: "tenant siem", URL: "https://signals.example.com/siem", SigningSecret: "siem-secret-value"})
	if err != nil {
		t.Fatal(err)
	}

	sourceName := "tenant source updated"
	if _, err := control.UpdateSource(ctx, actor, source.ID, app.UpdateSourceRequest{Name: &sourceName, Reason: "integration update"}); err != nil {
		t.Fatal(err)
	}
	endpointName := "tenant endpoint updated"
	if _, _, err := control.UpdateEndpoint(ctx, actor, endpoint.ID, app.UpdateEndpointRequest{Name: &endpointName, Reason: "integration update"}); err != nil {
		t.Fatal(err)
	}
	routeName := "tenant route updated"
	if _, err := control.UpdateRoute(ctx, actor, route.ID, app.UpdateRouteRequest{Name: &routeName, Reason: "integration update"}); err != nil {
		t.Fatal(err)
	}
	subscriptionFormat := "canonical_json"
	if _, err := control.UpdateSubscription(ctx, actor, subscription.ID, app.UpdateSubscriptionRequest{PayloadFormat: &subscriptionFormat, Reason: "integration update"}); err != nil {
		t.Fatal(err)
	}
	retryName := "tenant retry updated"
	updatedRetryPolicy, err := control.UpdateRetryPolicy(ctx, actor, retryPolicy.ID, app.UpdateRetryPolicyRequest{Name: &retryName, Reason: "integration update"})
	if err != nil {
		t.Fatal(err)
	}
	retryPolicy = updatedRetryPolicy
	alertName := "tenant alert updated"
	if _, err := control.UpdateAlertRule(ctx, actor, alert.ID, app.UpdateAlertRuleRequest{Name: &alertName, Reason: "integration update"}); err != nil {
		t.Fatal(err)
	}
	channelName := "tenant notification updated"
	if _, _, err := control.UpdateNotificationChannel(ctx, actor, channel.ID, app.UpdateNotificationChannelRequest{Name: &channelName, Reason: "integration update"}); err != nil {
		t.Fatal(err)
	}
	sinkName := "tenant siem updated"
	if _, _, err := control.UpdateSIEMSink(ctx, actor, sink.ID, app.UpdateSIEMSinkRequest{Name: &sinkName, Reason: "integration update"}); err != nil {
		t.Fatal(err)
	}

	_, err = control.GetSource(ctx, other, source.ID)
	assertPostgresNotFound(t, err)
	_, err = control.GetEndpoint(ctx, other, endpoint.ID)
	assertPostgresNotFound(t, err)
	_, err = control.GetRoute(ctx, other, route.ID)
	assertPostgresNotFound(t, err)
	_, err = control.GetSubscription(ctx, other, subscription.ID)
	assertPostgresNotFound(t, err)
	_, err = control.GetRetryPolicy(ctx, other, retryPolicy.ID)
	assertPostgresNotFound(t, err)
	_, err = control.GetAlertRule(ctx, other, alert.ID)
	assertPostgresNotFound(t, err)
	_, err = control.GetNotificationChannel(ctx, other, channel.ID)
	assertPostgresNotFound(t, err)
	_, err = control.GetSIEMSink(ctx, other, sink.ID)
	assertPostgresNotFound(t, err)

	for _, item := range []struct {
		resourceType string
		resourceID   string
	}{
		{domain.ConfigResourceSource, source.ID},
		{domain.ConfigResourceEndpoint, endpoint.ID},
		{domain.ConfigResourceRoute, route.ID},
		{domain.ConfigResourceSubscription, subscription.ID},
		{domain.ConfigResourceRetryPolicy, retryPolicy.ID},
	} {
		assertPostgresConfigVersion(t, ctx, store, actor.TenantID, item.resourceType, item.resourceID)
	}
	for _, item := range []struct {
		action     string
		resource   string
		resourceID string
	}{
		{"source.updated", "source", source.ID},
		{"endpoint.updated", "endpoint", endpoint.ID},
		{"route.updated", "route", route.ID},
		{"subscription.updated", "subscription", subscription.ID},
		{"retry_policy.updated", "retry_policy", retryPolicy.ID},
		{"alert_rule.updated", "alert_rule", alert.ID},
		{"notification_channel.updated", "notification_channel", channel.ID},
		{"siem_sink.updated", "siem_sink", sink.ID},
	} {
		assertPostgresAuditEvent(t, ctx, store, actor.TenantID, item.action, item.resource, item.resourceID)
	}

	sources, err := control.ListSources(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresSource(sources, source.ID, domain.StateActive) {
		t.Fatalf("expected source in tenant list, got %+v", sources)
	}
	if found, err := store.FindSourceByProviderPath(ctx, source.Provider, source.ID); err != nil || found.ID != source.ID {
		t.Fatalf("expected provider path source lookup to find %s, found=%+v err=%v", source.ID, found, err)
	}
	endpoints, err := control.ListEndpoints(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresEndpoint(endpoints, endpoint.ID, domain.StateActive) {
		t.Fatalf("expected endpoint in tenant list, got %+v", endpoints)
	}
	testDelivery, err := control.TestEndpoint(ctx, actor, endpoint.ID, app.TestEndpointRequest{Reason: "integration endpoint test"})
	if err != nil {
		t.Fatal(err)
	}
	if testDelivery.ID == "" || testDelivery.EndpointID != endpoint.ID || testDelivery.State != "scheduled" {
		t.Fatalf("unexpected endpoint test delivery: %+v", testDelivery)
	}
	subscriptions, err := control.ListSubscriptions(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresSubscription(subscriptions, subscription.ID, domain.StateActive) {
		t.Fatalf("expected subscription in tenant list, got %+v", subscriptions)
	}
	routes, err := control.ListRoutes(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresRoute(routes, route.ID, domain.StateActive) {
		t.Fatalf("expected route in tenant list, got %+v", routes)
	}
	activatedRoute, err := control.ActivateRoute(ctx, actor, route.ID, "integration activation")
	if err != nil {
		t.Fatal(err)
	}
	if activatedRoute.State != domain.StateActive {
		t.Fatalf("expected active route, got %+v", activatedRoute)
	}
	routeVersions, err := control.ListRouteVersions(ctx, actor, route.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(routeVersions) == 0 {
		t.Fatal("expected route versions")
	}
	retryPolicies, err := control.ListRetryPolicies(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresRetryPolicy(retryPolicies, retryPolicy.ID, domain.StateActive) {
		t.Fatalf("expected retry policy in tenant list, got %+v", retryPolicies)
	}
	alerts, err := control.ListAlertRules(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresAlertRule(alerts, alert.ID, domain.StateActive) {
		t.Fatalf("expected alert rule in tenant list, got %+v", alerts)
	}
	channels, err := control.ListNotificationChannels(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresNotificationChannel(channels, channel.ID, domain.StateActive) {
		t.Fatalf("expected notification channel in tenant list, got %+v", channels)
	}
	notificationDelivery, err := control.TestNotificationChannel(ctx, actor, channel.ID, app.StateChangeRequest{Reason: "integration notification test"})
	if err != nil {
		t.Fatal(err)
	}
	if notificationDelivery.ID == "" || notificationDelivery.ChannelID != channel.ID {
		t.Fatalf("unexpected notification test delivery: %+v", notificationDelivery)
	}
	sinks, err := control.ListSIEMSinks(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresSIEMSink(sinks, sink.ID, domain.StateActive) {
		t.Fatalf("expected SIEM sink in tenant list, got %+v", sinks)
	}
	siemDelivery, err := control.TestSIEMSink(ctx, actor, sink.ID, app.StateChangeRequest{Reason: "integration siem test"})
	if err != nil {
		t.Fatal(err)
	}
	if siemDelivery.ID == "" || siemDelivery.SinkID != sink.ID {
		t.Fatalf("unexpected SIEM test delivery: %+v", siemDelivery)
	}
	if _, err := control.ListEndpointHealth(ctx, actor, 20); err != nil {
		t.Fatal(err)
	}
	if _, err := control.ListWorkers(ctx, actor, 20); err != nil {
		t.Fatal(err)
	}
	if _, err := control.ListQueues(ctx, actor); err != nil {
		t.Fatal(err)
	}

	if deleted, err := control.DeleteSubscription(ctx, actor, subscription.ID, app.StateChangeRequest{Reason: "integration disable"}); err != nil || deleted.State != domain.StateDisabled {
		t.Fatalf("expected disabled subscription, got %+v err=%v", deleted, err)
	}
	if deleted, err := control.DeleteRoute(ctx, actor, route.ID, app.StateChangeRequest{Reason: "integration inactivate"}); err != nil || deleted.State != domain.StateInactive {
		t.Fatalf("expected inactive route, got %+v err=%v", deleted, err)
	}
	if deleted, err := control.DeleteRetryPolicy(ctx, actor, retryPolicy.ID, app.StateChangeRequest{Reason: "integration disable"}); err != nil || deleted.State != domain.StateDisabled {
		t.Fatalf("expected disabled retry policy, got %+v err=%v", deleted, err)
	}
	if deleted, err := control.DeleteAlertRule(ctx, actor, alert.ID, app.StateChangeRequest{Reason: "integration disable"}); err != nil || deleted.State != domain.StateDisabled {
		t.Fatalf("expected disabled alert rule, got %+v err=%v", deleted, err)
	}
	if deleted, err := control.DeleteNotificationChannel(ctx, actor, channel.ID, app.StateChangeRequest{Reason: "integration disable"}); err != nil || deleted.State != domain.StateDisabled {
		t.Fatalf("expected disabled notification channel, got %+v err=%v", deleted, err)
	}
	if deleted, err := control.DeleteSIEMSink(ctx, actor, sink.ID, app.StateChangeRequest{Reason: "integration disable"}); err != nil || deleted.State != domain.StateDisabled {
		t.Fatalf("expected disabled SIEM sink, got %+v err=%v", deleted, err)
	}
	if deleted, err := control.DeleteEndpoint(ctx, actor, endpoint.ID, app.StateChangeRequest{Reason: "integration disable"}); err != nil || deleted.State != domain.StateDisabled {
		t.Fatalf("expected disabled endpoint, got %+v err=%v", deleted, err)
	}
	if deleted, err := control.DeleteSource(ctx, actor, source.ID, app.StateChangeRequest{Reason: "integration disable"}); err != nil || deleted.State != domain.StateDisabled {
		t.Fatalf("expected disabled source, got %+v err=%v", deleted, err)
	}
}

func TestPostgresSignalDeliveryAttemptLifecycle(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	if _, err := store.pool.Exec(ctx, `UPDATE notification_deliveries SET state='succeeded', worker_id='' WHERE tenant_id LIKE 'ten_it_%' AND state IN ('scheduled','in_progress')`); err != nil {
		t.Fatalf("clear prior integration notification work: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE siem_deliveries SET state='succeeded', worker_id='' WHERE tenant_id LIKE 'ten_it_%' AND state IN ('scheduled','in_progress')`); err != nil {
		t.Fatalf("clear prior integration SIEM work: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE notification_channels SET state='disabled' WHERE tenant_id LIKE 'ten_it_%' AND state='active'`); err != nil {
		t.Fatalf("disable prior integration notification channels: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE siem_sinks SET state='disabled' WHERE tenant_id LIKE 'ten_it_%' AND state='active'`); err != nil {
		t.Fatalf("disable prior integration SIEM sinks: %v", err)
	}

	control := app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{
		"signals.example.com": {netip.MustParseAddr("93.184.216.34")},
	}})
	channel, _, err := control.CreateNotificationChannel(ctx, actor, app.CreateNotificationChannelRequest{Name: "signal lifecycle notification", URL: "https://signals.example.com/notify", SigningSecret: "notify-secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	notificationDelivery, err := control.TestNotificationChannel(ctx, actor, channel.ID, app.StateChangeRequest{Reason: "integration notification lifecycle"})
	if err != nil {
		t.Fatal(err)
	}
	notificationItems, err := store.ClaimNotificationDeliveries(ctx, "it-notification-worker", 10)
	if err != nil {
		t.Fatal(err)
	}
	notificationItem := findPostgresSignalDeliveryItem(t, notificationItems, notificationDelivery.ID)
	if notificationItem.URL != channel.URL || string(notificationItem.Secret) != "notify-secret-value" || !bytes.Contains(notificationItem.Body, []byte(`"notification_channel.test"`)) {
		t.Fatalf("claimed notification item mismatch: id=%s tenant=%s url=%q secret_len=%d body=%s", notificationItem.ID, notificationItem.TenantID, notificationItem.URL, len(notificationItem.Secret), string(notificationItem.Body))
	}
	longResponse := bytes.Repeat([]byte("x"), 20<<10)
	if err := store.RecordNotificationDeliveryAttempt(ctx, notificationItem, worker.SignalDeliveryResult{StatusCode: 503, FailureClass: "upstream_5xx", ResponseBody: longResponse, ResponseTruncated: true}, errors.New("network unavailable")); err != nil {
		t.Fatal(err)
	}
	if retried, err := control.RetryNotificationDelivery(ctx, actor, notificationDelivery.ID, app.StateChangeRequest{Reason: "integration notification retry"}); err != nil || retried.State != domain.SignalDeliveryScheduled {
		t.Fatalf("expected scheduled notification retry, got %+v err=%v", retried, err)
	}
	notificationItems, err = store.ClaimNotificationDeliveries(ctx, "it-notification-worker-success", 10)
	if err != nil {
		t.Fatal(err)
	}
	notificationItem = findPostgresSignalDeliveryItem(t, notificationItems, notificationDelivery.ID)
	if err := store.RecordNotificationDeliveryAttempt(ctx, notificationItem, worker.SignalDeliveryResult{StatusCode: 202, FailureClass: "success", ResponseBody: []byte("accepted")}, nil); err != nil {
		t.Fatal(err)
	}
	notificationAttempts, err := control.ListNotificationDeliveryAttempts(ctx, actor, notificationDelivery.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(notificationAttempts) != 2 {
		t.Fatalf("expected failed and succeeded notification attempts, got %+v", notificationAttempts)
	}
	if notificationAttempts[0].StatusCode != 202 || notificationAttempts[0].FailureClass != "success" {
		t.Fatalf("latest notification attempt did not record success: %+v", notificationAttempts[0])
	}
	if notificationAttempts[1].StatusCode != 503 || !notificationAttempts[1].ResponseTruncated || len(notificationAttempts[1].ResponseBody) != 16<<10 {
		t.Fatalf("failed notification attempt did not retain truncated evidence: %+v", notificationAttempts[1])
	}
	notificationDeliveries, err := control.ListNotificationDeliveries(ctx, actor, domain.SignalDeliverySucceeded, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresNotificationDelivery(notificationDeliveries, notificationDelivery.ID, domain.SignalDeliverySucceeded) {
		t.Fatalf("expected succeeded notification delivery in tenant list, got %+v", notificationDeliveries)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "notification_delivery.retry_requested", "notification_delivery", notificationDelivery.ID)

	sink, _, err := control.CreateSIEMSink(ctx, actor, app.CreateSIEMSinkRequest{Name: "signal lifecycle siem", URL: "https://signals.example.com/siem", SigningSecret: "siem-secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnqueueSIEMDeliveries(ctx, "it-siem-enqueue", 10); err != nil {
		t.Fatal(err)
	}
	siemItems, err := store.ClaimSIEMDeliveries(ctx, "it-siem-worker", 10)
	if err != nil {
		t.Fatal(err)
	}
	siemItem := findPostgresSignalDeliveryForTenant(t, siemItems, actor.TenantID)
	if siemItem.URL != sink.URL || string(siemItem.Secret) != "siem-secret-value" || !bytes.Contains(siemItem.Body, []byte(`"tenant_id":"`+actor.TenantID+`"`)) {
		t.Fatalf("claimed SIEM item mismatch: id=%s tenant=%s url=%q secret_len=%d body=%s", siemItem.ID, siemItem.TenantID, siemItem.URL, len(siemItem.Secret), string(siemItem.Body))
	}
	if err := store.RecordSIEMDeliveryAttempt(ctx, siemItem, worker.SignalDeliveryResult{StatusCode: 500, FailureClass: "siem_5xx", ResponseBody: []byte("temporarily failed")}, errors.New("temporary SIEM outage")); err != nil {
		t.Fatal(err)
	}
	if retried, err := control.RetrySIEMDelivery(ctx, actor, siemItem.ID, app.StateChangeRequest{Reason: "integration siem retry"}); err != nil || retried.State != domain.SignalDeliveryScheduled {
		t.Fatalf("expected scheduled SIEM retry, got %+v err=%v", retried, err)
	}
	siemItems, err = store.ClaimSIEMDeliveries(ctx, "it-siem-worker-success", 10)
	if err != nil {
		t.Fatal(err)
	}
	siemItem = findPostgresSignalDeliveryItem(t, siemItems, siemItem.ID)
	if err := store.RecordSIEMDeliveryAttempt(ctx, siemItem, worker.SignalDeliveryResult{StatusCode: 204, FailureClass: "success", ResponseBody: []byte("ok")}, nil); err != nil {
		t.Fatal(err)
	}
	siemAttempts, err := control.ListSIEMDeliveryAttempts(ctx, actor, siemItem.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(siemAttempts) != 2 || siemAttempts[0].StatusCode != 204 || siemAttempts[1].StatusCode != 500 {
		t.Fatalf("expected failed and succeeded SIEM attempts, got %+v", siemAttempts)
	}
	siemDeliveries, err := control.ListSIEMDeliveries(ctx, actor, domain.SignalDeliverySucceeded, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresSIEMDelivery(siemDeliveries, siemItem.ID, domain.SignalDeliverySucceeded) {
		t.Fatalf("expected succeeded SIEM delivery in tenant list, got %+v", siemDeliveries)
	}
	refreshedSink, err := control.GetSIEMSink(ctx, actor, sink.ID)
	if err != nil {
		t.Fatal(err)
	}
	if refreshedSink.CursorSequence == 0 {
		t.Fatalf("SIEM cursor did not advance after successful delivery: %+v", refreshedSink)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "siem_delivery.retry_requested", "siem_delivery", siemItem.ID)
}

func TestPostgresMetricsRollupsAndAlertFiringLifecycle(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	if _, err := store.pool.Exec(ctx, `UPDATE alert_rules SET state='disabled' WHERE tenant_id LIKE 'ten_it_%' AND state='active'`); err != nil {
		t.Fatalf("disable prior integration alert rules: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE notification_channels SET state='disabled' WHERE tenant_id LIKE 'ten_it_%' AND state='active'`); err != nil {
		t.Fatalf("disable prior integration notification channels: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE notification_deliveries SET state='succeeded', worker_id='' WHERE tenant_id LIKE 'ten_it_%' AND state IN ('scheduled','in_progress')`); err != nil {
		t.Fatalf("clear prior integration notification work: %v", err)
	}

	control := app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{
		"signals.example.com": {netip.MustParseAddr("93.184.216.34")},
	}})
	if err := store.RefreshMetricsRollups(ctx, "it-metrics-worker", 1000); err != nil {
		t.Fatal(err)
	}
	eventRollups, err := control.ListMetricRollups(ctx, actor, "events.total", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresMetricRollup(eventRollups, actor.TenantID, "events.total") {
		t.Fatalf("expected refreshed events.total rollup for tenant, got %+v", eventRollups)
	}

	channel, _, err := control.CreateNotificationChannel(ctx, actor, app.CreateNotificationChannelRequest{Name: "metrics alert notification", URL: "https://signals.example.com/notify", SigningSecret: "notify-secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	rule, err := control.CreateAlertRule(ctx, actor, app.CreateAlertRuleRequest{
		Name:          "dead letter metric threshold",
		RuleType:      domain.AlertRuleDeadLetterOpen,
		MetricName:    "dead_letter.open",
		Threshold:     1,
		Comparator:    ">=",
		WindowSeconds: 300,
		ChannelIDs:    []string{channel.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	bucketStart := time.Now().UTC().Truncate(time.Minute)
	thresholdRollup := domain.MetricRollup{
		ID:             mustID("mru"),
		TenantID:       actor.TenantID,
		MetricName:     "dead_letter.open",
		BucketStart:    bucketStart,
		BucketSeconds:  60,
		Dimensions:     map[string]string{},
		DimensionsHash: domain.MetricDimensionsHash(map[string]string{}),
		Value:          3,
		Source:         "integration-test",
	}
	if err := store.upsertMetricRollup(ctx, thresholdRollup); err != nil {
		t.Fatal(err)
	}
	deadLetterRollups, err := control.ListMetricRollups(ctx, actor, "dead_letter.open", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresMetricRollupValue(deadLetterRollups, actor.TenantID, "dead_letter.open", 3) {
		t.Fatalf("expected threshold rollup value in tenant list, got %+v", deadLetterRollups)
	}
	if err := store.EvaluateAlertRules(ctx, "it-alert-evaluator", 1000); err != nil {
		t.Fatal(err)
	}
	openFirings, err := control.ListAlertFirings(ctx, actor, domain.AlertFiringOpen, 10)
	if err != nil {
		t.Fatal(err)
	}
	firing := findPostgresAlertFiringForRule(t, openFirings, rule.ID)
	if firing.ObservedValue < 3 || firing.Threshold != 1 {
		t.Fatalf("alert firing did not preserve metric evidence: %+v", firing)
	}
	fetched, err := control.GetAlertFiring(ctx, actor, firing.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fetched.ID != firing.ID || fetched.State != domain.AlertFiringOpen {
		t.Fatalf("alert firing lookup mismatch: %+v", fetched)
	}
	acked, err := control.AcknowledgeAlertFiring(ctx, actor, firing.ID, app.StateChangeRequest{Reason: "integration alert acknowledged"})
	if err != nil {
		t.Fatal(err)
	}
	if acked.State != domain.AlertFiringAcknowledged || acked.AcknowledgedBy != actor.ID || acked.AcknowledgedAt.IsZero() {
		t.Fatalf("alert acknowledgment did not persist actor evidence: %+v", acked)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "alert_firing.acknowledged", "alert_firing", firing.ID)

	thresholdRollup.Value = 0
	if err := store.upsertMetricRollup(ctx, thresholdRollup); err != nil {
		t.Fatal(err)
	}
	if err := store.EvaluateAlertRules(ctx, "it-alert-resolver", 1000); err != nil {
		t.Fatal(err)
	}
	resolved, err := control.GetAlertFiring(ctx, actor, firing.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.State != domain.AlertFiringResolved || resolved.ResolvedAt.IsZero() || resolved.ObservedValue != 0 {
		t.Fatalf("alert firing did not resolve after metric recovery: %+v", resolved)
	}
	notificationDeliveries, err := control.ListNotificationDeliveries(ctx, actor, domain.SignalDeliveryScheduled, 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, transition := range []string{domain.AlertFiringOpen, domain.AlertFiringAcknowledged, domain.AlertFiringResolved} {
		if !containsPostgresNotificationTransition(notificationDeliveries, firing.ID, transition) {
			t.Fatalf("expected %s notification delivery for firing %s, got %+v", transition, firing.ID, notificationDeliveries)
		}
	}
}

func TestPostgresAuditChainAndRetentionEvidenceLifecycle(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	control := app.NewControlService(store, ssrf.Validator{})
	auditEvents, err := control.ListAuditEvents(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresAuditAction(auditEvents, "api_key.created") {
		t.Fatalf("expected API key creation audit evidence, got %+v", auditEvents)
	}
	head, err := control.GetAuditChainHead(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	if head.Sequence == 0 && head.UnchainedEvents > 0 {
		if _, err := store.BackfillAuditChain(ctx, "it-audit-backfill", 100); err != nil {
			t.Fatal(err)
		}
		head, err = control.GetAuditChainHead(ctx, actor)
		if err != nil {
			t.Fatal(err)
		}
	}
	if head.Sequence == 0 || head.ChainHash == "" {
		t.Fatalf("expected chained audit evidence for tenant, got %+v", head)
	}
	verification, err := control.VerifyAuditChain(ctx, actor, app.AuditChainVerifyRequest{FromSequence: 1, ToSequence: head.Sequence})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Valid || verification.CheckedEntries == 0 || verification.EndChainHash != head.ChainHash {
		t.Fatalf("audit chain verification mismatch: head=%+v verification=%+v", head, verification)
	}
	anchor, err := control.CreateAuditChainAnchor(ctx, actor, app.AuditChainAnchorRequest{FromSequence: 1, ToSequence: head.Sequence, Reason: "integration audit checkpoint"})
	if err != nil {
		t.Fatal(err)
	}
	if anchor.TenantID != actor.TenantID || anchor.ToSequence != head.Sequence || anchor.ManifestSHA256 == "" || anchor.CreatedBy != actor.ID {
		t.Fatalf("audit chain anchor did not preserve checkpoint evidence: %+v", anchor)
	}
	anchors, err := control.ListAuditChainAnchors(ctx, actor, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresAuditChainAnchor(anchors, anchor.ID, head.Sequence) {
		t.Fatalf("expected audit chain anchor in tenant list, got %+v", anchors)
	}
	fetchedAnchor, err := control.GetAuditChainAnchor(ctx, actor, anchor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fetchedAnchor.ID != anchor.ID || fetchedAnchor.ChainHash != anchor.ChainHash {
		t.Fatalf("audit chain anchor lookup mismatch: got %+v want %+v", fetchedAnchor, anchor)
	}
	refreshedHead, err := control.GetAuditChainHead(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	if refreshedHead.LastAnchorID != anchor.ID || refreshedHead.LastAnchorSequence != head.Sequence {
		t.Fatalf("audit chain head did not expose latest anchor: %+v", refreshedHead)
	}

	policy, err := control.CreateRetentionPolicy(ctx, actor, app.CreateRetentionPolicyRequest{
		ResourceType:  domain.RetentionResourceAuditEvent,
		RetentionDays: 3650,
		State:         domain.StateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	policies, err := control.ListRetentionPolicies(ctx, actor, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresRetentionPolicy(policies, policy.ID, domain.RetentionResourceAuditEvent, domain.StateActive) {
		t.Fatalf("expected retention policy in tenant list, got %+v", policies)
	}
	retentionDays := 3650
	hold := false
	updated, err := control.UpdateRetentionPolicy(ctx, actor, policy.ID, app.UpdateRetentionPolicyRequest{
		RetentionDays: &retentionDays,
		LegalHold:     &hold,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != policy.ID || updated.RetentionDays != 3650 || updated.LegalHold {
		t.Fatalf("retention policy update mismatch: %+v", updated)
	}
	if err := store.ApplyRetentionPolicies(ctx, "it-retention-worker", 1000); err != nil {
		t.Fatal(err)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "retention_policy.updated", "retention_policy", policy.ID)
}

func TestPostgresProviderAdapterRegistryLifecycle(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	control := app.NewControlService(store, ssrf.Validator{})
	suffix := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "_")
	adapter, err := control.CreateProviderAdapter(ctx, actor, app.CreateProviderAdapterRequest{
		Name:          "integration_adapter_" + suffix,
		Kind:          domain.AdapterKindDeclarative,
		Description:   "integration adapter registry lifecycle",
		RiskLevel:     domain.AdapterRiskMedium,
		ProvenanceURL: "https://docs.example.com/integration-adapter",
	})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.TenantID != actor.TenantID || adapter.CreatedBy != actor.ID || adapter.State != domain.AdapterStateDraft {
		t.Fatalf("provider adapter did not preserve tenant and creator evidence: %+v", adapter)
	}
	if _, err := store.GetProviderAdapter(ctx, actor.TenantID+"_wrong", adapter.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("wrong-tenant provider adapter lookup must be hidden, got %v", err)
	}
	adapters, err := control.ListProviderAdapters(ctx, actor, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresProviderAdapter(adapters, adapter.ID, domain.AdapterStateDraft) {
		t.Fatalf("expected created adapter in tenant list, got %+v", adapters)
	}
	fetchedAdapter, err := control.GetProviderAdapter(ctx, actor, adapter.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fetchedAdapter.ID != adapter.ID || fetchedAdapter.Name != adapter.Name {
		t.Fatalf("provider adapter lookup mismatch: got %+v want %+v", fetchedAdapter, adapter)
	}

	definition := json.RawMessage(`{"provider":"custom","verification":{"algorithm":"hmac-sha256","header":"X-Webhookery-Signature"},"normalization":{"event_id":"$.id","event_type":"$.type"}}`)
	version, err := control.CreateAdapterVersion(ctx, actor, adapter.ID, app.CreateAdapterVersionRequest{
		Version:       "v1",
		Definition:    definition,
		ProvenanceURL: "https://docs.example.com/integration-adapter/v1",
		RiskLevel:     domain.AdapterRiskMedium,
		Reason:        "integration adapter version creation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if version.AdapterID != adapter.ID || version.Name != adapter.Name || version.State != domain.AdapterStateDraft || version.DefinitionSHA256 == "" {
		t.Fatalf("adapter version did not preserve draft metadata: %+v", version)
	}
	versions, err := control.ListAdapterVersions(ctx, actor, adapter.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresAdapterVersion(versions, version.ID, domain.AdapterStateDraft) {
		t.Fatalf("expected draft adapter version in tenant list, got %+v", versions)
	}
	vector, err := control.CreateAdapterTestVector(ctx, actor, adapter.ID, version.ID, app.CreateAdapterTestVectorRequest{
		Name:     "valid hmac envelope",
		Purpose:  "integration governance evidence",
		Request:  json.RawMessage(`{"headers":{"X-Webhookery-Signature":"valid-test-vector"},"body":{"id":"evt_test","type":"invoice.created"}}`),
		Expected: json.RawMessage(`{"verified":true,"provider_event_id":"evt_test","type":"invoice.created"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if vector.AdapterVersionID != version.ID || vector.RequestSHA256 == "" || vector.ExpectedSHA256 == "" {
		t.Fatalf("adapter test vector did not preserve hash evidence: %+v", vector)
	}

	version, err = control.TransitionAdapterVersion(ctx, actor, adapter.ID, version.ID, app.AdapterVersionTransitionRequest{
		Action:      "submit_tests",
		Reason:      "integration automated test pass",
		TestResults: json.RawMessage(`{"passed":true,"vectors":1}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if version.State != domain.AdapterStateAutomatedTests || !bytes.Contains(version.TestResults, []byte(`"passed": true`)) && !bytes.Contains(version.TestResults, []byte(`"passed":true`)) {
		t.Fatalf("adapter version did not record automated test evidence: %+v", version)
	}
	version, err = control.TransitionAdapterVersion(ctx, actor, adapter.ID, version.ID, app.AdapterVersionTransitionRequest{Action: "request_review", Reason: "integration security review requested"})
	if err != nil {
		t.Fatal(err)
	}
	if version.State != domain.AdapterStateSecurityReview {
		t.Fatalf("expected security review state, got %+v", version)
	}
	version, err = control.TransitionAdapterVersion(ctx, actor, adapter.ID, version.ID, app.AdapterVersionTransitionRequest{
		Action:      "approve_staging",
		Reason:      "integration staging approval",
		ReviewNotes: "definition is deterministic and secret-free",
	})
	if err != nil {
		t.Fatal(err)
	}
	if version.State != domain.AdapterStateStagingApproved || version.ReviewedBy != actor.ID || version.ReviewedAt.IsZero() {
		t.Fatalf("adapter version did not record review evidence: %+v", version)
	}
	version, err = control.TransitionAdapterVersion(ctx, actor, adapter.ID, version.ID, app.AdapterVersionTransitionRequest{Action: "activate", Reason: "integration activation"})
	if err != nil {
		t.Fatal(err)
	}
	if version.State != domain.AdapterStateActive || version.ActivatedBy != actor.ID || version.ActivatedAt.IsZero() {
		t.Fatalf("adapter version did not record activation evidence: %+v", version)
	}
	active, err := store.ActiveDeclarativeAdapterVersion(ctx, actor.TenantID, adapter.Name)
	if err != nil {
		t.Fatal(err)
	}
	if active.ID != version.ID || active.State != domain.AdapterStateActive {
		t.Fatalf("active declarative adapter lookup mismatch: got %+v want %+v", active, version)
	}
	var reviews int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM adapter_version_reviews WHERE tenant_id=$1 AND adapter_version_id=$2`, actor.TenantID, version.ID).Scan(&reviews); err != nil {
		t.Fatal(err)
	}
	if reviews != 4 {
		t.Fatalf("expected four adapter version review records, got %d", reviews)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "adapter.created", "provider_adapter", adapter.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "adapter_version.created", "adapter_version", version.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "adapter_test_vector.created", "adapter_version", version.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "adapter_version.activate", "adapter_version", version.ID)
}

func TestPostgresProviderConnectionAndReconciliationLifecycle(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	control := app.NewControlService(store, ssrf.Validator{})
	suffix := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "_")
	credential := "shpat_integration_credential_" + suffix
	connection, err := control.CreateProviderConnection(ctx, actor, app.CreateProviderConnectionRequest{
		Name:           " integration shopify connection ",
		Provider:       " Shopify ",
		CredentialType: "api_key",
		Credential:     credential,
		Config:         map[string]string{" shop ": "integration-store.myshopify.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if connection.TenantID != actor.TenantID || connection.Provider != "shopify" || connection.State != domain.ProviderConnectionStateActive || connection.Config["shop"] != "integration-store.myshopify.com" {
		t.Fatalf("provider connection was not normalized and tenant scoped: %+v", connection)
	}
	if connection.CredentialHint == "" || strings.Contains(connection.CredentialHint, credential) {
		t.Fatalf("provider connection public credential hint leaked full credential: %q", connection.CredentialHint)
	}
	var encryptedCredential []byte
	if err := store.pool.QueryRow(ctx, `SELECT encrypted_credential FROM provider_connections WHERE tenant_id=$1 AND id=$2`, actor.TenantID, connection.ID).Scan(&encryptedCredential); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encryptedCredential, []byte(credential)) {
		t.Fatal("encrypted provider credential contains plaintext credential bytes")
	}
	if _, err := store.GetProviderConnection(ctx, actor.TenantID+"_wrong", connection.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("wrong-tenant provider connection lookup must be hidden, got %v", err)
	}
	connections, err := control.ListProviderConnections(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresProviderConnection(connections, connection.ID, domain.ProviderConnectionStateActive) {
		t.Fatalf("expected active provider connection in tenant list, got %+v", connections)
	}
	fetched, err := control.GetProviderConnection(ctx, actor, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fetched.ID != connection.ID || fetched.CredentialHint != connection.CredentialHint {
		t.Fatalf("provider connection lookup mismatch: got %+v want %+v", fetched, connection)
	}

	reconciliationConnection, decryptedCredential, err := store.GetReconciliationConnection(ctx, actor.TenantID, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reconciliationConnection.ID != connection.ID || decryptedCredential != credential {
		t.Fatal("reconciliation credential lookup did not decrypt the expected provider credential")
	}
	verified, err := control.VerifyProviderConnection(ctx, actor, connection.ID, app.ProviderConnectionStateRequest{Reason: "integration verification"})
	if err != nil {
		t.Fatal(err)
	}
	if verified.VerifiedAt.IsZero() || verified.State != domain.ProviderConnectionStateActive {
		t.Fatalf("provider connection verification did not persist evidence: %+v", verified)
	}

	windowStart := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	windowEnd := time.Now().UTC().Truncate(time.Second)
	job, err := control.CreateReconciliationJob(ctx, actor, app.ReconciliationJobRequest{
		ConnectionID:    connection.ID,
		CaptureMissing:  true,
		RouteRecovered:  true,
		RedeliverFailed: true,
		ScopeObjectID:   "gid://shopify/WebhookSubscription/integration",
		WindowStart:     windowStart,
		WindowEnd:       windowEnd,
		Reason:          "integration reconciliation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.TenantID != actor.TenantID || job.Provider != "shopify" || job.State != domain.ReconciliationJobStateScheduled || !job.CaptureMissing || !job.RouteRecovered || !job.RedeliverFailed {
		t.Fatalf("reconciliation job did not preserve requested provider recovery controls: %+v", job)
	}
	if job.WindowStart.IsZero() || job.WindowEnd.IsZero() || job.CreatedBy != actor.ID {
		t.Fatalf("reconciliation job did not preserve time window and actor evidence: %+v", job)
	}
	jobs, err := control.ListReconciliationJobs(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresReconciliationJob(jobs, job.ID, domain.ReconciliationJobStateScheduled) {
		t.Fatalf("expected scheduled reconciliation job in tenant list, got %+v", jobs)
	}
	fetchedJob, err := control.GetReconciliationJob(ctx, actor, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fetchedJob.ID != job.ID || fetchedJob.ConnectionID != connection.ID {
		t.Fatalf("reconciliation job lookup mismatch: got %+v want %+v", fetchedJob, job)
	}
	items, err := control.ListReconciliationItems(ctx, actor, job.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("new reconciliation job should not have item evidence before worker processing, got %+v", items)
	}
	var outboxRows int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND kind=$2 AND resource_id=$3`, actor.TenantID, app.OutboxKindReconciliationJob, job.ID).Scan(&outboxRows); err != nil {
		t.Fatal(err)
	}
	if outboxRows != 1 {
		t.Fatalf("expected reconciliation job outbox work, got %d rows", outboxRows)
	}
	canceled, err := control.CancelReconciliationJob(ctx, actor, job.ID, app.ProviderConnectionStateRequest{Reason: "integration cancellation"})
	if err != nil {
		t.Fatal(err)
	}
	if canceled.State != domain.ReconciliationJobStateCanceled || canceled.CanceledAt.IsZero() || canceled.CompletedAt.IsZero() {
		t.Fatalf("reconciliation cancellation did not persist terminal evidence: %+v", canceled)
	}

	revoked, err := control.RevokeProviderConnection(ctx, actor, connection.ID, app.ProviderConnectionStateRequest{Reason: "integration revocation"})
	if err != nil {
		t.Fatal(err)
	}
	if revoked.State != domain.ProviderConnectionStateRevoked || revoked.RevokedAt.IsZero() {
		t.Fatalf("provider connection revocation did not persist evidence: %+v", revoked)
	}
	if _, _, err := store.GetReconciliationConnection(ctx, actor.TenantID, connection.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("revoked provider credential must not be available to reconciliation workers, got %v", err)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "provider_connection.created", "provider_connection", connection.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "provider_connection.verified", "provider_connection", connection.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "reconciliation.created", "reconciliation_job", job.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "reconciliation.canceled", "reconciliation_job", job.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "provider_connection.revoked", "provider_connection", connection.ID)
}

func TestPostgresIncidentLifecycleReportAndEvidenceExport(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	control := app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{
		"receiver.example.com": {netip.MustParseAddr("93.184.216.34")},
	}})
	source, _ := createPostgresIntegrationRoute(t, ctx, control, actor, "invoice.incident")
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	ingested := ingestPostgresIntegrationEvent(t, ctx, store, actor, source.ID, "invoice.incident", "evt_it_incident_"+time.Now().UTC().Format("150405.000000000"), now)

	incident, err := control.CreateIncident(ctx, actor, app.CreateIncidentRequest{
		Title:  "Receiver outage for invoice incident",
		Reason: "support investigation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if incident.TenantID != actor.TenantID || incident.State != domain.StateActive || incident.CreatedBy != actor.ID {
		t.Fatalf("incident was not tenant scoped and active: %+v", incident)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "incident.created", "incident", incident.ID)

	incidents, err := control.ListIncidents(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresIncident(incidents, incident.ID, domain.StateActive) {
		t.Fatalf("expected incident in tenant list, got %+v", incidents)
	}
	if _, err := store.GetIncident(ctx, "ten_it_wrong_incident", incident.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("wrong-tenant incident lookup must be hidden, got %v", err)
	}

	link, err := control.AddIncidentEvent(ctx, actor, incident.ID, app.AddIncidentEventRequest{
		EventID: ingested.EventID,
		Reason:  "customer escalation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if link.TenantID != actor.TenantID || link.IncidentID != incident.ID || link.EventID != ingested.EventID || link.AddedBy != actor.ID {
		t.Fatalf("incident event link was not scoped correctly: %+v", link)
	}
	updatedLink, err := control.AddIncidentEvent(ctx, actor, incident.ID, app.AddIncidentEventRequest{
		EventID: ingested.EventID,
		Reason:  "customer escalation updated",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updatedLink.ID != link.ID || updatedLink.Reason != "customer escalation updated" {
		t.Fatalf("duplicate incident event link did not update idempotently: original=%+v updated=%+v", link, updatedLink)
	}
	links, err := store.ListIncidentEvents(ctx, actor.TenantID, incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].EventID != ingested.EventID {
		t.Fatalf("expected one incident event link, got %+v", links)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "incident.event_added", "incident", incident.ID)

	snapshot, err := control.GenerateIncidentReport(ctx, actor, incident.ID, app.IncidentReportRequest{Reason: "handoff"})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TenantID != actor.TenantID || snapshot.IncidentID != incident.ID || snapshot.SchemaVersion != "webhookery.incident_report.v1" || !strings.Contains(snapshot.Markdown, "Receiver outage for invoice incident") {
		t.Fatalf("unexpected report snapshot: %+v", snapshot)
	}
	latestSnapshot, err := control.GetIncidentReport(ctx, actor, incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	if latestSnapshot.ID != snapshot.ID || !bytes.Contains(latestSnapshot.Report, []byte(ingested.EventID)) {
		t.Fatalf("latest incident report did not round trip: %+v", latestSnapshot)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "incident_report.generated", "incident", incident.ID)

	incidentExport, export, err := control.CreateIncidentEvidenceExport(ctx, actor, incident.ID, app.CreateIncidentEvidenceExportRequest{Reason: "customer evidence"})
	if err != nil {
		t.Fatal(err)
	}
	if incidentExport.TenantID != actor.TenantID || incidentExport.IncidentID != incident.ID || incidentExport.ExportID != export.ID || !export.IncludeTimelines || export.IncludeRawPayloads || export.IncludePayloadBodies {
		t.Fatalf("unexpected incident evidence export: incident_export=%+v export=%+v", incidentExport, export)
	}
	download, err := control.DownloadAuditExport(ctx, actor, export.ID)
	if err != nil {
		t.Fatal(err)
	}
	files := readTestTarGzipFiles(t, download.Body)
	if !bytes.Contains(files["incident_report.json"], []byte(ingested.EventID)) || !bytes.Contains(files["incident_report.md"], []byte("Receiver outage for invoice incident")) {
		t.Fatalf("incident export did not include expected report files: names=%v", sortedTestMapKeys(files))
	}
	if bytes.Contains(files["incident_report.json"], []byte("acct_it")) {
		t.Fatalf("incident export included raw payload content: %s", files["incident_report.json"])
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "incident_evidence_export.created", "incident", incident.ID)

	removed, err := control.RemoveIncidentEvent(ctx, actor, incident.ID, ingested.EventID, app.StateChangeRequest{Reason: "resolved"})
	if err != nil {
		t.Fatal(err)
	}
	if removed.ID != link.ID || removed.EventID != ingested.EventID {
		t.Fatalf("unexpected removed incident event link: %+v", removed)
	}
	links, err = store.ListIncidentEvents(ctx, actor.TenantID, incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 0 {
		t.Fatalf("expected incident links to be removed, got %+v", links)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "incident.event_removed", "incident", incident.ID)
	if _, err := control.RemoveIncidentEvent(ctx, actor, incident.ID, ingested.EventID, app.StateChangeRequest{Reason: "already removed"}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("removing a missing incident event should return not found, got %v", err)
	}
}

func TestPostgresProducerClientAndMTLSLifecycle(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	control := app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	source, err := control.CreateSource(ctx, actor, app.CreateSourceRequest{
		Name:               "producer source",
		Provider:           "stripe",
		Adapter:            "stripe",
		VerificationSecret: "whsec_producer",
	})
	if err != nil {
		t.Fatal(err)
	}

	created, err := control.CreateProducerClient(ctx, actor, app.CreateProducerClientRequest{
		Name:            "batch producer",
		SourceID:        source.ID,
		Scopes:          []string{"events:write"},
		TokenTTLSeconds: 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Client.TenantID != actor.TenantID || created.Client.SourceID != source.ID || created.ClientSecret == "" || !strings.HasPrefix(created.ClientSecret, "whpcs_") {
		t.Fatalf("unexpected producer client creation: %+v secret=%q", created.Client, created.ClientSecret)
	}
	if created.Client.ID == created.ClientSecret || strings.Contains(created.Client.ID, created.ClientSecret) {
		t.Fatalf("client response leaked secret into id fields: %+v", created.Client)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "producer_client.created", "producer_client", created.Client.ID)

	clients, err := control.ListProducerClients(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresProducerClient(clients, created.Client.ID, domain.StateActive) {
		t.Fatalf("expected active producer client in list, got %+v", clients)
	}
	gotClient, err := control.GetProducerClient(ctx, actor, created.Client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotClient.ID != created.Client.ID || gotClient.SourceID != source.ID {
		t.Fatalf("producer client did not round trip: %+v", gotClient)
	}
	if _, err := store.GetProducerClient(ctx, "ten_it_wrong_producer", created.Client.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("wrong-tenant producer client lookup must be hidden, got %v", err)
	}

	producerToken, err := control.IssueProducerToken(ctx, created.Client.ID, created.ClientSecret)
	if err != nil {
		t.Fatal(err)
	}
	if producerToken.AccessToken == "" || producerToken.TokenType != "Bearer" || producerToken.ExpiresIn != 600 {
		t.Fatalf("unexpected producer token response: %+v", producerToken)
	}
	producerActor, err := store.AuthenticateProducerAccessToken(ctx, app.HashToken(producerToken.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	if producerActor.TenantID != actor.TenantID || producerActor.SourceID != source.ID || producerActor.ID != "producer_client:"+created.Client.ID {
		t.Fatalf("unexpected producer access actor: %+v", producerActor)
	}

	newName := "batch producer renamed"
	newTTL := 1200
	updated, err := control.UpdateProducerClient(ctx, actor, created.Client.ID, app.UpdateProducerClientRequest{
		Name:            &newName,
		TokenTTLSeconds: &newTTL,
		Scopes:          []string{"events:write"},
		Reason:          "tighten token policy",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != newName || updated.TokenTTLSeconds != newTTL || strings.Join(updated.Scopes, ",") != "events:write" {
		t.Fatalf("producer client update did not persist: %+v", updated)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "producer_client.updated", "producer_client", created.Client.ID)

	rotated, err := control.RotateProducerClientSecret(ctx, actor, created.Client.ID, app.RotateProducerClientSecretRequest{Reason: "scheduled rotation"})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ClientSecret == "" || rotated.Secret.Hash != "" || rotated.Secret.ClientID != created.Client.ID {
		t.Fatalf("rotated producer secret response leaked hash or lost linkage: %+v secret=%q", rotated.Secret, rotated.ClientSecret)
	}
	if _, err := control.IssueProducerToken(ctx, created.Client.ID, created.ClientSecret); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatalf("old producer secret must not authenticate after rotation, got %v", err)
	}
	if _, err := control.IssueProducerToken(ctx, created.Client.ID, rotated.ClientSecret); err != nil {
		t.Fatalf("rotated producer secret should authenticate, got %v", err)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "producer_client.secret_rotated", "producer_client", created.Client.ID)

	certPEM := testPostgresClientCertificatePEM(t, "Webhookery Producer Integration")
	identity, err := control.CreateProducerMTLSIdentity(ctx, actor, app.CreateProducerMTLSIdentityRequest{
		Name:           "producer certificate",
		SourceID:       source.ID,
		CertificatePEM: certPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	if identity.TenantID != actor.TenantID || identity.SourceID != source.ID || identity.CertificateFingerprintSHA256 == "" || identity.State != domain.StateActive {
		t.Fatalf("unexpected producer mTLS identity: %+v", identity)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "producer_mtls_identity.created", "producer_mtls_identity", identity.ID)

	mtlsActor, err := store.AuthenticateProducerMTLSIdentity(ctx, identity.CertificateFingerprintSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if mtlsActor.TenantID != actor.TenantID || mtlsActor.SourceID != source.ID || mtlsActor.ID != "producer_mtls:"+identity.ID {
		t.Fatalf("unexpected producer mTLS actor: %+v", mtlsActor)
	}
	verification, err := control.VerifyProducerMTLSIdentity(ctx, actor, identity.ID, app.VerifyProducerMTLSIdentityRequest{CertificatePEM: certPEM})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Matched {
		t.Fatalf("expected producer certificate to match identity: %+v", verification)
	}
	identities, err := control.ListProducerMTLSIdentities(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresProducerMTLSIdentity(identities, identity.ID, domain.StateActive) {
		t.Fatalf("expected active producer mTLS identity in list, got %+v", identities)
	}
	if _, err := store.GetProducerMTLSIdentity(ctx, "ten_it_wrong_producer", identity.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("wrong-tenant producer mTLS identity lookup must be hidden, got %v", err)
	}

	mtlsName := "producer certificate renamed"
	updatedIdentity, err := control.UpdateProducerMTLSIdentity(ctx, actor, identity.ID, app.UpdateProducerMTLSIdentityRequest{Name: &mtlsName, Reason: "rename certificate"})
	if err != nil {
		t.Fatal(err)
	}
	if updatedIdentity.Name != mtlsName || updatedIdentity.State != domain.StateActive {
		t.Fatalf("producer mTLS update did not persist: %+v", updatedIdentity)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "producer_mtls_identity.updated", "producer_mtls_identity", identity.ID)

	disabledIdentity, err := control.DeleteProducerMTLSIdentity(ctx, actor, identity.ID, app.StateChangeRequest{Reason: "certificate retired"})
	if err != nil {
		t.Fatal(err)
	}
	if disabledIdentity.State != domain.StateDisabled {
		t.Fatalf("expected disabled producer mTLS identity, got %+v", disabledIdentity)
	}
	if _, err := store.AuthenticateProducerMTLSIdentity(ctx, identity.CertificateFingerprintSHA256); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatalf("disabled producer mTLS identity must not authenticate, got %v", err)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "producer_mtls_identity.disabled", "producer_mtls_identity", identity.ID)

	disabledClient, err := control.DeleteProducerClient(ctx, actor, created.Client.ID, app.StateChangeRequest{Reason: "producer retired"})
	if err != nil {
		t.Fatal(err)
	}
	if disabledClient.State != domain.StateDisabled {
		t.Fatalf("expected disabled producer client, got %+v", disabledClient)
	}
	if _, err := control.IssueProducerToken(ctx, created.Client.ID, rotated.ClientSecret); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatalf("disabled producer client must not authenticate, got %v", err)
	}
	if _, err := store.AuthenticateProducerAccessToken(ctx, app.HashToken(producerToken.AccessToken)); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatalf("producer access token must be revoked when client is disabled, got %v", err)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "producer_client.disabled", "producer_client", created.Client.ID)
}

func TestPostgresEnterpriseIdentitySessionsAndProviderLifecycle(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	suffix := time.Now().UTC().Format("150405.000000000")
	idp, err := store.CreateIdentityProvider(ctx, actor.TenantID, actor.ID, app.CreateIdentityProviderRequest{
		Name:                " Integration OIDC ",
		IssuerURL:           " https://issuer.example.com ",
		AuthorizationURL:    " https://issuer.example.com/authorize ",
		TokenURL:            " https://issuer.example.com/token ",
		JWKSURL:             " https://issuer.example.com/jwks.json ",
		ClientID:            " client-" + suffix + " ",
		ClientSecret:        " oidc-secret-" + suffix + " ",
		RedirectURI:         " https://webhookery.example.com/auth/callback ",
		AllowedEmailDomains: []string{" Example.COM ", "example.com", "", "Ops.Example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if idp.ProviderType != app.IdentityProviderOIDC || idp.Name != "Integration OIDC" {
		t.Fatalf("expected default OIDC provider with trimmed name, got %+v", idp)
	}
	if strings.Join(idp.AllowedEmailDomains, ",") != "example.com,ops.example.com" {
		t.Fatalf("expected normalized allowed domains, got %v", idp.AllowedEmailDomains)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "identity_provider.created", "identity_provider", idp.ID)
	idps, err := store.ListIdentityProviders(ctx, actor.TenantID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresIdentityProvider(idps, idp.ID, domain.StateActive) {
		t.Fatalf("expected identity provider in tenant list, got %+v", idps)
	}

	gotIDP, err := store.GetIdentityProvider(ctx, actor.TenantID, idp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotIDP.ClientSecret) != " oidc-secret-"+suffix+" " {
		t.Fatalf("expected decrypted client secret to round trip")
	}
	if _, err := store.GetIdentityProvider(ctx, "ten_it_wrong_"+suffix, idp.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("wrong-tenant identity provider lookup must be hidden, got %v", err)
	}
	testedIDP, err := store.TestIdentityProvider(ctx, actor.TenantID, idp.ID, actor.ID, "integration smoke")
	if err != nil {
		t.Fatal(err)
	}
	if len(testedIDP.ClientSecret) != 0 {
		t.Fatal("identity provider test result must not expose the client secret")
	}

	stateHash := app.HashToken("state-" + suffix)
	if err := store.CreateOIDCLoginState(ctx, domain.OIDCLoginState{
		TenantID:           actor.TenantID,
		IdentityProviderID: idp.ID,
		StateHash:          stateHash,
		NonceHash:          app.HashToken("nonce-" + suffix),
		PKCEVerifier:       []byte("pkce-verifier-" + suffix),
		RedirectAfter:      "/events",
		ExpiresAt:          time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	consumed, consumedIDP, err := store.ConsumeOIDCLoginState(ctx, stateHash)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.IdentityProviderID != idp.ID || consumedIDP.ID != idp.ID || string(consumed.PKCEVerifier) != "pkce-verifier-"+suffix {
		t.Fatalf("unexpected consumed OIDC state/provider: state=%+v idp=%+v", consumed, consumedIDP)
	}
	if _, _, err := store.ConsumeOIDCLoginState(ctx, stateHash); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatalf("OIDC login state must be one-time use, got %v", err)
	}

	sessionHash := app.HashToken("session-" + suffix)
	session, sessionActor, err := store.CreateOIDCSession(ctx, app.OIDCSessionInput{
		TenantID:           actor.TenantID,
		IdentityProviderID: idp.ID,
		ExternalSubject:    "sub-" + suffix,
		Email:              "User+" + suffix + "@Example.com",
		EmailVerified:      true,
		DisplayName:        "OIDC User",
		SessionHash:        sessionHash,
		UserAgentHash:      app.HashToken("ua-" + suffix),
		IPHash:             app.HashToken("ip-" + suffix),
		ExpiresAt:          time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.ExternalIdentityID == "" || sessionActor.TenantID != actor.TenantID || sessionActor.Role != authz.RoleSupport {
		t.Fatalf("unexpected OIDC session/actor: session=%+v actor=%+v", session, sessionActor)
	}
	authenticated, err := store.AuthenticateSession(ctx, sessionHash)
	if err != nil {
		t.Fatal(err)
	}
	if authenticated.ID != sessionActor.ID || authenticated.TenantID != actor.TenantID {
		t.Fatalf("unexpected authenticated actor: %+v", authenticated)
	}
	current, err := store.CurrentAuthSession(ctx, actor.TenantID, sessionActor.ID, sessionHash)
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != session.ID {
		t.Fatalf("expected current session %s, got %+v", session.ID, current)
	}
	sessions, err := store.ListAuthSessions(ctx, actor.TenantID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresAuthSession(sessions, session.ID, domain.StateActive) {
		t.Fatalf("expected active session in tenant list, got %+v", sessions)
	}
	revoked, err := store.RevokeAuthSessionByID(ctx, actor.TenantID, session.ID, actor.ID, "integration revoke")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.State != "revoked" {
		t.Fatalf("expected revoked session, got %+v", revoked)
	}
	if _, err := store.AuthenticateSession(ctx, sessionHash); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatalf("revoked session must not authenticate, got %v", err)
	}
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "auth_session.revoked", "auth_session", session.ID)

	logoutSessionHash := app.HashToken("session-logout-" + suffix)
	if _, _, err := store.CreateOIDCSession(ctx, app.OIDCSessionInput{
		TenantID:           actor.TenantID,
		IdentityProviderID: idp.ID,
		ExternalSubject:    "sub-logout-" + suffix,
		Email:              "logout+" + suffix + "@example.com",
		DisplayName:        "Logout User",
		SessionHash:        logoutSessionHash,
		ExpiresAt:          time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeAuthSession(ctx, actor.TenantID, actor.ID, logoutSessionHash, "integration logout"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateSession(ctx, logoutSessionHash); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatalf("logged-out session must not authenticate, got %v", err)
	}

	secondSessionHash := app.HashToken("session-disabled-idp-" + suffix)
	secondSession, _, err := store.CreateOIDCSession(ctx, app.OIDCSessionInput{
		TenantID:           actor.TenantID,
		IdentityProviderID: idp.ID,
		ExternalSubject:    "sub-disabled-" + suffix,
		Email:              "disabled+" + suffix + "@example.com",
		DisplayName:        "Disabled IDP User",
		SessionHash:        secondSessionHash,
		ExpiresAt:          time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := store.DisableIdentityProvider(ctx, actor.TenantID, idp.ID, actor.ID, "integration disable")
	if err != nil {
		t.Fatal(err)
	}
	if disabled.State != domain.StateDisabled {
		t.Fatalf("expected disabled identity provider, got %+v", disabled)
	}
	if _, err := store.AuthenticateSession(ctx, secondSessionHash); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatalf("sessions from disabled identity providers must not authenticate, got %v", err)
	}
	sessions, err = store.ListAuthSessions(ctx, actor.TenantID, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresAuthSession(sessions, secondSession.ID, "revoked") {
		t.Fatalf("disabling identity provider should revoke active sessions, got %+v", sessions)
	}
}

func TestPostgresSCIMAndPolicyLifecycle(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	suffix := time.Now().UTC().Format("150405.000000000")
	tokenValue := "scim-token-" + suffix
	scimToken, err := store.CreateSCIMToken(ctx, actor.TenantID, actor.ID, domain.SCIMToken{
		Name:   "SCIM integration token",
		Hash:   app.HashToken(tokenValue),
		Prefix: "scim",
		Last4:  "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	scimActor, err := store.AuthenticateSCIMTokenHash(ctx, app.HashToken(tokenValue))
	if err != nil {
		t.Fatal(err)
	}
	if scimActor.TenantID != actor.TenantID || scimActor.Role != authz.RoleSecurity || scimActor.ID != "scim:"+scimToken.ID {
		t.Fatalf("unexpected SCIM actor: %+v", scimActor)
	}
	tokens, err := store.ListSCIMTokens(ctx, actor.TenantID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresSCIMToken(tokens, scimToken.ID, domain.StateActive) {
		t.Fatalf("expected active SCIM token in tenant list, got %+v", tokens)
	}

	user, err := store.SCIMCreateOrReplaceUser(ctx, actor.TenantID, scimActor.ID, app.SCIMUserRequest{
		ExternalID:  "scim-user-" + suffix,
		UserName:    "Scim.User+" + suffix + "@Example.com",
		DisplayName: "SCIM User",
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if user.ID == "" || user.UserName != "Scim.User+"+suffix+"@Example.com" || !user.Active {
		t.Fatalf("unexpected provisioned SCIM user: %+v", user)
	}
	patchedUser, err := store.SCIMPatchUser(ctx, actor.TenantID, scimActor.ID, user.ID, app.SCIMPatchRequest{Operations: []app.SCIMOperation{{
		Op:    "replace",
		Path:  "displayName",
		Value: json.RawMessage(`"SCIM User Patched"`),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if patchedUser.DisplayName != "SCIM User Patched" {
		t.Fatalf("expected patched display name, got %+v", patchedUser)
	}
	if _, err := store.SCIMGetUser(ctx, "ten_it_wrong_"+suffix, user.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("wrong-tenant SCIM user lookup must be hidden, got %v", err)
	}
	users, err := store.SCIMListUsers(ctx, actor.TenantID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresSCIMUser(users, user.ID, true) {
		t.Fatalf("expected active SCIM user in tenant list, got %+v", users)
	}

	group, err := store.SCIMCreateOrReplaceGroup(ctx, actor.TenantID, scimActor.ID, app.SCIMGroupRequest{
		ExternalID:  "scim-group-" + suffix,
		DisplayName: "SCIM Operators",
		Members:     []app.SCIMGroupMember{{Value: user.ID}},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if group.ID == "" || len(group.Members) != 1 || group.Members[0].Value != user.ID {
		t.Fatalf("unexpected SCIM group: %+v", group)
	}
	patchedGroup, err := store.SCIMPatchGroup(ctx, actor.TenantID, scimActor.ID, group.ID, app.SCIMPatchRequest{Operations: []app.SCIMOperation{{
		Op:    "replace",
		Path:  "displayName",
		Value: json.RawMessage(`"SCIM Security"`),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if patchedGroup.DisplayName != "SCIM Security" {
		t.Fatalf("expected patched group display name, got %+v", patchedGroup)
	}
	if groups, err := store.SCIMListGroups(ctx, actor.TenantID, 10); err != nil {
		t.Fatal(err)
	} else if !containsPostgresSCIMGroup(groups, group.ID, true) {
		t.Fatalf("expected active SCIM group in tenant list, got %+v", groups)
	}

	binding, err := store.CreateRoleBinding(ctx, actor.TenantID, actor.ID, app.CreateRoleBindingRequest{
		PrincipalType:  "group",
		PrincipalID:    group.ID,
		Role:           authz.RoleOwner,
		ResourceFamily: "secrets",
		ResourceID:     "secret-" + suffix,
		Environment:    "prod",
		Reason:         "integration group elevation",
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := store.ListRoleBindings(ctx, actor.TenantID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresRoleBinding(bindings, binding.ID, domain.StateActive) {
		t.Fatalf("expected active role binding in tenant list, got %+v", bindings)
	}
	decision, err := store.ExplainAuthorization(ctx, actor.TenantID, user.ID, app.AuthzExplainRequest{
		Action:         "security:write",
		ResourceFamily: "secrets",
		ResourceID:     "secret-" + suffix,
		Environment:    "prod",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || decision.MatchedRoleBindingID != binding.ID {
		t.Fatalf("expected group role binding to allow security write, got %+v", decision)
	}

	policy, err := store.CreateAccessPolicyRule(ctx, actor.TenantID, actor.ID, app.CreateAccessPolicyRuleRequest{
		Name:           "deny integration secret writes",
		Action:         "security:write",
		Effect:         app.PolicyEffectDeny,
		ResourceFamily: "secrets",
		Environment:    "prod",
		Conditions:     json.RawMessage(`{"reason":"integration"}`),
		Reason:         "integration deny override",
	})
	if err != nil {
		t.Fatal(err)
	}
	policies, err := store.ListAccessPolicyRules(ctx, actor.TenantID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresAccessPolicyRule(policies, policy.ID, domain.StateActive) {
		t.Fatalf("expected active access policy in tenant list, got %+v", policies)
	}
	denied, err := store.ExplainAuthorization(ctx, actor.TenantID, user.ID, app.AuthzExplainRequest{
		Action:         "security:write",
		ResourceFamily: "secrets",
		ResourceID:     "secret-" + suffix,
		Environment:    "prod",
	})
	if err != nil {
		t.Fatal(err)
	}
	if denied.Allowed || denied.MatchedPolicyRuleID != policy.ID || denied.Reason != "denied by access policy" {
		t.Fatalf("expected deny policy to override role binding, got %+v", denied)
	}
	if _, err := store.UpdateRoleBinding(ctx, actor.TenantID, binding.ID, actor.ID, app.UpdateRoleBindingRequest{Reason: "integration binding update"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DisableRoleBinding(ctx, actor.TenantID, binding.ID, actor.ID, "integration binding disable"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateAccessPolicyRule(ctx, actor.TenantID, policy.ID, actor.ID, app.UpdateAccessPolicyRuleRequest{Reason: "integration policy update"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DisableAccessPolicyRule(ctx, actor.TenantID, policy.ID, actor.ID, "integration policy disable"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SCIMDeactivateGroup(ctx, actor.TenantID, scimActor.ID, group.ID); err != nil {
		t.Fatal(err)
	}
	deactivatedUser, err := store.SCIMDeactivateUser(ctx, actor.TenantID, scimActor.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if deactivatedUser.Active {
		t.Fatalf("expected deactivated SCIM user, got %+v", deactivatedUser)
	}
	revokedToken, err := store.RevokeSCIMToken(ctx, actor.TenantID, scimToken.ID, actor.ID, "integration revoke")
	if err != nil {
		t.Fatal(err)
	}
	if revokedToken.State != "revoked" {
		t.Fatalf("expected revoked SCIM token, got %+v", revokedToken)
	}
	if _, err := store.AuthenticateSCIMTokenHash(ctx, app.HashToken(tokenValue)); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatalf("revoked SCIM token must not authenticate, got %v", err)
	}

	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "scim_token.revoked", "scim_token", scimToken.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "role_binding.updated", "role_binding", binding.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "access_policy.updated", "access_policy", policy.ID)
}

func TestPostgresSchemaAndTransformationLifecycle(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	control := app.NewControlService(store, ssrf.Validator{})
	suffix := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "_")
	eventTypeName := "invoice.schema_" + suffix
	eventType, err := control.CreateEventType(ctx, actor, app.CreateEventTypeRequest{
		Name:        eventTypeName,
		Description: "schema lifecycle integration",
	})
	if err != nil {
		t.Fatal(err)
	}
	if eventType.Name != eventTypeName || eventType.State != domain.StateActive {
		t.Fatalf("unexpected event type: %+v", eventType)
	}
	eventTypes, err := control.ListEventTypes(ctx, actor, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresEventType(eventTypes, eventTypeName, domain.StateActive) {
		t.Fatalf("expected event type in tenant list, got %+v", eventTypes)
	}
	if got, err := control.GetEventType(ctx, actor, eventTypeName); err != nil || got.Name != eventTypeName {
		t.Fatalf("expected event type lookup to round trip, got=%+v err=%v", got, err)
	}
	updatedDescription := "schema lifecycle integration updated"
	updatedEventType, err := control.UpdateEventType(ctx, actor, eventTypeName, app.UpdateEventTypeRequest{
		Description: &updatedDescription,
		Reason:      "integration update",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updatedEventType.Description != updatedDescription {
		t.Fatalf("expected updated event type description, got %+v", updatedEventType)
	}

	schema, err := control.CreateEventSchema(ctx, actor, eventTypeName, app.CreateEventSchemaRequest{
		Version: "1",
		Schema:  `{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if schema.ID == "" || schema.State != domain.StateActive {
		t.Fatalf("unexpected event schema: %+v", schema)
	}
	schemas, err := control.ListEventSchemas(ctx, actor, eventTypeName, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresEventSchema(schemas, schema.ID, domain.StateActive) {
		t.Fatalf("expected event schema in tenant list, got %+v", schemas)
	}
	if got, err := control.GetEventSchema(ctx, actor, eventTypeName, "1"); err != nil || got.ID != schema.ID {
		t.Fatalf("expected event schema lookup to round trip, got=%+v err=%v", got, err)
	}
	deprecated := domain.StateDeprecated
	updatedSchema, err := control.UpdateEventSchema(ctx, actor, eventTypeName, "1", app.UpdateEventSchemaRequest{
		State:  &deprecated,
		Reason: "integration deprecation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updatedSchema.State != domain.StateDeprecated {
		t.Fatalf("expected deprecated schema, got %+v", updatedSchema)
	}

	transformation, err := control.CreateTransformation(ctx, actor, app.CreateTransformationRequest{
		Name:       "integration transformation",
		Operations: json.RawMessage(`[{"op":"set","path":"/metadata/integration","value":"created"}]`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if transformation.ID == "" || transformation.ActiveVersionID == "" {
		t.Fatalf("expected transformation with active version, got %+v", transformation)
	}
	transformations, err := control.ListTransformations(ctx, actor, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresTransformation(transformations, transformation.ID, domain.StateActive) {
		t.Fatalf("expected transformation in tenant list, got %+v", transformations)
	}
	if got, err := control.GetTransformation(ctx, actor, transformation.ID); err != nil || got.ID != transformation.ID {
		t.Fatalf("expected transformation lookup to round trip, got=%+v err=%v", got, err)
	}
	version, err := control.CreateTransformationVersion(ctx, actor, transformation.ID, app.CreateTransformationVersionRequest{
		Operations: json.RawMessage(`[{"op":"set","path":"/metadata/integration","value":"version2"}]`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if version.State != "draft" {
		t.Fatalf("expected draft transformation version, got %+v", version)
	}
	versions, err := control.ListTransformationVersions(ctx, actor, transformation.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPostgresTransformationVersion(versions, version.ID, "draft") {
		t.Fatalf("expected draft transformation version in tenant list, got %+v", versions)
	}
	activated, err := control.ActivateTransformationVersion(ctx, actor, transformation.ID, version.ID, app.ActivateTransformationVersionRequest{Reason: "integration activation"})
	if err != nil {
		t.Fatal(err)
	}
	if activated.State != domain.StateActive {
		t.Fatalf("expected activated transformation version, got %+v", activated)
	}
	retiredSchema, err := control.DeleteEventSchema(ctx, actor, eventTypeName, "1", app.StateChangeRequest{Reason: "integration retire"})
	if err != nil {
		t.Fatal(err)
	}
	if retiredSchema.State != domain.StateRetired {
		t.Fatalf("expected retired schema, got %+v", retiredSchema)
	}
	disabledType, err := control.DeleteEventType(ctx, actor, eventTypeName, app.StateChangeRequest{Reason: "integration disable"})
	if err != nil {
		t.Fatal(err)
	}
	if disabledType.State != domain.StateDisabled {
		t.Fatalf("expected disabled event type, got %+v", disabledType)
	}

	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "event_type.updated", "event_type", eventTypeName)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "event_schema.retired", "event_schema", schema.ID)
	assertPostgresAuditEvent(t, ctx, store, actor.TenantID, "transformation_version.activated", "transformation", transformation.ID)
}

func TestPostgresMigrationsAreIdempotentAndEnforceKeyConstraints(t *testing.T) {
	ctx, store, _ := openPostgresIntegrationStore(t)
	defer store.Close()

	migrationsDir := filepath.Join("..", "..", "..", "migrations")
	if err := MigrateUp(ctx, os.Getenv("WEBHOOKERY_TEST_DATABASE_URL"), migrationsDir); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("expected migration files")
	}
	for _, file := range files {
		version := strings.TrimSuffix(filepath.Base(file), ".up.sql")
		var count int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=$1`, version).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("expected migration %s to be recorded once after rerun, got %d", version, count)
		}
	}

	checksumDrillSuffix := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "_")
	checksumDrillDir := t.TempDir()
	checksumDrillVersion := "999_checksum_drill_" + checksumDrillSuffix
	checksumDrillFile := filepath.Join(checksumDrillDir, checksumDrillVersion+".up.sql")
	checksumDrillBody := "CREATE TABLE IF NOT EXISTS checksum_drill_" + checksumDrillSuffix + "(id integer);\n"
	if err := os.WriteFile(checksumDrillFile, []byte(checksumDrillBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MigrateUp(ctx, os.Getenv("WEBHOOKERY_TEST_DATABASE_URL"), checksumDrillDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checksumDrillFile, []byte(checksumDrillBody+"-- altered after apply\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = MigrateUp(ctx, os.Getenv("WEBHOOKERY_TEST_DATABASE_URL"), checksumDrillDir)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected migration checksum mismatch, got %v", err)
	}

	suffix := time.Now().UTC().Format("150405.000000000")
	tenantID := "ten_it_migration_" + suffix
	if _, err := store.pool.Exec(ctx, `INSERT INTO tenants(id, name) VALUES($1, 'migration constraints') ON CONFLICT (id) DO NOTHING`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO sources(id, tenant_id, name, provider, adapter, state, encrypted_secret)
		VALUES($1,$2,'migration source','stripe','stripe','active',$3)`,
		"src_it_migration_"+suffix, tenantID, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO raw_payloads(id, tenant_id, sha256, content_type, size_bytes, body)
		VALUES($1,$2,'sha256:migration','application/json',2,'{}')`,
		"raw_it_migration_"+suffix, tenantID); err != nil {
		t.Fatal(err)
	}
	insertEvent := func(id string) error {
		_, err := store.pool.Exec(ctx, `
			INSERT INTO events(id, tenant_id, source_id, provider, type, provider_event_id, raw_payload_id, raw_payload_hash,
				signature_verified, verification_reason, dedupe_key, dedupe_status, received_at)
			VALUES($1,$2,$3,'stripe','invoice.created',$1,$4,'sha256:migration',true,'valid','same-dedupe-key','new',now())`,
			id, tenantID, "src_it_migration_"+suffix, "raw_it_migration_"+suffix)
		return err
	}
	if err := insertEvent("evt_it_migration_a_" + suffix); err != nil {
		t.Fatal(err)
	}
	expectPostgresSQLFailure(t, insertEvent("evt_it_migration_b_"+suffix), "duplicate event dedupe key")

	auditA := "aud_it_migration_a_" + suffix
	auditB := "aud_it_migration_b_" + suffix
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason, occurred_at)
		VALUES($1,$2,'usr_it','migration.constraint','test',$1,'constraint',now()),
		      ($3,$2,'usr_it','migration.constraint','test',$3,'constraint',now())`,
		auditA, tenantID, auditB); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO audit_chain_entries(id, tenant_id, sequence, audit_event_id, event_hash, previous_chain_hash, chain_hash,
			canonicalization_version, source, state)
		VALUES($1,$2,1,$3,'sha256:event-a','','sha256:chain-a','audit-chain-v1','backfill','active')`,
		"ace_it_migration_a_"+suffix, tenantID, auditA); err != nil {
		t.Fatal(err)
	}
	_, err = store.pool.Exec(ctx, `
		INSERT INTO audit_chain_entries(id, tenant_id, sequence, audit_event_id, event_hash, previous_chain_hash, chain_hash,
			canonicalization_version, source, state)
		VALUES($1,$2,1,$3,'sha256:event-b','sha256:chain-a','sha256:chain-b','audit-chain-v1','backfill','active')`,
		"ace_it_migration_b_"+suffix, tenantID, auditB)
	expectPostgresSQLFailure(t, err, "duplicate audit chain sequence")

	fingerprint := "sha256:migration-fingerprint-" + suffix
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO producer_mtls_identities(id, tenant_id, name, certificate_fingerprint_sha256, cert_subject, not_before, not_after, state)
		VALUES($1,$2,'migration mTLS',$3,'CN=migration',now(),now() + interval '1 hour','active')`,
		"mtls_it_migration_a_"+suffix, tenantID, fingerprint); err != nil {
		t.Fatal(err)
	}
	_, err = store.pool.Exec(ctx, `
		INSERT INTO producer_mtls_identities(id, tenant_id, name, certificate_fingerprint_sha256, cert_subject, not_before, not_after, state)
		VALUES($1,$2,'migration mTLS duplicate',$3,'CN=migration',now(),now() + interval '1 hour','active')`,
		"mtls_it_migration_b_"+suffix, tenantID, fingerprint)
	expectPostgresSQLFailure(t, err, "duplicate producer mTLS fingerprint")
}

func TestPostgresAuditFailureRollsBackAPIKeyRevocation(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	rawToken := "whkey_audit_failure_" + time.Now().UTC().Format("150405.000000000")
	key, err := store.CreateAPIKey(ctx, app.APIKeyCreateInput{
		Key: domain.APIKey{
			TenantID: actor.TenantID,
			UserID:   actor.ID,
			Name:     "audit failure key",
			Prefix:   "whkey_af",
			Last4:    "0001",
			Hash:     app.HashToken(rawToken),
			Scopes:   []string{"events:read"},
			State:    domain.StateActive,
		},
		Role:    authz.RoleOperator,
		ActorID: actor.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	poisonNextPostgresAuditSequence(t, ctx, store, actor.TenantID)

	if _, err := store.RevokeAPIKey(ctx, actor.TenantID, key.ID, actor.ID, "audit failure injection"); err == nil {
		t.Fatal("expected audit-chain failure to abort API key revocation")
	}
	var state string
	if err := store.pool.QueryRow(ctx, `SELECT state FROM api_keys WHERE tenant_id=$1 AND id=$2`, actor.TenantID, key.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != domain.StateActive {
		t.Fatalf("API key revocation must roll back when audit evidence fails, got state %q", state)
	}
	assertPostgresNoAuditEvent(t, ctx, store, actor.TenantID, "api_key.revoked", "api_key", key.ID)
}

func TestPostgresAuditFailureRollsBackReplayStateChange(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	job, err := store.CreateReplay(ctx, actor.TenantID, actor.ID, app.ReplayRequest{Reason: "audit failure replay", ConfigMode: app.ReplayConfigCurrent})
	if err != nil {
		t.Fatal(err)
	}
	poisonNextPostgresAuditSequence(t, ctx, store, actor.TenantID)

	if _, err := store.PauseReplayJob(ctx, actor.TenantID, job.ID, actor.ID, "audit failure injection"); err == nil {
		t.Fatal("expected audit-chain failure to abort replay pause")
	}
	var state string
	if err := store.pool.QueryRow(ctx, `SELECT state FROM replay_jobs WHERE tenant_id=$1 AND id=$2`, actor.TenantID, job.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "scheduled" {
		t.Fatalf("replay state change must roll back when audit evidence fails, got state %q", state)
	}
	assertPostgresNoAuditEvent(t, ctx, store, actor.TenantID, "replay.paused", "replay_job", job.ID)
}

func assertPostgresNotFound(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("expected wrong-tenant lookup to return not found, got %v", err)
	}
}

func expectPostgresSQLFailure(t *testing.T, err error, operation string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected SQL constraint failure for %s", operation)
	}
}

func assertPostgresConfigVersion(t *testing.T, ctx context.Context, store *Store, tenantID, resourceType, resourceID string) {
	t.Helper()
	var count int
	if err := store.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM config_versions
		WHERE tenant_id=$1 AND resource_type=$2 AND resource_id=$3`,
		tenantID, resourceType, resourceID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatalf("expected config version for %s/%s", resourceType, resourceID)
	}
}

func assertPostgresAuditEvent(t *testing.T, ctx context.Context, store *Store, tenantID, action, resource, resourceID string) {
	t.Helper()
	var count int
	if err := store.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM audit_events
		WHERE tenant_id=$1 AND action=$2 AND resource=$3 AND resource_id=$4`,
		tenantID, action, resource, resourceID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatalf("expected audit event %s for %s/%s", action, resource, resourceID)
	}
}

func assertPostgresNoAuditEvent(t *testing.T, ctx context.Context, store *Store, tenantID, action, resource, resourceID string) {
	t.Helper()
	var count int
	if err := store.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM audit_events
		WHERE tenant_id=$1 AND action=$2 AND resource=$3 AND resource_id=$4`,
		tenantID, action, resource, resourceID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected no audit event %s for %s/%s, got %d", action, resource, resourceID, count)
	}
}

func containsPostgresAuthSession(sessions []domain.AuthSession, id, state string) bool {
	for _, session := range sessions {
		if session.ID == id && session.State == state {
			return true
		}
	}
	return false
}

func containsPostgresIncident(incidents []domain.Incident, id, state string) bool {
	for _, incident := range incidents {
		if incident.ID == id && incident.State == state {
			return true
		}
	}
	return false
}

func containsPostgresEvent(events []domain.Event, id string) bool {
	for _, event := range events {
		if event.ID == id {
			return true
		}
	}
	return false
}

func findPostgresDelivery(deliveries []domain.Delivery, id string) (domain.Delivery, bool) {
	for _, delivery := range deliveries {
		if delivery.ID == id {
			return delivery, true
		}
	}
	return domain.Delivery{}, false
}

func findPostgresDeliveryForEvent(t *testing.T, deliveries []domain.Delivery, eventID string) domain.Delivery {
	t.Helper()
	for _, delivery := range deliveries {
		if delivery.EventID == eventID {
			return delivery
		}
	}
	t.Fatalf("expected delivery for event %s, got %+v", eventID, deliveries)
	return domain.Delivery{}
}

func findPostgresOutboxItem(t *testing.T, items []worker.OutboxItem, kind, resourceID string) worker.OutboxItem {
	t.Helper()
	for _, item := range items {
		if item.Kind == kind && item.ResourceID == resourceID {
			return item
		}
	}
	t.Fatalf("expected outbox item kind=%s resource_id=%s, got %+v", kind, resourceID, items)
	return worker.OutboxItem{}
}

func containsPostgresTimelineKind(timeline []app.EventTimelineEntry, kind string) bool {
	for _, item := range timeline {
		if item.Kind == kind {
			return true
		}
	}
	return false
}

func findPostgresDeadLetterEntry(entries []map[string]any, deliveryID string) string {
	for _, entry := range entries {
		id, _ := entry["id"].(string)
		entryDeliveryID, _ := entry["delivery_id"].(string)
		state, _ := entry["state"].(string)
		if id != "" && entryDeliveryID == deliveryID && state == "open" {
			return id
		}
	}
	return ""
}

func containsPostgresAuditAction(events []domain.AuditEvent, action string) bool {
	for _, event := range events {
		if event.Action == action {
			return true
		}
	}
	return false
}

func containsPostgresAuditChainAnchor(anchors []domain.AuditChainAnchor, id string, toSequence int64) bool {
	for _, anchor := range anchors {
		if anchor.ID == id && anchor.ToSequence == toSequence {
			return true
		}
	}
	return false
}

func containsPostgresRetentionPolicy(policies []domain.RetentionPolicy, id, resourceType, state string) bool {
	for _, policy := range policies {
		if policy.ID == id && policy.ResourceType == resourceType && policy.State == state {
			return true
		}
	}
	return false
}

func containsPostgresReplayApprovalPolicy(policies []domain.ReplayApprovalPolicy, id, state string) bool {
	for _, policy := range policies {
		if policy.ID == id && policy.State == state {
			return true
		}
	}
	return false
}

func containsPostgresReplayJob(jobs []app.ReplayJob, id, state string) bool {
	for _, job := range jobs {
		if job.ID == id && job.State == state {
			return true
		}
	}
	return false
}

func containsPostgresProviderAdapter(adapters []domain.ProviderAdapter, id, state string) bool {
	for _, adapter := range adapters {
		if adapter.ID == id && adapter.State == state {
			return true
		}
	}
	return false
}

func containsPostgresAdapterVersion(versions []domain.AdapterVersion, id, state string) bool {
	for _, version := range versions {
		if version.ID == id && version.State == state {
			return true
		}
	}
	return false
}

func containsPostgresProviderConnection(connections []domain.ProviderConnection, id, state string) bool {
	for _, connection := range connections {
		if connection.ID == id && connection.State == state {
			return true
		}
	}
	return false
}

func containsPostgresReconciliationJob(jobs []domain.ReconciliationJob, id, state string) bool {
	for _, job := range jobs {
		if job.ID == id && job.State == state {
			return true
		}
	}
	return false
}

func assertPostgresNoOutboxItem(t *testing.T, ctx context.Context, store *Store, tenantID, kind, resourceID string) {
	t.Helper()
	var count int
	if err := store.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM outbox
		WHERE tenant_id=$1 AND kind=$2 AND resource_id=$3 AND state <> 'completed'`,
		tenantID, kind, resourceID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected no active outbox item kind=%s resource_id=%s, got %d", kind, resourceID, count)
	}
}

func containsPostgresProducerClient(clients []domain.ProducerClient, id, state string) bool {
	for _, client := range clients {
		if client.ID == id && client.State == state {
			return true
		}
	}
	return false
}

func containsPostgresProducerMTLSIdentity(identities []domain.ProducerMTLSIdentity, id, state string) bool {
	for _, identity := range identities {
		if identity.ID == id && identity.State == state {
			return true
		}
	}
	return false
}

func containsPostgresSource(sources []domain.Source, id, state string) bool {
	for _, source := range sources {
		if source.ID == id && source.State == state {
			return true
		}
	}
	return false
}

func containsPostgresEndpoint(endpoints []domain.Endpoint, id, state string) bool {
	for _, endpoint := range endpoints {
		if endpoint.ID == id && endpoint.State == state {
			return true
		}
	}
	return false
}

func containsPostgresSubscription(subscriptions []domain.Subscription, id, state string) bool {
	for _, subscription := range subscriptions {
		if subscription.ID == id && subscription.State == state {
			return true
		}
	}
	return false
}

func containsPostgresRoute(routes []domain.Route, id, state string) bool {
	for _, route := range routes {
		if route.ID == id && route.State == state {
			return true
		}
	}
	return false
}

func containsPostgresRetryPolicy(policies []domain.RetryPolicy, id, state string) bool {
	for _, policy := range policies {
		if policy.ID == id && policy.State == state {
			return true
		}
	}
	return false
}

func containsPostgresAlertRule(rules []domain.AlertRule, id, state string) bool {
	for _, rule := range rules {
		if rule.ID == id && rule.State == state {
			return true
		}
	}
	return false
}

func containsPostgresMetricRollup(rollups []domain.MetricRollup, tenantID, metricName string) bool {
	for _, rollup := range rollups {
		if rollup.TenantID == tenantID && rollup.MetricName == metricName {
			return true
		}
	}
	return false
}

func containsPostgresMetricRollupValue(rollups []domain.MetricRollup, tenantID, metricName string, value float64) bool {
	for _, rollup := range rollups {
		if rollup.TenantID == tenantID && rollup.MetricName == metricName && rollup.Value == value {
			return true
		}
	}
	return false
}

func findPostgresAlertFiringForRule(t *testing.T, firings []domain.AlertFiring, ruleID string) domain.AlertFiring {
	t.Helper()
	for _, firing := range firings {
		if firing.RuleID == ruleID {
			return firing
		}
	}
	t.Fatalf("expected alert firing for rule %s, got %+v", ruleID, firings)
	return domain.AlertFiring{}
}

func containsPostgresNotificationChannel(channels []domain.NotificationChannel, id, state string) bool {
	for _, channel := range channels {
		if channel.ID == id && channel.State == state {
			return true
		}
	}
	return false
}

func containsPostgresNotificationDelivery(deliveries []domain.NotificationDelivery, id, state string) bool {
	for _, delivery := range deliveries {
		if delivery.ID == id && delivery.State == state {
			return true
		}
	}
	return false
}

func containsPostgresNotificationTransition(deliveries []domain.NotificationDelivery, firingID, transition string) bool {
	for _, delivery := range deliveries {
		if delivery.FiringID == firingID && delivery.Transition == transition {
			return true
		}
	}
	return false
}

func containsPostgresSIEMSink(sinks []domain.SIEMSink, id, state string) bool {
	for _, sink := range sinks {
		if sink.ID == id && sink.State == state {
			return true
		}
	}
	return false
}

func containsPostgresSIEMDelivery(deliveries []domain.SIEMDelivery, id, state string) bool {
	for _, delivery := range deliveries {
		if delivery.ID == id && delivery.State == state {
			return true
		}
	}
	return false
}

func findPostgresSignalDeliveryItem(t *testing.T, items []worker.SignalDeliveryItem, id string) worker.SignalDeliveryItem {
	t.Helper()
	for _, item := range items {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("expected claimed signal delivery %s, got %s", id, postgresSignalDeliveryIDs(items))
	return worker.SignalDeliveryItem{}
}

func findPostgresSignalDeliveryForTenant(t *testing.T, items []worker.SignalDeliveryItem, tenantID string) worker.SignalDeliveryItem {
	t.Helper()
	for _, item := range items {
		if item.TenantID == tenantID {
			return item
		}
	}
	t.Fatalf("expected claimed signal delivery for tenant %s, got %s", tenantID, postgresSignalDeliveryIDs(items))
	return worker.SignalDeliveryItem{}
}

func postgresSignalDeliveryIDs(items []worker.SignalDeliveryItem) string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID+"@"+item.TenantID)
	}
	return strings.Join(ids, ",")
}

func containsPostgresEventType(types []domain.EventType, name, state string) bool {
	for _, eventType := range types {
		if eventType.Name == name && eventType.State == state {
			return true
		}
	}
	return false
}

func containsPostgresEventSchema(schemas []domain.EventSchema, id, state string) bool {
	for _, schema := range schemas {
		if schema.ID == id && schema.State == state {
			return true
		}
	}
	return false
}

func containsPostgresTransformation(transformations []domain.Transformation, id, state string) bool {
	for _, transformation := range transformations {
		if transformation.ID == id && transformation.State == state {
			return true
		}
	}
	return false
}

func containsPostgresTransformationVersion(versions []domain.TransformationVersion, id, state string) bool {
	for _, version := range versions {
		if version.ID == id && version.State == state {
			return true
		}
	}
	return false
}

func containsPostgresIdentityProvider(idps []domain.IdentityProvider, id, state string) bool {
	for _, idp := range idps {
		if idp.ID == id && idp.State == state {
			return true
		}
	}
	return false
}

func containsPostgresSCIMToken(tokens []domain.SCIMToken, id, state string) bool {
	for _, token := range tokens {
		if token.ID == id && token.State == state {
			return true
		}
	}
	return false
}

func containsPostgresSCIMUser(users []app.SCIMUser, id string, active bool) bool {
	for _, user := range users {
		if user.ID == id && user.Active == active {
			return true
		}
	}
	return false
}

func containsPostgresSCIMGroup(groups []app.SCIMGroup, id string, active bool) bool {
	for _, group := range groups {
		if group.ID == id && group.Active == active {
			return true
		}
	}
	return false
}

func containsPostgresRoleBinding(bindings []domain.RoleBinding, id, state string) bool {
	for _, binding := range bindings {
		if binding.ID == id && binding.State == state {
			return true
		}
	}
	return false
}

func containsPostgresAccessPolicyRule(rules []domain.AccessPolicyRule, id, state string) bool {
	for _, rule := range rules {
		if rule.ID == id && rule.State == state {
			return true
		}
	}
	return false
}

func poisonNextPostgresAuditSequence(t *testing.T, ctx context.Context, store *Store, tenantID string) {
	t.Helper()
	var maxSequence int64
	if err := store.pool.QueryRow(ctx, `SELECT COALESCE(max(sequence), 0) FROM audit_chain_entries WHERE tenant_id=$1`, tenantID).Scan(&maxSequence); err != nil {
		t.Fatal(err)
	}
	nextSequence := maxSequence + 1
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO audit_chain_heads(tenant_id, sequence, chain_hash)
		VALUES($1,$2,'sha256:poison-head')
		ON CONFLICT (tenant_id) DO UPDATE SET sequence=EXCLUDED.sequence, chain_hash=EXCLUDED.chain_hash`,
		tenantID, nextSequence-1,
	); err != nil {
		t.Fatal(err)
	}
	suffix := strings.NewReplacer(".", "_", ":", "_").Replace(time.Now().UTC().Format("150405.000000000"))
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO audit_chain_entries(id, tenant_id, sequence, audit_event_id, event_hash, previous_chain_hash, chain_hash,
			canonicalization_version, source, state, created_at)
		VALUES($1,$2,$3,$4,'sha256:poison-event','sha256:poison-head','sha256:poison-chain','audit-chain-v1','live','active',now())`,
		"ace_it_poison_"+suffix, tenantID, nextSequence, "aud_it_poison_"+suffix,
	); err != nil {
		t.Fatal(err)
	}
}

func openPostgresIntegrationStore(t *testing.T) (context.Context, *Store, authz.Actor) {
	t.Helper()
	databaseURL := os.Getenv("WEBHOOKERY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("WEBHOOKERY_TEST_DATABASE_URL is required to prove live Postgres tenant predicates, transactions, locks, outbox, replay, export, and migration behavior")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	migrationsDir := filepath.Join("..", "..", "..", "migrations")
	if err := MigrateUp(ctx, databaseURL, migrationsDir); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	box, err := crypto.NewEnvelope(key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(ctx, databaseURL, box)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UTC().Format("150405.000000000")
	actor := authz.Actor{ID: "usr_it_" + suffix, TenantID: "ten_it_" + suffix, Role: authz.RoleOwner, Scopes: []string{"*"}}
	if _, err := store.CreateAPIKey(ctx, app.APIKeyCreateInput{
		Key: domain.APIKey{
			TenantID: actor.TenantID,
			UserID:   actor.ID,
			Name:     "integration owner",
			Prefix:   "it-owner",
			Last4:    "test",
			Hash:     app.HashToken("integration-owner-" + suffix),
			Scopes:   []string{"*"},
			State:    domain.StateActive,
		},
		Role:    authz.RoleOwner,
		ActorID: actor.ID,
	}); err != nil {
		t.Fatal(err)
	}
	return ctx, store, actor
}

func createPostgresIntegrationRoute(t *testing.T, ctx context.Context, control *app.ControlService, actor authz.Actor, eventType string) (domain.Source, domain.Endpoint) {
	t.Helper()
	source, err := control.CreateSource(ctx, actor, app.CreateSourceRequest{Name: "integration source", Provider: "stripe", Adapter: "stripe", VerificationSecret: "whsec_it"})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, _, err := control.CreateEndpoint(ctx, actor, app.CreateEndpointRequest{Name: "integration endpoint", URL: "https://receiver.example.com/webhook"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.CreateRoute(ctx, actor, app.CreateRouteRequest{SourceID: source.ID, Name: "integration route", Priority: 10, EventTypes: []string{eventType}, EndpointID: endpoint.ID, State: domain.StateActive}); err != nil {
		t.Fatal(err)
	}
	return source, endpoint
}

func ingestPostgresIntegrationEvent(t *testing.T, ctx context.Context, store *Store, actor authz.Actor, sourceID, eventType, providerID string, now time.Time) app.IngestResult {
	t.Helper()
	body := []byte(`{"id":"` + providerID + `","type":"` + eventType + `","account":"acct_it"}`)
	result, err := app.NewIngestService(store, fixedIntegrationClock{now: now}).Ingest(ctx, app.IngestRequest{
		TenantID:    actor.TenantID,
		SourceID:    sourceID,
		Provider:    "stripe",
		RawBody:     body,
		Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: verifier.TimestampedHeader("v1", now, []byte("whsec_it"), body)}},
		ContentType: "application/json",
		RemoteIP:    "198.51.100.20",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || result.EventID == "" {
		t.Fatalf("expected accepted integration event, got %+v", result)
	}
	return result
}

type fixedIntegrationClock struct {
	now time.Time
}

func (c fixedIntegrationClock) Now() time.Time {
	return c.now
}

func readTestTarGzipFiles(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		files[header.Name] = data
	}
	return files
}

func sortedTestMapKeys[V any](items map[string]V) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func testPostgresClientCertificatePEM(t *testing.T, commonName string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func decodeTestJSONLines(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	var out []map[string]any
	for {
		var item map[string]any
		err := dec.Decode(&item)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, item)
	}
	return out
}
