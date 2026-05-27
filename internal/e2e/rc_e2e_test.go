package e2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"webhookery/internal/adapters/crypto"
	"webhookery/internal/adapters/deliveryhttp"
	"webhookery/internal/adapters/postgres"
	"webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/blobstore"
	"webhookery/internal/domain"
	"webhookery/internal/evidence"
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

func (c *recordingDeliveryClient) Deliver(ctx context.Context, rawURL string, body []byte, secret []byte, keyID string, keyVersion int, _, _ []byte) (worker.DeliveryResult, error) {
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
	}).BuildRequest(ctx, rawURL, body)
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
	createRCActorMembership(t, ctx, store, otherTenant)
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

func TestRCE2EEvidenceLifecycleRetentionExportAndPermissionGates(t *testing.T) {
	ctx, store, actor := openRCStore(t)
	defer store.Close()

	oldNow := time.Now().UTC().AddDate(0, 0, -2).Truncate(time.Second)
	control := app.NewControlService(store, ssrf.Validator{Resolver: rcResolver})
	source, _ := createRCRoute(t, ctx, control, actor, "stripe", "stripe", "payment_intent.succeeded")
	body := []byte(`{"id":"evt_rc_evidence_` + testSuffix(t) + `","type":"payment_intent.succeeded","account":"acct_rc","data":{"object":{"id":"pi_rc"}}}`)

	ingest := app.NewIngestService(store, fixedClock{now: oldNow})
	result, err := ingest.Ingest(ctx, app.IngestRequest{
		TenantID:    actor.TenantID,
		SourceID:    source.ID,
		Provider:    "stripe",
		RawBody:     body,
		Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: verifier.TimestampedHeader("v1", oldNow, []byte("whsec_rc"), body)}},
		ContentType: "application/json",
		RemoteIP:    "198.51.100.14",
	})
	if err != nil {
		t.Fatalf("ingest evidence lifecycle event: %v", err)
	}
	runWorkerOnce(t, ctx, store, &recordingDeliveryClient{
		t:   t,
		now: oldNow.Add(time.Second),
		result: worker.DeliveryResult{
			StatusCode:   http.StatusAccepted,
			ResponseBody: []byte("ok"),
			FailureClass: "success",
		},
	}, "rc-evidence-"+testSuffix(t))

	reader := authz.Actor{ID: "usr_reader_" + testSuffix(t), TenantID: actor.TenantID, Role: authz.RoleSupport}
	createRCActorMembership(t, ctx, store, reader)
	if _, err := control.GetRawPayload(ctx, reader, result.EventID); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("expected raw payload read without events:raw to be forbidden, got %v", err)
	}
	if _, err := control.GetNormalizedEvent(ctx, reader, result.EventID, true); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("expected normalized data read without events:raw to be forbidden, got %v", err)
	}
	metadataOnly, err := control.GetNormalizedEvent(ctx, reader, result.EventID, false)
	if err != nil {
		t.Fatalf("metadata-only normalized event read should be allowed: %v", err)
	}
	if len(metadataOnly.Data) != 0 || metadataOnly.EnvelopeSHA256 == "" || metadataOnly.MetadataSHA256 == "" {
		t.Fatalf("expected metadata-only normalized event with hashes and no data body: %+v", metadataOnly)
	}
	raw, err := control.GetRawPayload(ctx, actor, result.EventID)
	if err != nil {
		t.Fatalf("owner raw payload read before retention: %v", err)
	}
	if string(raw.Body) != string(body) || raw.SHA256 == "" {
		t.Fatalf("expected raw body and hash before retention: %+v", raw)
	}

	auditOnly := authz.Actor{ID: "usr_audit_" + testSuffix(t), TenantID: actor.TenantID, Role: authz.RoleAuditor, Scopes: []string{"audit:read"}}
	createRCActorMembership(t, ctx, store, auditOnly)
	if _, err := control.CreateAuditExport(ctx, auditOnly, app.CreateAuditExportRequest{IncludePayloadBodies: true, Reason: "forbidden payload export"}); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("expected payload-inclusive export without events:raw to be forbidden, got %v", err)
	}

	if _, err := control.CreateRetentionPolicy(ctx, actor, app.CreateRetentionPolicyRequest{ResourceType: domain.RetentionResourceRawPayload, RetentionDays: 1, State: domain.StateActive}); err != nil {
		t.Fatalf("create raw retention policy: %v", err)
	}
	if _, err := control.CreateRetentionPolicy(ctx, actor, app.CreateRetentionPolicyRequest{ResourceType: domain.RetentionResourceNormalized, RetentionDays: 1, State: domain.StateActive}); err != nil {
		t.Fatalf("create normalized retention policy: %v", err)
	}
	if err := store.ApplyRetentionPolicies(ctx, "rc-retention-"+testSuffix(t), 20); err != nil {
		t.Fatalf("apply retention policies: %v", err)
	}
	if _, err := control.GetRawPayload(ctx, actor, result.EventID); !errors.Is(err, app.ErrGone) {
		t.Fatalf("expected retained raw payload body to be gone, got %v", err)
	}
	retainedMetadata, err := control.GetNormalizedEvent(ctx, reader, result.EventID, false)
	if err != nil {
		t.Fatalf("metadata-only normalized event should survive retention: %v", err)
	}
	if retainedMetadata.StorageStatus != domain.StorageStatusDeleted || retainedMetadata.EnvelopeSHA256 == "" || retainedMetadata.DataSHA256 == "" {
		t.Fatalf("expected retained normalized metadata and hashes: %+v", retainedMetadata)
	}
	if _, err := control.GetNormalizedEvent(ctx, actor, result.EventID, true); !errors.Is(err, app.ErrGone) {
		t.Fatalf("expected retained normalized data body to be gone, got %v", err)
	}

	export, err := control.CreateAuditExport(ctx, actor, app.CreateAuditExportRequest{
		IncludeRawPayloads:   true,
		IncludeTimelines:     true,
		IncludePayloadBodies: true,
		Reason:               "RC evidence export drill",
	})
	if err != nil {
		t.Fatalf("create body-inclusive audit export: %v", err)
	}
	if export.ID == "" || export.State != domain.EvidenceExportStateReady || export.SHA256 == "" || export.ManifestSHA256 == "" {
		t.Fatalf("expected ready export with hashes: %+v", export)
	}
	if _, err := control.DownloadAuditExport(ctx, auditOnly, export.ID); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("expected raw-restricted actor to be unable to download body-inclusive export, got %v", err)
	}
	download, err := control.DownloadAuditExport(ctx, actor, export.ID)
	if err != nil {
		t.Fatalf("download body-inclusive audit export: %v", err)
	}
	verification, err := evidence.VerifyTarGzipBundle(download.Body)
	if err != nil {
		t.Fatalf("verify downloaded audit export bundle: %v", err)
	}
	if !verification.Valid || verification.CheckedFiles == 0 || verification.CheckedChainEntries == 0 {
		t.Fatalf("expected valid bundle with file hashes and chain proof: %+v", verification)
	}
	chain, err := control.VerifyAuditChain(ctx, actor, app.AuditChainVerifyRequest{})
	if err != nil {
		t.Fatalf("verify audit chain after retention/export: %v", err)
	}
	if !chain.Valid || chain.CheckedEntries == 0 {
		t.Fatalf("expected valid audit chain after retention/export: %+v", chain)
	}
}

func TestRCE2EStorageFailureDrillsRejectInboundSuccess(t *testing.T) {
	ctx, store, actor := openRCStore(t)
	now := time.Date(2026, 5, 26, 15, 0, 0, 0, time.UTC)
	control := app.NewControlService(store, ssrf.Validator{Resolver: rcResolver})
	source, _ := createRCRoute(t, ctx, control, actor, "stripe", "stripe", "setup_intent.created")
	store.Close()

	body := []byte(`{"id":"evt_rc_db_down_` + testSuffix(t) + `","type":"setup_intent.created","account":"acct_rc"}`)
	ingest := app.NewIngestService(store, fixedClock{now: now})
	dbDownResult, err := ingest.Ingest(ctx, app.IngestRequest{
		TenantID:    actor.TenantID,
		SourceID:    source.ID,
		Provider:    "stripe",
		RawBody:     body,
		Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: verifier.TimestampedHeader("v1", now, []byte("whsec_rc"), body)}},
		ContentType: "application/json",
		RemoteIP:    "198.51.100.15",
	})
	if err == nil {
		t.Fatalf("expected DB-down ingest to fail before acceptance: %+v", dbDownResult)
	}
	if dbDownResult.Accepted || dbDownResult.EventID != "" || dbDownResult.RawPayloadID != "" {
		t.Fatalf("DB-down ingest must not return accepted durable ids: %+v", dbDownResult)
	}
	if leaksSensitiveValue(err.Error(), "whsec_rc", string(body)) {
		t.Fatalf("DB-down error leaked secret or raw body: %v", err)
	}

	ctx, s3Store, s3Actor := openRCStoreWithOptions(t, postgres.StoreOptions{
		RawStorageMode: domain.RawStorageS3,
		ObjectStore:    &failingBlobStore{putErr: errors.New("backend failure with whsec_rc and " + string(body))},
		ObjectBucket:   "rc-test-bucket",
	})
	defer s3Store.Close()
	s3Control := app.NewControlService(s3Store, ssrf.Validator{Resolver: rcResolver})
	s3Source, _ := createRCRoute(t, ctx, s3Control, s3Actor, "stripe", "stripe", "setup_intent.created")
	s3Ingest := app.NewIngestService(s3Store, fixedClock{now: now})
	s3Result, err := s3Ingest.Ingest(ctx, app.IngestRequest{
		TenantID:    s3Actor.TenantID,
		SourceID:    s3Source.ID,
		Provider:    "stripe",
		RawBody:     body,
		Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: verifier.TimestampedHeader("v1", now, []byte("whsec_rc"), body)}},
		ContentType: "application/json",
		RemoteIP:    "198.51.100.16",
	})
	if err == nil {
		t.Fatalf("expected S3 object write failure to block inbound success: %+v", s3Result)
	}
	if s3Result.Accepted || s3Result.EventID != "" || s3Result.RawPayloadID != "" {
		t.Fatalf("S3 failure must not return accepted durable ids: %+v", s3Result)
	}
	if leaksSensitiveValue(err.Error(), "whsec_rc", string(body)) {
		t.Fatalf("S3 storage error leaked secret or raw body: %v", err)
	}
}

func TestRCE2EFailedPaymentWebhookIncidentPacketDemo(t *testing.T) {
	outputDir := os.Getenv("WEBHOOKERY_DEMO_OUTPUT_DIR")
	if outputDir == "" {
		t.Skip("WEBHOOKERY_DEMO_OUTPUT_DIR is required to write demo artifacts")
	}
	ctx, store, actor := openRCStore(t)
	defer store.Close()

	now := time.Date(2026, 5, 26, 16, 0, 0, 0, time.UTC)
	control := app.NewControlService(store, ssrf.Validator{Resolver: rcResolver})
	retryPolicy, err := control.CreateRetryPolicy(ctx, actor, app.CreateRetryPolicyRequest{
		Name:                "Demo single attempt",
		MaxAttempts:         1,
		MaxDurationSeconds:  60,
		InitialDelaySeconds: 1,
		MaxDelaySeconds:     1,
		State:               domain.StateActive,
	})
	if err != nil {
		t.Fatalf("create demo retry policy: %v", err)
	}
	source, endpoint := createRCRouteWithOptions(t, ctx, control, actor, "stripe", "stripe", "invoice.paid", rcRouteOptions{RetryPolicyID: retryPolicy.ID})
	body := []byte(`{"id":"evt_demo_payment_` + testSuffix(t) + `","type":"invoice.paid","account":"acct_demo","data":{"object":{"id":"in_demo","customer":"cus_demo"}}}`)

	ingest := app.NewIngestService(store, fixedClock{now: now})
	result, err := ingest.Ingest(ctx, app.IngestRequest{
		TenantID:    actor.TenantID,
		SourceID:    source.ID,
		Provider:    "stripe",
		RawBody:     body,
		Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: verifier.TimestampedHeader("v1", now, []byte("whsec_rc"), body)}},
		ContentType: "application/json",
		RemoteIP:    "198.51.100.20",
	})
	if err != nil {
		t.Fatalf("ingest demo payment event: %v", err)
	}
	if !result.Accepted {
		t.Fatalf("expected demo event to be accepted after durable capture: %+v", result)
	}

	failingDelivery := &recordingDeliveryClient{
		t:   t,
		now: now.Add(time.Second),
		result: worker.DeliveryResult{
			StatusCode:   http.StatusInternalServerError,
			ResponseBody: []byte("demo receiver is down"),
			FailureClass: "temporary_http",
		},
	}
	runWorkerOnce(t, ctx, store, failingDelivery, "demo-fail-"+testSuffix(t))
	if len(failingDelivery.calls) != 1 {
		t.Fatalf("expected one failed downstream delivery, got %d", len(failingDelivery.calls))
	}
	deadLetters, err := control.ListDeadLetter(ctx, actor, 20)
	if err != nil {
		t.Fatalf("list demo dead letters: %v", err)
	}
	dlqEntryID := findMapID(deadLetters, "event_id", result.EventID)
	if dlqEntryID == "" {
		t.Fatalf("expected demo event %s to enter DLQ: %+v", result.EventID, deadLetters)
	}

	incident, err := control.CreateIncident(ctx, actor, app.CreateIncidentRequest{
		Title:  "Stripe payment webhook failed",
		Reason: "local demo failure/replay investigation",
	})
	if err != nil {
		t.Fatalf("create demo incident: %v", err)
	}
	if _, err := control.AddIncidentEvent(ctx, actor, incident.ID, app.AddIncidentEventRequest{
		EventID: result.EventID,
		Reason:  "attach failed payment webhook evidence",
	}); err != nil {
		t.Fatalf("attach demo event to incident: %v", err)
	}

	replayJob, err := control.ReleaseDeadLetter(ctx, actor, dlqEntryID, app.DeadLetterReleaseRequest{Reason: "receiver fixed during local evidence demo"})
	if err != nil {
		t.Fatalf("release demo DLQ entry: %v", err)
	}
	recoveredName := "Demo receiver recovered"
	if _, _, err := control.UpdateEndpoint(ctx, actor, endpoint.ID, app.UpdateEndpointRequest{Name: &recoveredName, Reason: "receiver fixed during local evidence demo"}); err != nil {
		t.Fatalf("record demo endpoint recovery: %v", err)
	}
	resetDemoEndpointCircuit(t, ctx, actor.TenantID, endpoint.ID)
	successDelivery := &recordingDeliveryClient{
		t:   t,
		now: now.Add(2 * time.Second),
		result: worker.DeliveryResult{
			StatusCode:   http.StatusAccepted,
			ResponseBody: []byte("ok"),
			FailureClass: "success",
		},
	}
	runWorkerUntilDeliveryCalls(t, ctx, store, successDelivery, "demo-replay-"+testSuffix(t), 1, 3)
	if len(successDelivery.calls) == 0 {
		t.Fatalf("expected at least one successful replay delivery, got %d", len(successDelivery.calls))
	}
	deadLetters, err = control.ListDeadLetter(ctx, actor, 20)
	if err != nil {
		t.Fatalf("list released demo dead letters: %v", err)
	}
	if !containsMapState(deadLetters, dlqEntryID, "released") {
		t.Fatalf("expected demo DLQ entry to be released: %+v", deadLetters)
	}

	report, err := control.GenerateIncidentReport(ctx, actor, incident.ID, app.IncidentReportRequest{Reason: "generate local demo incident packet"})
	if err != nil {
		t.Fatalf("generate demo incident report: %v", err)
	}
	assertDemoReportSections(t, report.Markdown)
	_, export, err := control.CreateIncidentEvidenceExport(ctx, actor, incident.ID, app.CreateIncidentEvidenceExportRequest{Reason: "export local demo incident packet"})
	if err != nil {
		t.Fatalf("create demo incident evidence export: %v", err)
	}
	download, err := control.DownloadAuditExport(ctx, actor, export.ID)
	if err != nil {
		t.Fatalf("download demo incident evidence export: %v", err)
	}
	verification, err := evidence.VerifyTarGzipBundle(download.Body)
	if err != nil {
		t.Fatalf("verify demo evidence bundle: %v", err)
	}
	if !verification.Valid || verification.CheckedFiles == 0 {
		t.Fatalf("expected valid demo evidence bundle: %+v", verification)
	}
	writeDemoPacketOutput(t, outputDir, actor.TenantID, incident, result.EventID, dlqEntryID, replayJob, report, download, verification)
}

func TestRCE2EObjectReadFailuresAreRedacted(t *testing.T) {
	blob := &flakyBlobStore{}
	ctx, store, actor := openRCStoreWithOptions(t, postgres.StoreOptions{
		RawStorageMode: domain.RawStorageS3,
		ObjectStore:    blob,
		ObjectBucket:   "bucket-secret",
	})
	defer store.Close()

	now := time.Date(2026, 5, 26, 18, 0, 0, 0, time.UTC)
	control := app.NewControlService(store, ssrf.Validator{Resolver: rcResolver})
	source, _ := createRCRoute(t, ctx, control, actor, "stripe", "stripe", "invoice.object_read")
	body := []byte(`{"id":"evt_rc_object_read_` + testSuffix(t) + `","type":"invoice.object_read","data":{"object":{"id":"in_read"}}}`)
	result, err := app.NewIngestService(store, fixedClock{now: now}).Ingest(ctx, app.IngestRequest{
		TenantID:    actor.TenantID,
		SourceID:    source.ID,
		Provider:    "stripe",
		RawBody:     body,
		Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: verifier.TimestampedHeader("v1", now, []byte("whsec_rc"), body)}},
		ContentType: "application/json",
		RemoteIP:    "198.51.100.10",
	})
	if err != nil {
		t.Fatalf("ingest object-backed event: %v", err)
	}
	blob.getErr = errors.New("backend timeout for bucket-secret/raw-payloads with raw body " + string(body))
	if _, err := control.GetRawPayload(ctx, actor, result.EventID); err == nil || leaksSensitiveValue(err.Error(), "bucket-secret", string(body), "raw-payloads") {
		t.Fatalf("object raw read failure must be redacted, got %v", err)
	}

	blob.getErr = nil
	export, err := control.CreateAuditExport(ctx, actor, app.CreateAuditExportRequest{IncludeTimelines: true, Reason: "object read failure drill"})
	if err != nil {
		t.Fatalf("create object-backed audit export: %v", err)
	}
	blob.getErr = errors.New("backend timeout for bucket-secret/evidence-export object key")
	if _, err := control.DownloadAuditExport(ctx, actor, export.ID); err == nil || leaksSensitiveValue(err.Error(), "bucket-secret", "evidence-export") {
		t.Fatalf("object export read failure must be redacted, got %v", err)
	}
}

func TestRCRestoreDrill(t *testing.T) {
	sourceDatabaseURL := os.Getenv("WEBHOOKERY_TEST_DATABASE_URL")
	restoreDatabaseURL := os.Getenv("WEBHOOKERY_RESTORE_DRILL_DATABASE_URL")
	if sourceDatabaseURL == "" || restoreDatabaseURL == "" {
		t.Skip("WEBHOOKERY_TEST_DATABASE_URL and WEBHOOKERY_RESTORE_DRILL_DATABASE_URL are required")
	}
	if sourceDatabaseURL == restoreDatabaseURL {
		t.Fatal("restore drill database URL must point to a separate disposable database")
	}
	if _, err := exec.LookPath("pg_dump"); err != nil {
		t.Fatalf("pg_dump is required for restore drill: %v", err)
	}
	if _, err := exec.LookPath("pg_restore"); err != nil {
		t.Fatalf("pg_restore is required for restore drill: %v", err)
	}

	ctx, store, actor := openRCStore(t)
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	control := app.NewControlService(store, ssrf.Validator{Resolver: rcResolver})
	source, _ := createRCRoute(t, ctx, control, actor, "stripe", "stripe", "checkout.session.completed")
	body := []byte(`{"id":"evt_rc_restore_` + testSuffix(t) + `","type":"checkout.session.completed","account":"acct_rc"}`)
	ingest := app.NewIngestService(store, fixedClock{now: now})
	result, err := ingest.Ingest(ctx, app.IngestRequest{
		TenantID:    actor.TenantID,
		SourceID:    source.ID,
		Provider:    "stripe",
		RawBody:     body,
		Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: verifier.TimestampedHeader("v1", now, []byte("whsec_rc"), body)}},
		ContentType: "application/json",
		RemoteIP:    "198.51.100.17",
	})
	if err != nil {
		t.Fatalf("ingest restore drill event: %v", err)
	}
	runWorkerOnce(t, ctx, store, &recordingDeliveryClient{
		t:   t,
		now: now.Add(time.Second),
		result: worker.DeliveryResult{
			StatusCode:   http.StatusAccepted,
			ResponseBody: []byte("ok"),
			FailureClass: "success",
		},
	}, "rc-restore-"+testSuffix(t))
	export, err := control.CreateAuditExport(ctx, actor, app.CreateAuditExportRequest{IncludeTimelines: true, Reason: "RC restore drill export"})
	if err != nil {
		t.Fatalf("create restore drill export: %v", err)
	}
	before, err := control.VerifyAuditChain(ctx, actor, app.AuditChainVerifyRequest{})
	if err != nil {
		t.Fatalf("verify source audit chain before backup: %v", err)
	}
	if !before.Valid || before.CheckedEntries == 0 {
		t.Fatalf("expected valid source audit chain before backup: %+v", before)
	}
	store.Close()

	drillCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dumpFile := runBackupCommand(t, drillCtx, sourceDatabaseURL)
	runRestoreCommand(t, drillCtx, restoreDatabaseURL, dumpFile)
	if err := postgres.MigrateUp(drillCtx, restoreDatabaseURL, filepath.Join("..", "..", "migrations")); err != nil {
		t.Fatalf("migrate restored database: %v", err)
	}
	box := rcTestSecretBox(t)
	restored, err := postgres.New(drillCtx, restoreDatabaseURL, box)
	if err != nil {
		t.Fatalf("open restored store: %v", err)
	}
	defer restored.Close()
	restoredControl := app.NewControlService(restored, ssrf.Validator{Resolver: rcResolver})
	if _, err := restoredControl.GetEvent(drillCtx, actor, result.EventID); err != nil {
		t.Fatalf("read restored event evidence: %v", err)
	}
	download, err := restoredControl.DownloadAuditExport(drillCtx, actor, export.ID)
	if err != nil {
		t.Fatalf("download restored audit export: %v", err)
	}
	verification, err := evidence.VerifyTarGzipBundle(download.Body)
	if err != nil {
		t.Fatalf("verify restored audit export bundle: %v", err)
	}
	if !verification.Valid || verification.CheckedFiles == 0 || verification.CheckedChainEntries == 0 {
		t.Fatalf("expected readable restored audit export with chain proof: %+v", verification)
	}
	after, err := restoredControl.VerifyAuditChain(drillCtx, actor, app.AuditChainVerifyRequest{})
	if err != nil {
		t.Fatalf("verify restored audit chain: %v", err)
	}
	if !after.Valid || after.EndChainHash != before.EndChainHash {
		t.Fatalf("restored audit chain mismatch before=%+v after=%+v", before, after)
	}
}

func openRCStore(t *testing.T) (context.Context, *postgres.Store, authz.Actor) {
	t.Helper()
	return openRCStoreWithOptions(t, postgres.StoreOptions{RawStorageMode: domain.RawStoragePostgres})
}

func openRCStoreWithOptions(t *testing.T, opts postgres.StoreOptions) (context.Context, *postgres.Store, authz.Actor) {
	t.Helper()
	databaseURL := os.Getenv("WEBHOOKERY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("WEBHOOKERY_TEST_DATABASE_URL is required for RC E2E tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	migrationsDir := filepath.Join("..", "..", "migrations")
	if err := postgres.MigrateUp(ctx, databaseURL, migrationsDir); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	clearPriorRCE2EWork(t, ctx, databaseURL)
	box := rcTestSecretBox(t)
	store, err := postgres.NewWithOptions(ctx, databaseURL, box, opts)
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
	if _, err := store.CreateAPIKey(ctx, app.APIKeyCreateInput{
		Key: domain.APIKey{
			TenantID: actor.TenantID,
			UserID:   actor.ID,
			Name:     "RC E2E owner",
			Prefix:   "rc-e2e",
			Last4:    "test",
			Hash:     app.HashToken("rc-e2e-" + suffix),
			Scopes:   []string{"*"},
			State:    domain.StateActive,
		},
		Role:    authz.RoleOwner,
		ActorID: actor.ID,
	}); err != nil {
		t.Fatalf("create RC E2E actor membership: %v", err)
	}
	return ctx, store, actor
}

func createRCActorMembership(t *testing.T, ctx context.Context, store *postgres.Store, actor authz.Actor) {
	t.Helper()
	suffix := testSuffix(t) + "_" + strings.ReplaceAll(actor.ID, "-", "_")
	scopes := actor.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	if _, err := store.CreateAPIKey(ctx, app.APIKeyCreateInput{
		Key: domain.APIKey{
			TenantID: actor.TenantID,
			UserID:   actor.ID,
			Name:     "RC E2E actor " + actor.ID,
			Prefix:   "rc-e2e",
			Last4:    "test",
			Hash:     app.HashToken("rc-e2e-" + suffix),
			Scopes:   scopes,
			State:    domain.StateActive,
		},
		Role:    actor.Role,
		ActorID: actor.ID,
	}); err != nil {
		t.Fatalf("create RC E2E actor membership for %s: %v", actor.ID, err)
	}
}

func clearPriorRCE2EWork(t *testing.T, ctx context.Context, databaseURL string) {
	t.Helper()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open cleanup pool: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `UPDATE outbox SET state='completed', locked_by=NULL, lock_expires_at=NULL WHERE (tenant_id LIKE 'ten_rc_%' OR tenant_id LIKE 'ten_it_%') AND state <> 'completed'`); err != nil {
		t.Fatalf("clear prior RC outbox work: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE deliveries SET state='canceled', locked_by=NULL, lock_expires_at=NULL WHERE (tenant_id LIKE 'ten_rc_%' OR tenant_id LIKE 'ten_it_%') AND state IN ('scheduled','in_progress')`); err != nil {
		t.Fatalf("clear prior RC delivery work: %v", err)
	}
}

func rcTestSecretBox(t *testing.T) crypto.Envelope {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	box, err := crypto.NewEnvelope(key)
	if err != nil {
		t.Fatalf("create test envelope: %v", err)
	}
	return box
}

func runBackupCommand(t *testing.T, ctx context.Context, sourceDatabaseURL string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, filepath.Join("..", "..", "scripts", "backup_postgres.sh"), t.TempDir())
	cmd.Env = append(os.Environ(), "WEBHOOKERY_DATABASE_URL="+sourceDatabaseURL)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("backup command failed: %v", err)
	}
	dumpFile := strings.TrimSpace(string(output))
	if dumpFile == "" {
		t.Fatal("backup command did not return a dump file path")
	}
	if _, err := os.Stat(dumpFile); err != nil {
		t.Fatalf("backup dump file is not readable: %v", err)
	}
	return dumpFile
}

func runRestoreCommand(t *testing.T, ctx context.Context, restoreDatabaseURL, dumpFile string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, filepath.Join("..", "..", "scripts", "restore_postgres.sh"), dumpFile)
	cmd.Env = append(os.Environ(), "WEBHOOKERY_DATABASE_URL="+restoreDatabaseURL, "WEBHOOKERY_RESTORE_CONFIRM=restore")
	if err := cmd.Run(); err != nil {
		t.Fatalf("restore command failed: %v", err)
	}
}

type failingBlobStore struct {
	putErr error
}

func (s *failingBlobStore) Put(context.Context, blobstore.Object, []byte) error {
	return s.putErr
}

func (s *failingBlobStore) Get(context.Context, string, string) ([]byte, error) {
	return nil, blobstore.ErrNotFound
}

func (s *failingBlobStore) Delete(context.Context, string, string) error {
	return nil
}

type flakyBlobStore struct {
	objects map[string][]byte
	getErr  error
}

func (s *flakyBlobStore) Put(_ context.Context, object blobstore.Object, body []byte) error {
	if s.objects == nil {
		s.objects = map[string][]byte{}
	}
	s.objects[object.Bucket+"/"+object.Key] = append([]byte(nil), body...)
	return nil
}

func (s *flakyBlobStore) Get(_ context.Context, bucket, key string) ([]byte, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	body, ok := s.objects[bucket+"/"+key]
	if !ok {
		return nil, blobstore.ErrNotFound
	}
	return append([]byte(nil), body...), nil
}

func (s *flakyBlobStore) Delete(_ context.Context, bucket, key string) error {
	delete(s.objects, bucket+"/"+key)
	return nil
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
	fanout := app.NewDeliveryFanoutService(store, fixedClock{now: time.Now().UTC()})
	reconciliation := app.NewReconciliationService(store, nil)
	processor := app.NewOutboxProcessorService(fanout, reconciliation)
	err := (worker.Worker{
		Store:          store,
		Processor:      processor,
		DeliveryStore:  store,
		DeliveryClient: delivery,
		WorkerID:       workerID,
		Limit:          20,
	}).RunOnce(ctx)
	if err != nil {
		t.Fatalf("run worker once: %v", err)
	}
}

func runWorkerUntilDeliveryCalls(t *testing.T, ctx context.Context, store *postgres.Store, delivery *recordingDeliveryClient, workerID string, wantCalls, maxRuns int) {
	t.Helper()
	for i := 0; i < maxRuns && len(delivery.calls) < wantCalls; i++ {
		runWorkerOnce(t, ctx, store, delivery, fmt.Sprintf("%s-%d", workerID, i+1))
	}
}

func resetDemoEndpointCircuit(t *testing.T, ctx context.Context, tenantID, endpointID string) {
	t.Helper()
	databaseURL := os.Getenv("WEBHOOKERY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("WEBHOOKERY_TEST_DATABASE_URL is required to reset demo endpoint circuit")
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open demo endpoint reset pool: %v", err)
	}
	defer pool.Close()
	tag, err := pool.Exec(ctx, `UPDATE endpoints SET circuit_state='closed', failure_count=0, disabled_until=NULL WHERE tenant_id=$1 AND id=$2`, tenantID, endpointID)
	if err != nil {
		t.Fatalf("reset demo endpoint circuit: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("expected to reset one demo endpoint circuit, reset %d", tag.RowsAffected())
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

func leaksSensitiveValue(text string, values ...string) bool {
	for _, value := range values {
		if value != "" && strings.Contains(text, value) {
			return true
		}
	}
	return false
}

func assertDemoReportSections(t *testing.T, markdown string) {
	t.Helper()
	for _, section := range []string{
		"## 1. Summary",
		"## 2. Event Identity",
		"## 3. Provider Verification",
		"## 4. Raw Capture Evidence",
		"## 5. Route And Configuration Snapshot",
		"## 6. Delivery Attempt Timeline",
		"## 7. Retry And DLQ State",
		"## 8. Replay History",
		"## 9. Retention And Raw-Payload Access State",
		"## 10. Audit-Chain Proof References",
		"## 11. Known Gaps And Non-Claims",
	} {
		if !strings.Contains(markdown, section) {
			t.Fatalf("demo incident report missing section %q", section)
		}
	}
	for _, text := range []string{
		"Inbound capture does not prove downstream business success.",
		"does not claim exactly-once delivery",
		"whcp audit verify-bundle --file evidence.tar.gz",
	} {
		if !strings.Contains(markdown, text) {
			t.Fatalf("demo incident report missing non-claim or verification text %q", text)
		}
	}
}

func writeDemoPacketOutput(t *testing.T, outputDir, tenantID string, incident domain.Incident, eventID, dlqEntryID string, replayJob app.ReplayJob, report domain.IncidentReportSnapshot, download app.EvidenceExportDownload, verification evidence.BundleVerification) {
	t.Helper()
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		t.Fatalf("create demo output directory: %v", err)
	}
	manifestBytes := readDemoBundleFile(t, download.Body, "manifest.json")
	var manifest evidence.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode demo evidence manifest: %v", err)
	}
	writeDemoBytes(t, filepath.Join(outputDir, "incident-report.md"), []byte(report.Markdown))
	writeDemoJSON(t, filepath.Join(outputDir, "incident-report.json"), sanitizedDemoReportJSON(t, report.Report, tenantID))
	writeDemoJSON(t, filepath.Join(outputDir, "evidence-manifest.json"), map[string]any{
		"schema_version":          "webhookery.demo_evidence_manifest.v1",
		"source_manifest_sha256":  evidence.SHA256(manifestBytes),
		"bundle_sha256":           download.Export.SHA256,
		"export_id":               manifest.ExportID,
		"tenant_id_hash":          domain.HashSHA256([]byte(manifest.TenantID)),
		"created_at":              manifest.CreatedAt,
		"include_raw_payloads":    manifest.IncludeRawPayloads,
		"include_payload_bodies":  manifest.IncludePayloadBodies,
		"include_timelines":       manifest.IncludeTimelines,
		"files":                   manifest.Files,
		"redaction_policy":        "raw payload bodies, webhook secrets, provider signatures, bearer tokens, private keys, and tenant identifiers are omitted or hashed in demo-visible files",
		"local_verification_file": "verify-output.json",
		"non_claims": []string{
			"Inbound capture does not prove downstream business success.",
			"Webhookery records at-least-once delivery evidence and does not claim exactly-once delivery.",
			"The local demo does not prove provider-side completeness or provider certification.",
		},
	})
	writeDemoJSON(t, filepath.Join(outputDir, "verify-output.json"), map[string]any{
		"schema_version": "webhookery.demo_verify_output.v1",
		"command":        "whcp audit verify-bundle --file evidence.tar.gz",
		"bundle_sha256":  download.Export.SHA256,
		"result":         verification,
	})
	writeDemoBytes(t, filepath.Join(outputDir, "evidence.tar.gz"), download.Body)
	writeDemoBytes(t, filepath.Join(outputDir, "README.md"), []byte(demoPacketREADME(incident, eventID, dlqEntryID, replayJob, download.Export)))
	assertDemoPacketOutputRedacted(t, outputDir)
}

func sanitizedDemoReportJSON(t *testing.T, raw json.RawMessage, tenantID string) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decode demo incident report: %v", err)
	}
	return redactDemoValue(value, tenantID)
}

func redactDemoValue(value any, tenantID string) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			lower := strings.ToLower(key)
			switch {
			case lower == "tenant_id":
				out["tenant_id_hash"] = domain.HashSHA256([]byte(fmt.Sprint(item)))
			case lower == "raw_body":
				out[key] = "omitted"
			case lower == "body" || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "authorization") || strings.Contains(lower, "signature_header") || strings.Contains(lower, "signature_value"):
				out[key] = "[redacted]"
			default:
				out[key] = redactDemoValue(item, tenantID)
			}
		}
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, redactDemoValue(item, tenantID))
		}
		return out
	case string:
		if v == tenantID {
			return domain.HashSHA256([]byte(v))
		}
		return v
	default:
		return value
	}
}

func readDemoBundleFile(t *testing.T, body []byte, name string) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("open demo evidence bundle: %v", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read demo evidence bundle: %v", err)
		}
		if header.Name != name {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read demo bundle file %s: %v", name, err)
		}
		return data
	}
	t.Fatalf("demo evidence bundle missing %s", name)
	return nil
}

func writeDemoJSON(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal demo output %s: %v", path, err)
	}
	body = append(body, '\n')
	writeDemoBytes(t, path, body)
}

func writeDemoBytes(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write demo output %s: %v", path, err)
	}
}

func demoPacketREADME(incident domain.Incident, eventID, dlqEntryID string, replayJob app.ReplayJob, export domain.EvidenceExport) string {
	return fmt.Sprintf(`# Failed Payment Webhook Evidence Packet

This folder was generated by `+"`examples/webhook-evidence-demo/run.sh`"+`.

## Scenario

1. A synthetic Stripe-style `+"`invoice.paid`"+` webhook was signed with a local test secret and ingested by Webhookery.
2. Webhookery durably captured the event before returning success.
3. The downstream receiver returned HTTP 500, so the delivery attempt failed and the event entered DLQ.
4. The operator released the DLQ entry after the receiver was fixed.
5. Replay created new delivery work linked to the original event, and replay delivery succeeded.
6. Webhookery generated an incident report and a local evidence bundle.

## Local IDs

- Incident: `+"`%s`"+`
- Event: `+"`%s`"+`
- DLQ entry: `+"`%s`"+`
- Replay job: `+"`%s`"+`
- Evidence export: `+"`%s`"+`

These IDs are local disposable demo identifiers. Tenant identifiers are hashed in human-visible demo files.

## Files

- `+"`incident-report.md`"+`: support/SRE-readable report.
- `+"`incident-report.json`"+`: sanitized JSON report.
- `+"`evidence-manifest.json`"+`: sanitized manifest summary for the generated bundle.
- `+"`verify-output.json`"+`: local bundle verification result. A successful demo has `+"`result.valid: true`"+`.
- `+"`evidence.tar.gz`"+`: generated local evidence bundle used for verification.

## What This Proves

- Inbound success followed durable capture in the local PostgreSQL-backed test path.
- The downstream failure, DLQ transition, replay, and successful replay delivery are visible as evidence.
- The evidence bundle hash and included file hashes verify locally.

## What This Does Not Prove

- It does not prove provider-side completeness or Stripe certification.
- It does not prove downstream business success.
- It does not claim exactly-once delivery or global ordering.
- It does not replace restore drills, deployment review, or live-provider proof.

## Safety

The demo output omits raw payload bodies, webhook secrets, provider signature headers, bearer tokens, private keys, and database URLs. Do not replace the synthetic fixture with real customer data for screenshots, issues, support packets, or launch materials.
`, incident.ID, eventID, dlqEntryID, replayJob.ID, export.ID)
}

func assertDemoPacketOutputRedacted(t *testing.T, outputDir string) {
	t.Helper()
	for _, name := range []string{"incident-report.md", "incident-report.json", "evidence-manifest.json", "verify-output.json", "README.md"} {
		body, err := os.ReadFile(filepath.Join(outputDir, name)) // #nosec G304 -- test reads files it just wrote under an explicit demo output directory.
		if err != nil {
			t.Fatalf("read demo output %s: %v", name, err)
		}
		for _, marker := range []string{"whsec_rc", "acct_demo", "cus_demo", "in_demo", "Stripe-Signature", "v1="} {
			if strings.Contains(string(body), marker) {
				t.Fatalf("demo output %s leaked sensitive marker %q", name, marker)
			}
		}
	}
}

func testSuffix(t *testing.T) string {
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	return name + "_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
}
