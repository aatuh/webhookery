package postgres

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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
		t.Skip("WEBHOOKERY_TEST_DATABASE_URL is required")
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
	if _, err := store.pool.Exec(ctx, `UPDATE outbox SET state='completed', locked_by=NULL, lock_expires_at=NULL WHERE tenant_id LIKE 'ten_it_%' AND state <> 'completed'`); err != nil {
		t.Fatalf("clear prior integration outbox work: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE deliveries SET state='succeeded', locked_by=NULL, lock_expires_at=NULL WHERE tenant_id LIKE 'ten_it_%' AND state IN ('scheduled','in_progress')`); err != nil {
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
		if item["kind"] == "raw_payload" {
			rawTimelineByID[item["ref_id"].(string)] = item["detail"].(string)
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
	if _, err := control.GetRawPayload(ctx, actor, first.EventID); !errors.Is(err, app.ErrGone) {
		t.Fatalf("expected retained raw body read to return gone after deletion, got %v", err)
	}
}

func TestPostgresAuditChainBackfillIsBoundedAndIdempotent(t *testing.T) {
	ctx, store, _ := openPostgresIntegrationStore(t)
	defer store.Close()

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
	channel, _, err := control.CreateNotificationChannel(ctx, actor, app.CreateNotificationChannelRequest{Name: "tenant notification", URL: "https://signals.example.com/notify", SigningSecret: "notify-secret"})
	if err != nil {
		t.Fatal(err)
	}
	alert, err := control.CreateAlertRule(ctx, actor, app.CreateAlertRuleRequest{Name: "tenant alert", RuleType: domain.AlertRuleDeadLetterOpen, Threshold: 1, ChannelIDs: []string{channel.ID}})
	if err != nil {
		t.Fatal(err)
	}
	sink, _, err := control.CreateSIEMSink(ctx, actor, app.CreateSIEMSinkRequest{Name: "tenant siem", URL: "https://signals.example.com/siem", SigningSecret: "siem-secret"})
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
	if _, err := control.UpdateRetryPolicy(ctx, actor, retryPolicy.ID, app.UpdateRetryPolicyRequest{Name: &retryName, Reason: "integration update"}); err != nil {
		t.Fatal(err)
	}
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
}

func assertPostgresNotFound(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("expected wrong-tenant lookup to return not found, got %v", err)
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

func openPostgresIntegrationStore(t *testing.T) (context.Context, *Store, authz.Actor) {
	t.Helper()
	databaseURL := os.Getenv("WEBHOOKERY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("WEBHOOKERY_TEST_DATABASE_URL is required")
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
