package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"webhookery/internal/app"
	"webhookery/internal/domain"

	"github.com/jackc/pgx/v5"
)

func (s *Store) CaptureInbound(ctx context.Context, input app.CaptureInboundInput) (app.CaptureInboundResult, error) {
	eventID := mustID("evt")
	rawID := mustID("raw")
	receiptID := mustID("rcp")
	outboxID := mustID("out")
	storage, bodyForDB, err := s.prepareRawPayloadStorage(ctx, input.Source.TenantID, rawID, input.RawPayload)
	if err != nil {
		return app.CaptureInboundResult{}, err
	}
	objectWritten := storage.backend == domain.RawStorageS3
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, storage.bucket, storage.key)
		}
		return app.CaptureInboundResult{}, err
	}
	defer rollback(ctx, tx)

	if _, err := tx.Exec(ctx, "INSERT INTO tenants(id, name) VALUES($1, $1) ON CONFLICT (id) DO NOTHING", input.Source.TenantID); err != nil {
		return app.CaptureInboundResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO raw_payloads(id, tenant_id, sha256, content_type, size_bytes, body, storage_backend, object_bucket, object_key, storage_status, created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		rawID, input.Source.TenantID, input.RawPayload.SHA256, input.RawPayload.ContentType, input.RawPayload.SizeBytes, bodyForDB,
		storage.backend, storage.bucket, storage.key, domain.StorageStatusStored, input.RawPayload.CreatedAt,
	); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, storage.bucket, storage.key)
		}
		return app.CaptureInboundResult{}, err
	}

	if input.Event.Type == "" {
		input.Event.Type = "unknown"
	}
	dedupeStatus := domain.DedupeUnique
	var insertedEventID string
	err = tx.QueryRow(ctx, `
		INSERT INTO events(id, tenant_id, source_id, provider, type, provider_event_id, raw_payload_id, raw_payload_hash,
			signature_verified, verification_reason, dedupe_key, dedupe_status, received_at, trace_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (tenant_id, dedupe_key) DO NOTHING
		RETURNING id`,
		eventID, input.Source.TenantID, input.Source.ID, input.Source.Provider, input.Event.Type, input.Event.ProviderID,
		rawID, input.RawPayload.SHA256, input.VerificationOK, input.VerifyReason, input.Event.DedupeKey, dedupeStatus,
		input.Event.ReceivedAt, input.Event.TraceID,
	).Scan(&insertedEventID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return app.CaptureInboundResult{}, err
	}
	if insertedEventID == "" {
		dedupeStatus = domain.DedupeDuplicateSuppressed
		err = tx.QueryRow(ctx, `
			SELECT id
			FROM events
			WHERE tenant_id=$1 AND dedupe_key=$2`,
			input.Source.TenantID, input.Event.DedupeKey,
		).Scan(&eventID)
		if err != nil {
			return app.CaptureInboundResult{}, err
		}
	} else {
		eventID = insertedEventID
		if len(input.Normalized.Envelope) > 0 {
			adapterVersionID, err := s.lookupAdapterVersionID(ctx, tx, firstNonEmpty(input.Source.Adapter, input.Source.Provider))
			if err != nil {
				return app.CaptureInboundResult{}, err
			}
			normalizedID := mustID("nenv")
			if _, err := tx.Exec(ctx, `
				INSERT INTO normalized_envelopes(id, tenant_id, event_id, adapter_version_id, provider, provider_event_id, type, source, subject,
					envelope_json, data_json, metadata_json, envelope_sha256, data_sha256, metadata_sha256, storage_status, created_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12::jsonb,$13,$14,$15,$16,$17)`,
				normalizedID, input.Source.TenantID, eventID, adapterVersionID, input.Normalized.Provider, input.Normalized.ProviderEventID,
				input.Normalized.Type, input.Normalized.Source, input.Normalized.Subject, string(input.Normalized.Envelope),
				string(input.Normalized.Data), string(input.Normalized.Metadata), input.Normalized.EnvelopeSHA256, input.Normalized.DataSHA256,
				input.Normalized.MetadataSHA256, domain.StorageStatusStored, input.Normalized.CreatedAt,
			); err != nil {
				return app.CaptureInboundResult{}, err
			}
		}
		payload, _ := json.Marshal(map[string]any{"event_id": eventID})
		if _, err := tx.Exec(ctx, `INSERT INTO outbox(id, tenant_id, kind, resource_id, payload) VALUES($1,$2,$3,$4,$5)`, outboxID, input.Source.TenantID, app.OutboxKindRouteEvent, eventID, payload); err != nil {
			return app.CaptureInboundResult{}, err
		}
	}

	if _, err := tx.Exec(ctx, `UPDATE raw_payloads SET event_id=$1 WHERE id=$2`, eventID, rawID); err != nil {
		return app.CaptureInboundResult{}, err
	}

	headersJSON, err := json.Marshal(input.Receipt.RawHeaders)
	if err != nil {
		return app.CaptureInboundResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO provider_receipts(id, tenant_id, source_id, event_id, raw_payload_id, raw_headers, remote_ip, verification_ok, verification_reason, received_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		receiptID, input.Source.TenantID, input.Source.ID, eventID, rawID, headersJSON, input.Receipt.RemoteIP,
		input.VerificationOK, input.VerifyReason, input.Receipt.ReceivedAt,
	); err != nil {
		return app.CaptureInboundResult{}, err
	}
	if input.Event.DedupeKey != "" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO idempotency_records(tenant_id, dedupe_key, resource_type, resource_id, status_code)
			VALUES($1,$2,'event',$3,202)
			ON CONFLICT (tenant_id, dedupe_key) DO NOTHING`,
			input.Source.TenantID, input.Event.DedupeKey, eventID,
		); err != nil {
			return app.CaptureInboundResult{}, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO dedupe_records(tenant_id, source_id, dedupe_key, first_event_id, last_receipt_id, status)
			VALUES($1,$2,$3,$4,$5,$6)
			ON CONFLICT (tenant_id, dedupe_key) DO UPDATE
			SET last_receipt_id=EXCLUDED.last_receipt_id, status=EXCLUDED.status, last_seen_at=now()`,
			input.Source.TenantID, input.Source.ID, input.Event.DedupeKey, eventID, receiptID, dedupeStatus,
		); err != nil {
			return app.CaptureInboundResult{}, err
		}
	}
	if !input.VerificationOK {
		if _, err := tx.Exec(ctx, `INSERT INTO quarantine_entries(id, tenant_id, event_id, reason) VALUES($1,$2,$3,$4)`, mustID("qua"), input.Source.TenantID, eventID, input.VerifyReason); err != nil {
			return app.CaptureInboundResult{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, storage.bucket, storage.key)
		}
		return app.CaptureInboundResult{}, err
	}
	return app.CaptureInboundResult{EventID: eventID, ReceiptID: receiptID, RawPayloadID: rawID, DedupeStatus: dedupeStatus}, nil
}
