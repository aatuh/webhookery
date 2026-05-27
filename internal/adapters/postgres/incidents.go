package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"webhookery/internal/app"
	"webhookery/internal/blobstore"
	"webhookery/internal/domain"
	"webhookery/internal/evidence"
)

func (s *Store) CreateIncident(ctx context.Context, incident domain.Incident) (domain.Incident, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Incident{}, err
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, "INSERT INTO tenants(id, name) VALUES($1, $1) ON CONFLICT (id) DO NOTHING", incident.TenantID); err != nil {
		return domain.Incident{}, err
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO incidents(id, tenant_id, title, reason, state, created_by)
		VALUES($1,$2,$3,$4,$5,$6)
		RETURNING id, tenant_id, title, reason, state, created_by, created_at, updated_at`,
		incident.ID, incident.TenantID, incident.Title, incident.Reason, incident.State, incident.CreatedBy,
	).Scan(&incident.ID, &incident.TenantID, &incident.Title, &incident.Reason, &incident.State, &incident.CreatedBy, &incident.CreatedAt, &incident.UpdatedAt)
	if err != nil {
		return domain.Incident{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: incident.TenantID, ActorID: incident.CreatedBy, Action: "incident.created", Resource: "incident", ResourceID: incident.ID, Reason: incident.Reason}); err != nil {
		return domain.Incident{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Incident{}, err
	}
	return incident, nil
}

func (s *Store) ListIncidents(ctx context.Context, tenantID string, limit int) ([]domain.Incident, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, title, reason, state, created_by, created_at, updated_at
		FROM incidents
		WHERE tenant_id=$1
		ORDER BY created_at DESC, id DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Incident
	for rows.Next() {
		item, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetIncident(ctx context.Context, tenantID, incidentID string) (domain.Incident, error) {
	item, err := scanIncident(s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, title, reason, state, created_by, created_at, updated_at
		FROM incidents
		WHERE tenant_id=$1 AND id=$2`, tenantID, incidentID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Incident{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) AddIncidentEvent(ctx context.Context, tenantID, incidentID, eventID, actorID, reason string) (domain.IncidentEvent, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.IncidentEvent{}, err
	}
	defer rollback(ctx, tx)
	if err := requireIncidentEventTenant(ctx, tx, tenantID, incidentID, eventID); err != nil {
		return domain.IncidentEvent{}, err
	}
	id := mustID("ine")
	item, err := scanIncidentEvent(tx.QueryRow(ctx, `
		INSERT INTO incident_events(id, tenant_id, incident_id, event_id, added_by, reason)
		VALUES($1,$2,$3,$4,$5,$6)
		ON CONFLICT (tenant_id, incident_id, event_id)
		DO UPDATE SET added_by=EXCLUDED.added_by, reason=EXCLUDED.reason
		RETURNING id, tenant_id, incident_id, event_id, added_by, reason, created_at`,
		id, tenantID, incidentID, eventID, actorID, reason))
	if err != nil {
		return domain.IncidentEvent{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "incident.event_added", Resource: "incident", ResourceID: incidentID, Reason: reason}); err != nil {
		return domain.IncidentEvent{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.IncidentEvent{}, err
	}
	return item, nil
}

func (s *Store) RemoveIncidentEvent(ctx context.Context, tenantID, incidentID, eventID, actorID, reason string) (domain.IncidentEvent, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.IncidentEvent{}, err
	}
	defer rollback(ctx, tx)
	item, err := scanIncidentEvent(tx.QueryRow(ctx, `
		DELETE FROM incident_events
		WHERE tenant_id=$1 AND incident_id=$2 AND event_id=$3
		RETURNING id, tenant_id, incident_id, event_id, added_by, reason, created_at`,
		tenantID, incidentID, eventID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.IncidentEvent{}, app.ErrNotFound
	}
	if err != nil {
		return domain.IncidentEvent{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "incident.event_removed", Resource: "incident", ResourceID: incidentID, Reason: reason}); err != nil {
		return domain.IncidentEvent{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.IncidentEvent{}, err
	}
	return item, nil
}

func (s *Store) ListIncidentEvents(ctx context.Context, tenantID, incidentID string) ([]domain.IncidentEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, incident_id, event_id, added_by, reason, created_at
		FROM incident_events
		WHERE tenant_id=$1 AND incident_id=$2
		ORDER BY created_at ASC, id ASC`, tenantID, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.IncidentEvent
	for rows.Next() {
		item, err := scanIncidentEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) CreateIncidentReportSnapshot(ctx context.Context, tenantID, incidentID, actorID, reason string, report app.IncidentReport, markdown string) (domain.IncidentReportSnapshot, error) {
	raw, err := json.Marshal(report)
	if err != nil {
		return domain.IncidentReportSnapshot{}, err
	}
	id := mustID("irs")
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.IncidentReportSnapshot{}, err
	}
	defer rollback(ctx, tx)
	if err := requireIncident(ctx, tx, tenantID, incidentID); err != nil {
		return domain.IncidentReportSnapshot{}, err
	}
	var out domain.IncidentReportSnapshot
	err = tx.QueryRow(ctx, `
		INSERT INTO incident_report_snapshots(id, tenant_id, incident_id, schema_version, report_json, report_markdown, generated_by)
		VALUES($1,$2,$3,$4,$5::jsonb,$6,$7)
		RETURNING id, tenant_id, incident_id, schema_version, report_json, report_markdown, generated_by, generated_at`,
		id, tenantID, incidentID, report.SchemaVersion, string(raw), markdown, actorID,
	).Scan(&out.ID, &out.TenantID, &out.IncidentID, &out.SchemaVersion, &out.Report, &out.Markdown, &out.GeneratedBy, &out.GeneratedAt)
	if err != nil {
		return domain.IncidentReportSnapshot{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "incident_report.generated", Resource: "incident", ResourceID: incidentID, Reason: reason}); err != nil {
		return domain.IncidentReportSnapshot{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.IncidentReportSnapshot{}, err
	}
	return out, nil
}

func (s *Store) GetIncidentReportSnapshot(ctx context.Context, tenantID, incidentID string) (domain.IncidentReportSnapshot, error) {
	var out domain.IncidentReportSnapshot
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, incident_id, schema_version, report_json, report_markdown, generated_by, generated_at
		FROM incident_report_snapshots
		WHERE tenant_id=$1 AND incident_id=$2
		ORDER BY generated_at DESC, id DESC
		LIMIT 1`, tenantID, incidentID).
		Scan(&out.ID, &out.TenantID, &out.IncidentID, &out.SchemaVersion, &out.Report, &out.Markdown, &out.GeneratedBy, &out.GeneratedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.IncidentReportSnapshot{}, app.ErrNotFound
	}
	return out, err
}

func (s *Store) CreateIncidentEvidenceExport(ctx context.Context, tenantID, incidentID, actorID string, req app.CreateIncidentEvidenceExportRequest, report app.IncidentReport, markdown string) (domain.IncidentEvidenceExport, domain.EvidenceExport, error) {
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, err
	}
	reportJSON = append(reportJSON, '\n')
	timelineItems := make([]any, 0)
	for _, event := range report.Events {
		for _, entry := range event.Timeline {
			timelineItems = append(timelineItems, map[string]any{"event_id": event.Event.ID, "entry": entry})
		}
	}
	timelines, err := evidence.JSONLines(timelineItems)
	if err != nil {
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, err
	}
	auditEvents, err := evidence.JSONLines([]any{})
	if err != nil {
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, err
	}
	exportID := mustID("exp")
	now := time.Now().UTC()
	files := map[string][]byte{
		"audit_events.jsonl":   auditEvents,
		"incident_report.json": reportJSON,
		"incident_report.md":   []byte(markdown),
		"timelines.jsonl":      timelines,
	}
	eventIDs := make([]string, 0, len(report.Events))
	for _, event := range report.Events {
		eventIDs = append(eventIDs, event.Event.ID)
	}
	bundle, err := evidence.BuildTarGzipBundle(evidence.Manifest{
		ExportID:             exportID,
		TenantID:             tenantID,
		CreatedAt:            now,
		IncludedEvents:       eventIDs,
		IncludedIncidents:    []string{incidentID},
		IncludeRawPayloads:   false,
		IncludeTimelines:     true,
		IncludePayloadBodies: false,
	}, files)
	if err != nil {
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, err
	}
	verification, err := evidence.VerifyTarGzipBundle(bundle.Bytes)
	if err != nil {
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, err
	}
	if !verification.Valid {
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, fmt.Errorf("incident evidence export bundle verification failed: %s", strings.Join(verification.Failures, "; "))
	}
	storageBackend := domain.RawStoragePostgres
	objectBucket := ""
	objectKey := ""
	bodyForDB := bundle.Bytes
	objectWritten := false
	if s.rawStorageMode == domain.RawStorageS3 {
		storageBackend = domain.RawStorageS3
		objectBucket = s.objectBucket
		objectKey = blobstore.ExportKey(tenantID, exportID)
		if err := s.objectStore.Put(ctx, blobstore.Object{
			Bucket:      objectBucket,
			Key:         objectKey,
			ContentType: "application/gzip",
			SHA256:      bundle.BundleSHA256,
			SizeBytes:   int64(len(bundle.Bytes)),
		}, bundle.Bytes); err != nil {
			return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, err
		}
		objectWritten = true
		bodyForDB = []byte{}
	}
	manifestJSON := string(bundle.Manifest)
	filesJSON, _ := json.Marshal(bundle.Files)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
		}
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, err
	}
	defer rollback(ctx, tx)
	if err := requireIncident(ctx, tx, tenantID, incidentID); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
		}
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, err
	}
	var export domain.EvidenceExport
	err = tx.QueryRow(ctx, `
		INSERT INTO evidence_exports(id, tenant_id, state, include_raw_payloads, include_timelines, include_payload_bodies, format,
			storage_backend, object_bucket, object_key, sha256, manifest_sha256, size_bytes, bundle, manifest, file_hashes,
			created_by, completed_at)
		VALUES($1,$2,$3,false,true,false,'tar+gzip+jsonl',$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13,now())
		RETURNING id, tenant_id, state, COALESCE(from_time, 'epoch'::timestamptz), COALESCE(to_time, 'epoch'::timestamptz),
			include_raw_payloads, include_timelines, include_payload_bodies, format, storage_backend, object_bucket, object_key, sha256,
			manifest_sha256, size_bytes, error, created_by, created_at, COALESCE(completed_at, 'epoch'::timestamptz)`,
		exportID, tenantID, domain.EvidenceExportStateReady, storageBackend, objectBucket, objectKey,
		bundle.BundleSHA256, bundle.ManifestSHA256, int64(len(bundle.Bytes)), bodyForDB, manifestJSON, string(filesJSON), actorID,
	).Scan(&export.ID, &export.TenantID, &export.State, &export.From, &export.To, &export.IncludeRawPayloads, &export.IncludeTimelines, &export.IncludePayloadBodies,
		&export.Format, &export.StorageBackend, &export.ObjectBucket, &export.ObjectKey, &export.SHA256, &export.ManifestSHA256,
		&export.SizeBytes, &export.Error, &export.CreatedBy, &export.CreatedAt, &export.CompletedAt)
	if err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
		}
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, err
	}
	for _, file := range bundle.Files {
		if _, err := tx.Exec(ctx, `
			INSERT INTO evidence_export_items(id, tenant_id, export_id, resource_type, resource_id, file_name, sha256, size_bytes)
			VALUES($1,$2,$3,'export_file',$4,$5,$6,$7)`,
			mustID("exi"), tenantID, exportID, file.Name, file.Name, file.SHA256, file.SizeBytes,
		); err != nil {
			if objectWritten {
				_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
			}
			return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, err
		}
	}
	var incidentExport domain.IncidentEvidenceExport
	err = tx.QueryRow(ctx, `
		INSERT INTO incident_evidence_exports(id, tenant_id, incident_id, export_id, created_by)
		VALUES($1,$2,$3,$4,$5)
		RETURNING id, tenant_id, incident_id, export_id, created_by, created_at`,
		mustID("iex"), tenantID, incidentID, exportID, actorID,
	).Scan(&incidentExport.ID, &incidentExport.TenantID, &incidentExport.IncidentID, &incidentExport.ExportID, &incidentExport.CreatedBy, &incidentExport.CreatedAt)
	if err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
		}
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "incident_evidence_export.created", Resource: "incident", ResourceID: incidentID, Reason: req.Reason}); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
		}
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
		}
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, err
	}
	return incidentExport, normalizeEvidenceExportTimes(export), nil
}

type incidentScanner interface {
	Scan(dest ...any) error
}

func scanIncident(scanner incidentScanner) (domain.Incident, error) {
	var item domain.Incident
	err := scanner.Scan(&item.ID, &item.TenantID, &item.Title, &item.Reason, &item.State, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func scanIncidentEvent(scanner incidentScanner) (domain.IncidentEvent, error) {
	var item domain.IncidentEvent
	err := scanner.Scan(&item.ID, &item.TenantID, &item.IncidentID, &item.EventID, &item.AddedBy, &item.Reason, &item.CreatedAt)
	return item, err
}

func requireIncident(ctx context.Context, tx pgx.Tx, tenantID, incidentID string) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM incidents WHERE tenant_id=$1 AND id=$2)`, tenantID, incidentID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return app.ErrNotFound
	}
	return nil
}

func requireIncidentEventTenant(ctx context.Context, tx pgx.Tx, tenantID, incidentID, eventID string) error {
	if err := requireIncident(ctx, tx, tenantID, incidentID); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM events WHERE tenant_id=$1 AND id=$2)`, tenantID, eventID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return app.ErrNotFound
	}
	return nil
}
