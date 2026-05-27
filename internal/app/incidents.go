package app

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/random"
)

const incidentReportSchemaV1 = "webhookery.incident_report.v1"

type CreateIncidentRequest struct {
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

type AddIncidentEventRequest struct {
	EventID string `json:"event_id"`
	Reason  string `json:"reason"`
}

type IncidentReportRequest struct {
	Reason string `json:"reason"`
}

type CreateIncidentEvidenceExportRequest struct {
	Reason string `json:"reason"`
}

type IncidentReport struct {
	SchemaVersion       string                `json:"schema_version"`
	GeneratedAt         time.Time             `json:"generated_at"`
	GeneratedBy         string                `json:"generated_by"`
	Incident            domain.Incident       `json:"incident"`
	Events              []IncidentReportEvent `json:"events"`
	VerificationCommand string                `json:"verification_command"`
	NonClaims           []string              `json:"non_claims"`
}

type IncidentReportEvent struct {
	IncidentEvent        domain.IncidentEvent `json:"incident_event"`
	Event                domain.Event         `json:"event"`
	EventIdentity        map[string]any       `json:"event_identity"`
	ProviderVerification map[string]any       `json:"provider_verification"`
	RawCaptureEvidence   map[string]any       `json:"raw_capture_evidence"`
	Timeline             []EventTimelineEntry `json:"timeline"`
}

func (s *ControlService) CreateIncident(ctx context.Context, actor authz.Actor, req CreateIncidentRequest) (domain.Incident, error) {
	if !s.authorized(ctx, actor, "incidents:write", "incident", "", "") {
		return domain.Incident{}, ErrForbidden
	}
	title := strings.TrimSpace(req.Title)
	reason := strings.TrimSpace(req.Reason)
	if title == "" || reason == "" {
		return domain.Incident{}, fmt.Errorf("%w: title and reason are required", ErrInvalidInput)
	}
	id, err := random.Token("inc", 18)
	if err != nil {
		return domain.Incident{}, err
	}
	return s.store.CreateIncident(ctx, domain.Incident{
		ID:        id,
		TenantID:  actor.TenantID,
		Title:     title,
		Reason:    reason,
		State:     domain.StateActive,
		CreatedBy: actor.ID,
	})
}

func (s *ControlService) ListIncidents(ctx context.Context, actor authz.Actor, limit int) ([]domain.Incident, error) {
	if !s.authorized(ctx, actor, "incidents:read", "incident", "", "") {
		return nil, ErrForbidden
	}
	return s.store.ListIncidents(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetIncident(ctx context.Context, actor authz.Actor, incidentID string) (domain.Incident, error) {
	if !s.authorized(ctx, actor, "incidents:read", "incident", incidentID, "") {
		return domain.Incident{}, ErrForbidden
	}
	incidentID = strings.TrimSpace(incidentID)
	if incidentID == "" {
		return domain.Incident{}, fmt.Errorf("%w: incident_id is required", ErrInvalidInput)
	}
	return s.store.GetIncident(ctx, actor.TenantID, incidentID)
}

func (s *ControlService) AddIncidentEvent(ctx context.Context, actor authz.Actor, incidentID string, req AddIncidentEventRequest) (domain.IncidentEvent, error) {
	if !s.authorized(ctx, actor, "incidents:write", "incident", incidentID, "") {
		return domain.IncidentEvent{}, ErrForbidden
	}
	incidentID = strings.TrimSpace(incidentID)
	eventID := strings.TrimSpace(req.EventID)
	reason := strings.TrimSpace(req.Reason)
	if incidentID == "" || eventID == "" || reason == "" {
		return domain.IncidentEvent{}, fmt.Errorf("%w: incident_id, event_id, and reason are required", ErrInvalidInput)
	}
	if _, err := s.store.GetIncident(ctx, actor.TenantID, incidentID); err != nil {
		return domain.IncidentEvent{}, err
	}
	if _, err := s.store.GetEvent(ctx, actor.TenantID, eventID); err != nil {
		return domain.IncidentEvent{}, err
	}
	return s.store.AddIncidentEvent(ctx, actor.TenantID, incidentID, eventID, actor.ID, reason)
}

func (s *ControlService) RemoveIncidentEvent(ctx context.Context, actor authz.Actor, incidentID, eventID string, req StateChangeRequest) (domain.IncidentEvent, error) {
	if !s.authorized(ctx, actor, "incidents:write", "incident", incidentID, "") {
		return domain.IncidentEvent{}, ErrForbidden
	}
	incidentID = strings.TrimSpace(incidentID)
	eventID = strings.TrimSpace(eventID)
	reason := strings.TrimSpace(req.Reason)
	if incidentID == "" || eventID == "" || reason == "" {
		return domain.IncidentEvent{}, fmt.Errorf("%w: incident_id, event_id, and reason are required", ErrInvalidInput)
	}
	return s.store.RemoveIncidentEvent(ctx, actor.TenantID, incidentID, eventID, actor.ID, reason)
}

func (s *ControlService) GenerateIncidentReport(ctx context.Context, actor authz.Actor, incidentID string, req IncidentReportRequest) (domain.IncidentReportSnapshot, error) {
	if !s.authorized(ctx, actor, "incidents:write", "incident", incidentID, "") {
		return domain.IncidentReportSnapshot{}, ErrForbidden
	}
	if strings.TrimSpace(req.Reason) == "" {
		return domain.IncidentReportSnapshot{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	report, markdown, err := s.buildIncidentReport(ctx, actor, incidentID)
	if err != nil {
		return domain.IncidentReportSnapshot{}, err
	}
	return s.store.CreateIncidentReportSnapshot(ctx, actor.TenantID, strings.TrimSpace(incidentID), actor.ID, strings.TrimSpace(req.Reason), report, markdown)
}

func (s *ControlService) GetIncidentReport(ctx context.Context, actor authz.Actor, incidentID string) (domain.IncidentReportSnapshot, error) {
	if !s.authorized(ctx, actor, "incidents:read", "incident", incidentID, "") {
		return domain.IncidentReportSnapshot{}, ErrForbidden
	}
	incidentID = strings.TrimSpace(incidentID)
	if incidentID == "" {
		return domain.IncidentReportSnapshot{}, fmt.Errorf("%w: incident_id is required", ErrInvalidInput)
	}
	return s.store.GetIncidentReportSnapshot(ctx, actor.TenantID, incidentID)
}

func (s *ControlService) CreateIncidentEvidenceExport(ctx context.Context, actor authz.Actor, incidentID string, req CreateIncidentEvidenceExportRequest) (domain.IncidentEvidenceExport, domain.EvidenceExport, error) {
	if !s.authorized(ctx, actor, "incidents:write", "incident", incidentID, "") {
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, ErrForbidden
	}
	if !s.authorized(ctx, actor, "audit:read", "audit_export", "", "") {
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, ErrForbidden
	}
	incidentID = strings.TrimSpace(incidentID)
	req.Reason = strings.TrimSpace(req.Reason)
	if incidentID == "" || req.Reason == "" {
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, fmt.Errorf("%w: incident_id and reason are required", ErrInvalidInput)
	}
	report, markdown, err := s.buildIncidentReport(ctx, actor, incidentID)
	if err != nil {
		return domain.IncidentEvidenceExport{}, domain.EvidenceExport{}, err
	}
	return s.store.CreateIncidentEvidenceExport(ctx, actor.TenantID, incidentID, actor.ID, req, report, markdown)
}

func (s *ControlService) buildIncidentReport(ctx context.Context, actor authz.Actor, incidentID string) (IncidentReport, string, error) {
	incidentID = strings.TrimSpace(incidentID)
	if incidentID == "" {
		return IncidentReport{}, "", fmt.Errorf("%w: incident_id is required", ErrInvalidInput)
	}
	incident, err := s.store.GetIncident(ctx, actor.TenantID, incidentID)
	if err != nil {
		return IncidentReport{}, "", err
	}
	links, err := s.store.ListIncidentEvents(ctx, actor.TenantID, incidentID)
	if err != nil {
		return IncidentReport{}, "", err
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].CreatedAt.Equal(links[j].CreatedAt) {
			return links[i].EventID < links[j].EventID
		}
		return links[i].CreatedAt.Before(links[j].CreatedAt)
	})
	report := IncidentReport{
		SchemaVersion:       incidentReportSchemaV1,
		GeneratedAt:         time.Now().UTC(),
		GeneratedBy:         actor.ID,
		Incident:            incident,
		VerificationCommand: "whcp audit verify-bundle --file evidence.tar.gz",
		NonClaims: []string{
			"Inbound capture does not prove downstream business success.",
			"Webhookery records at-least-once delivery evidence and does not claim exactly-once delivery.",
			"The report proves Webhookery evidence observed locally; it does not prove provider-side completeness.",
			"Raw payload bodies, secrets, signatures, bearer tokens, and private keys are omitted by default.",
		},
	}
	for _, link := range links {
		event, err := s.store.GetEvent(ctx, actor.TenantID, link.EventID)
		if err != nil {
			return IncidentReport{}, "", err
		}
		timeline, err := s.store.ListEventTimeline(ctx, actor.TenantID, link.EventID, 500)
		if err != nil {
			return IncidentReport{}, "", err
		}
		report.Events = append(report.Events, IncidentReportEvent{
			IncidentEvent: link,
			Event:         event,
			EventIdentity: map[string]any{
				"event_id":          event.ID,
				"provider":          event.Provider,
				"type":              event.Type,
				"provider_event_id": event.ProviderID,
				"source_id":         event.SourceID,
				"tenant_id_hash":    domain.HashSHA256([]byte(event.TenantID)),
				"received_at":       event.ReceivedAt,
			},
			ProviderVerification: map[string]any{
				"signature_verified":  event.Verified,
				"verification_reason": event.VerifyReason,
				"dedupe_status":       event.DedupeStatus,
			},
			RawCaptureEvidence: map[string]any{
				"raw_payload_id":   event.RawPayloadID,
				"raw_payload_hash": event.RawPayloadHash,
				"raw_body":         "omitted",
			},
			Timeline: sanitizeTimeline(timeline),
		})
	}
	markdown := markdownIncidentReport(report)
	return report, markdown, nil
}

func sanitizeTimeline(entries []EventTimelineEntry) []EventTimelineEntry {
	out := make([]EventTimelineEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.SchemaVersion == "" {
			entry.SchemaVersion = EventTimelineSchemaV1
		}
		if strings.Contains(strings.ToLower(entry.Detail), "body=") ||
			strings.Contains(strings.ToLower(entry.Detail), "secret=") ||
			strings.Contains(strings.ToLower(entry.Detail), "signature=") ||
			strings.Contains(strings.ToLower(entry.Detail), "token=") {
			entry.Detail = "[redacted]"
		}
		out = append(out, entry)
	}
	return out
}

func markdownIncidentReport(report IncidentReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Webhookery Incident Report\n\n")
	fmt.Fprintf(&b, "Schema version: `%s`\n\n", report.SchemaVersion)
	fmt.Fprintf(&b, "Generated at: `%s`\n\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "## 1. Summary\n\n")
	fmt.Fprintf(&b, "- Incident: `%s`\n", report.Incident.ID)
	fmt.Fprintf(&b, "- Title: %s\n", markdownText(report.Incident.Title))
	fmt.Fprintf(&b, "- Reason: %s\n", markdownText(report.Incident.Reason))
	fmt.Fprintf(&b, "- Events attached: %d\n\n", len(report.Events))
	for _, event := range report.Events {
		fmt.Fprintf(&b, "## 2. Event Identity\n\n")
		fmt.Fprintf(&b, "- Event ID: `%s`\n", event.Event.ID)
		fmt.Fprintf(&b, "- Provider: `%s`\n", event.Event.Provider)
		fmt.Fprintf(&b, "- Type: `%s`\n", event.Event.Type)
		fmt.Fprintf(&b, "- Provider event ID: `%s`\n", event.Event.ProviderID)
		fmt.Fprintf(&b, "- Received at: `%s`\n\n", event.Event.ReceivedAt.Format(time.RFC3339))
		fmt.Fprintf(&b, "## 3. Provider Verification\n\n")
		fmt.Fprintf(&b, "- Signature verified: `%t`\n", event.Event.Verified)
		fmt.Fprintf(&b, "- Verification reason: `%s`\n", event.Event.VerifyReason)
		fmt.Fprintf(&b, "- Dedupe status: `%s`\n\n", event.Event.DedupeStatus)
		fmt.Fprintf(&b, "## 4. Raw Capture Evidence\n\n")
		fmt.Fprintf(&b, "- Raw payload ID: `%s`\n", event.Event.RawPayloadID)
		fmt.Fprintf(&b, "- Raw payload hash: `%s`\n", event.Event.RawPayloadHash)
		fmt.Fprintf(&b, "- Raw payload body: omitted by default\n\n")
		fmt.Fprintf(&b, "## 5. Route And Configuration Snapshot\n\n")
		writeTimelineKind(&b, event.Timeline, "delivery")
		fmt.Fprintf(&b, "## 6. Delivery Attempt Timeline\n\n")
		writeTimelineKind(&b, event.Timeline, "attempt")
		fmt.Fprintf(&b, "## 7. Retry And DLQ State\n\n")
		writeTimelineKind(&b, event.Timeline, "dead_letter")
		fmt.Fprintf(&b, "## 8. Replay History\n\n")
		writeTimelineKind(&b, event.Timeline, "replay")
		fmt.Fprintf(&b, "## 9. Retention And Raw-Payload Access State\n\n")
		writeTimelineKind(&b, event.Timeline, "raw_payload")
		fmt.Fprintf(&b, "## 10. Audit-Chain Proof References\n\n")
		writeTimelineKind(&b, event.Timeline, "audit")
	}
	fmt.Fprintf(&b, "## 11. Known Gaps And Non-Claims\n\n")
	for _, nonClaim := range report.NonClaims {
		fmt.Fprintf(&b, "- %s\n", nonClaim)
	}
	fmt.Fprintf(&b, "- Verify exported bundles with `%s`.\n", report.VerificationCommand)
	return b.String()
}

func writeTimelineKind(b *strings.Builder, timeline []EventTimelineEntry, kind string) {
	wrote := false
	for _, entry := range timeline {
		if entry.Kind != kind {
			continue
		}
		wrote = true
		fmt.Fprintf(b, "- `%s` `%s` `%s`: %s\n", entry.OccurredAt.Format(time.RFC3339), entry.RefID, entry.State, markdownText(entry.Detail))
	}
	if !wrote {
		fmt.Fprintf(b, "- No `%s` entries recorded in the event timeline.\n", kind)
	}
	fmt.Fprintln(b)
}

func markdownText(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}
