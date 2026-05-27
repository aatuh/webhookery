package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"webhookery/internal/app"
	"webhookery/internal/domain"
	"webhookery/internal/problem"

	"github.com/go-chi/chi/v5"
)

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListEvents(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetEvent(r.Context(), actorFrom(r), chi.URLParam(r, "event_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) getRawPayload(w http.ResponseWriter, r *http.Request) {
	raw, err := s.cfg.Control.GetRawPayload(r.Context(), actorFrom(r), chi.URLParam(r, "event_id"), r.URL.Query().Get("reason"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"event_id":         raw.EventID,
		"raw_payload_hash": raw.SHA256,
		"content_type":     raw.ContentType,
		"size_bytes":       raw.SizeBytes,
		"storage_backend":  raw.StorageBackend,
		"storage_status":   raw.StorageStatus,
		"body_base64":      base64.StdEncoding.EncodeToString(raw.Body),
	})
}

func (s *Server) getNormalizedEvent(w http.ResponseWriter, r *http.Request) {
	includeData := strings.EqualFold(r.URL.Query().Get("include_data"), "true")
	item, err := s.cfg.Control.GetNormalizedEvent(r.Context(), actorFrom(r), chi.URLParam(r, "event_id"), includeData)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) getEventTimeline(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListEventTimeline(r.Context(), actorFrom(r), chi.URLParam(r, "event_id"), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) ingestProductEvent(w http.ResponseWriter, r *http.Request) {
	body, ok := readLimitedBody(w, r, maxIngressBodyBytes)
	if !ok {
		return
	}
	sourceID := productSourceID(body)
	if sourceID == "" {
		writeProblem(w, problem.BadRequest(requestID(r), "validation_error", "Product event body must include source_id."))
		return
	}
	actor := actorFrom(r)
	if actor.SourceID != "" && actor.SourceID != sourceID {
		writeProblem(w, problem.Forbidden(requestID(r)))
		return
	}
	result, err := s.cfg.Ingest.Ingest(r.Context(), app.IngestRequest{
		TenantID:    actor.TenantID,
		SourceID:    sourceID,
		Provider:    "internal",
		RawBody:     body,
		Headers:     headers(r.Header),
		ContentType: r.Header.Get("Content-Type"),
		RemoteIP:    r.RemoteAddr,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func productSourceID(raw []byte) string {
	var req struct {
		SourceID string `json:"source_id"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return ""
	}
	return strings.TrimSpace(req.SourceID)
}

func (s *Server) ingestGeneric(w http.ResponseWriter, r *http.Request) {
	body, ok := readLimitedBody(w, r, maxIngressBodyBytes)
	if !ok {
		return
	}
	result, err := s.cfg.Ingest.Ingest(r.Context(), app.IngestRequest{
		TenantID:    chi.URLParam(r, "tenant_id"),
		SourceID:    chi.URLParam(r, "source_id"),
		Provider:    "generic-hmac",
		RawBody:     body,
		Headers:     headers(r.Header),
		ContentType: r.Header.Get("Content-Type"),
		RemoteIP:    r.RemoteAddr,
	})
	s.writeIngestResult(w, r, result, err)
}

func (s *Server) ingestGenericOrProvider(w http.ResponseWriter, r *http.Request) {
	firstSegment := chi.URLParam(r, "tenant_id")
	if documentedProviderPath(firstSegment) {
		s.ingestProviderName(w, r, firstSegment)
		return
	}
	s.ingestGeneric(w, r)
}

func (s *Server) ingestProviderName(w http.ResponseWriter, r *http.Request, providerName string) {
	body, ok := readLimitedBody(w, r, maxIngressBodyBytes)
	if !ok {
		return
	}
	result, err := s.cfg.Ingest.IngestProviderPath(r.Context(), providerName, chi.URLParam(r, "source_id"), app.IngestRequest{
		Provider:    providerName,
		RawBody:     body,
		Headers:     headers(r.Header),
		ContentType: r.Header.Get("Content-Type"),
		RemoteIP:    r.RemoteAddr,
	})
	if err == nil && result.Accepted && strings.EqualFold(providerName, "slack") {
		if challenge := slackChallenge(body); challenge != "" {
			writeJSON(w, http.StatusOK, map[string]string{"challenge": challenge})
			return
		}
	}
	s.writeIngestResult(w, r, result, err)
}

func documentedProviderPath(providerName string) bool {
	switch strings.ToLower(providerName) {
	case "stripe", "github", "shopify", "slack", "cloudevents", "generic-jwt":
		return true
	default:
		return false
	}
}

func slackChallenge(raw []byte) string {
	var payload struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ""
	}
	if payload.Type != "url_verification" {
		return ""
	}
	return strings.TrimSpace(payload.Challenge)
}

func (s *Server) writeIngestResult(w http.ResponseWriter, r *http.Request, result app.IngestResult, err error) {
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if !result.Accepted {
		writeProblem(w, problem.New(http.StatusUnauthorized, "invalid_signature", "Invalid webhook signature", "Webhook evidence was captured, but the signature did not verify.", requestID(r), false))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"received": true, "event_id": result.EventID, "duplicate": result.DedupeStatus != domain.DedupeUnique})
}
