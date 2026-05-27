package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/problem"

	"github.com/aatuh/api-toolkit/v2/httpx/identity"
)

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	requestID := requestID(r)
	switch {
	case errors.Is(err, app.ErrUnauthorized):
		writeProblem(w, problem.Unauthorized(requestID))
	case errors.Is(err, app.ErrForbidden):
		writeProblem(w, problem.Forbidden(requestID))
	case errors.Is(err, app.ErrNotFound):
		writeProblem(w, problem.New(http.StatusNotFound, "not_found", "Not found", "The requested resource was not found.", requestID, false))
	case errors.Is(err, app.ErrGone):
		writeProblem(w, problem.New(http.StatusGone, "payload_expired", "Payload unavailable", "The requested payload body has expired or was removed by retention policy; metadata and hashes remain available.", requestID, false))
	case errors.Is(err, app.ErrInvalidInput):
		writeProblem(w, problem.BadRequest(requestID, "validation_error", err.Error()))
	default:
		writeProblem(w, problem.Internal(requestID))
	}
}

func actorFrom(r *http.Request) authz.Actor {
	actor, _ := r.Context().Value(actorContextKey{}).(authz.Actor)
	return actor
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeProblem(w, problem.BadRequest(requestID(r), "validation_error", "Invalid JSON body."))
		return false
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		writeProblem(w, problem.BadRequest(requestID(r), "validation_error", "JSON body must contain a single value."))
		return false
	}
	return true
}

func readLimitedBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		writeProblem(w, problem.BadRequest(requestID(r), "validation_error", "Could not read request body."))
		return nil, false
	}
	if int64(len(body)) > max {
		writeProblem(w, problem.New(http.StatusRequestEntityTooLarge, "payload_too_large", "Payload too large", "The webhook payload exceeds the configured limit.", requestID(r), false))
		return nil, false
	}
	return body, true
}

func rejectOversizedHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requestHeadersWithinLimits(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestHeadersWithinLimits(w http.ResponseWriter, r *http.Request) bool {
	var pairs int
	var total int
	for name, values := range r.Header {
		if len(values) == 0 {
			pairs++
			total += len(name)
			if pairs > maxHeaderPairs || total > maxHeaderBytes {
				writeProblem(w, problem.New(http.StatusRequestHeaderFieldsTooLarge, "headers_too_large", "Headers too large", "The request headers exceed the configured limit.", requestID(r), false))
				return false
			}
			continue
		}
		for _, value := range values {
			pairs++
			total += len(name) + len(value)
			if len(value) > maxHeaderValueBytes || pairs > maxHeaderPairs || total > maxHeaderBytes {
				writeProblem(w, problem.New(http.StatusRequestHeaderFieldsTooLarge, "headers_too_large", "Headers too large", "The request headers exceed the configured limit.", requestID(r), false))
				return false
			}
		}
	}
	return true
}

func headers(h http.Header) []domain.HeaderPair {
	var out []domain.HeaderPair
	for name, values := range h {
		for _, value := range values {
			out = append(out, domain.HeaderPair{Name: name, Value: value})
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeProblem(w http.ResponseWriter, p problem.Problem) {
	writeJSON(w, p.Status, p)
}

func page[T any](items []T) map[string]any {
	if items == nil {
		items = []T{}
	}
	return map[string]any{"data": items, "next_cursor": nil, "has_more": false}
}

func scimListResponse[T any](items []T) map[string]any {
	if items == nil {
		items = []T{}
	}
	return map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(items),
		"Resources":    items,
		"startIndex":   1,
		"itemsPerPage": len(items),
	}
}

func (s *Server) remoteAddr(r *http.Request) string {
	peer, ok := parseRemoteAddrIP(r.RemoteAddr)
	if !ok || !s.trustsProxy(peer) {
		return r.RemoteAddr
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		first, _, _ := strings.Cut(forwarded, ",")
		addr, err := netip.ParseAddr(strings.TrimSpace(first))
		if err == nil {
			return addr.Unmap().String()
		}
	}
	return r.RemoteAddr
}

func (s *Server) trustsProxy(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range s.cfg.TrustedProxyCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func parseRemoteAddrIP(raw string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		host = raw
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func formatPrometheus(metrics domain.OpsMetrics) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# HELP webhookery_events_total Total captured canonical events.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_events_total counter\n")
	fmt.Fprintf(&b, "webhookery_events_total %d\n", metrics.EventsTotal)
	fmt.Fprintf(&b, "# HELP webhookery_outbox_pending Pending durable outbox rows.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_outbox_pending gauge\n")
	fmt.Fprintf(&b, "webhookery_outbox_pending %d\n", metrics.OutboxPending)
	fmt.Fprintf(&b, "# HELP webhookery_outbox_oldest_age_seconds Oldest pending outbox age.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_outbox_oldest_age_seconds gauge\n")
	fmt.Fprintf(&b, "webhookery_outbox_oldest_age_seconds %d\n", metrics.OldestOutboxAgeSec)
	fmt.Fprintf(&b, "# HELP webhookery_dead_letter_open Open dead-letter entries.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_dead_letter_open gauge\n")
	fmt.Fprintf(&b, "webhookery_dead_letter_open %d\n", metrics.DeadLetterOpen)
	fmt.Fprintf(&b, "# HELP webhookery_quarantine_open Open quarantine entries.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_quarantine_open gauge\n")
	fmt.Fprintf(&b, "webhookery_quarantine_open %d\n", metrics.QuarantineOpen)
	fmt.Fprintf(&b, "# HELP webhookery_endpoint_circuit_open Open endpoint circuits.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_endpoint_circuit_open gauge\n")
	fmt.Fprintf(&b, "webhookery_endpoint_circuit_open %d\n", metrics.EndpointCircuitOpen)
	fmt.Fprintf(&b, "# HELP webhookery_audit_chain_unchained_events Audit events without chain entries.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_audit_chain_unchained_events gauge\n")
	fmt.Fprintf(&b, "webhookery_audit_chain_unchained_events %d\n", metrics.AuditChainUnchainedEvents)
	fmt.Fprintf(&b, "# HELP webhookery_audit_chain_verification_failures Audit chain entries that cannot verify against available audit rows.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_audit_chain_verification_failures gauge\n")
	fmt.Fprintf(&b, "webhookery_audit_chain_verification_failures %d\n", metrics.AuditChainVerificationFailures)
	fmt.Fprintf(&b, "# HELP webhookery_audit_chain_last_anchor_age_seconds Age of the newest audit chain anchor.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_audit_chain_last_anchor_age_seconds gauge\n")
	fmt.Fprintf(&b, "webhookery_audit_chain_last_anchor_age_seconds %d\n", metrics.AuditChainLastAnchorAgeSec)
	writeMetricCounts(&b, "webhookery_deliveries", "state", metrics.DeliveriesByState)
	writeMetricCounts(&b, "webhookery_replay_jobs", "state", metrics.ReplayJobsByState)
	writeMetricCounts(&b, "webhookery_reconciliation_jobs", "state", metrics.ReconciliationJobsByState)
	writeMetricCounts(&b, "webhookery_reconciliation_items", "outcome", metrics.ReconciliationItemsByOutcome)
	return b.String()
}

func writeMetricCounts(b *strings.Builder, metricName, labelName string, values map[string]int64) {
	counts := map[string]int64{}
	for value, count := range values {
		counts[safePublicMetricLabel(value)] += count
	}
	labels := make([]string, 0, len(counts))
	for label := range counts {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		fmt.Fprintf(b, "%s{%s=%q} %d\n", metricName, labelName, label, counts[label])
	}
}

func safePublicMetricLabel(value string) string {
	switch value {
	case "active", "canceled", "captured", "completed", "dead_lettered", "failed", "in_progress",
		"matched", "missing", "open", "paused", "pending", "pending_approval", "redelivery_requested", "released",
		"running", "scheduled", "succeeded", "unknown", "unrecoverable":
		return value
	default:
		return "unknown"
	}
}

func publicSource(source domain.Source) map[string]any {
	return map[string]any{
		"id":        source.ID,
		"tenant_id": source.TenantID,
		"name":      source.Name,
		"provider":  source.Provider,
		"adapter":   source.Adapter,
		"state":     source.State,
	}
}

func queryLimit(r *http.Request) int {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return 50
	}
	limit, err := strconv.Atoi(raw)
	if err != nil {
		return 50
	}
	return limit
}

func requestID(r *http.Request) string {
	reqID := identity.RequestID(r)
	if strings.TrimSpace(reqID) == "" {
		return "req_unknown"
	}
	return reqID
}
