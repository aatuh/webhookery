package httpapi

import (
	"net/http"

	"webhookery/internal/problem"
)

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Health != nil {
		if err := s.cfg.Health(r.Context()); err != nil {
			writeProblem(w, problem.New(http.StatusServiceUnavailable, "not_ready", "Not ready", "A required dependency is unavailable.", requestID(r), true))
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) prometheusMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := s.cfg.Control.PublicOpsMetrics(r.Context())
	if err != nil {
		writeProblem(w, problem.Internal(requestID(r)))
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(formatPrometheus(metrics)))
}

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(s.cfg.OpenAPI)
}
