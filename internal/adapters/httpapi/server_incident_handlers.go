package httpapi

import (
	"net/http"
	"strings"

	"webhookery/internal/app"

	"github.com/go-chi/chi/v5"
)

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListIncidents(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) createIncident(w http.ResponseWriter, r *http.Request) {
	var req app.CreateIncidentRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateIncident(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetIncident(r.Context(), actorFrom(r), chi.URLParam(r, "incident_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) addIncidentEvent(w http.ResponseWriter, r *http.Request) {
	var req app.AddIncidentEventRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.AddIncidentEvent(r.Context(), actorFrom(r), chi.URLParam(r, "incident_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) removeIncidentEvent(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.RemoveIncidentEvent(r.Context(), actorFrom(r), chi.URLParam(r, "incident_id"), chi.URLParam(r, "event_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) generateIncidentReport(w http.ResponseWriter, r *http.Request) {
	var req app.IncidentReportRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.GenerateIncidentReport(r.Context(), actorFrom(r), chi.URLParam(r, "incident_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) getIncidentReport(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetIncidentReport(r.Context(), actorFrom(r), chi.URLParam(r, "incident_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if strings.EqualFold(r.URL.Query().Get("format"), "markdown") {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(item.Markdown))
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createIncidentEvidenceExport(w http.ResponseWriter, r *http.Request) {
	var req app.CreateIncidentEvidenceExportRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	_, export, err := s.cfg.Control.CreateIncidentEvidenceExport(r.Context(), actorFrom(r), chi.URLParam(r, "incident_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, export)
}
