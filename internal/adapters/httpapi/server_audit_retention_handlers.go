package httpapi

import (
	"fmt"
	"net/http"

	"webhookery/internal/app"

	"github.com/go-chi/chi/v5"
)

func (s *Server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListAuditEvents(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getAuditChainHead(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetAuditChainHead(r.Context(), actorFrom(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) verifyAuditChain(w http.ResponseWriter, r *http.Request) {
	var req app.AuditChainVerifyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.VerifyAuditChain(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createAuditChainAnchor(w http.ResponseWriter, r *http.Request) {
	var req app.AuditChainAnchorRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateAuditChainAnchor(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listAuditChainAnchors(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListAuditChainAnchors(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getAuditChainAnchor(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetAuditChainAnchor(r.Context(), actorFrom(r), chi.URLParam(r, "anchor_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createAuditExport(w http.ResponseWriter, r *http.Request) {
	var req app.CreateAuditExportRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateAuditExport(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) listAuditExports(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListAuditExports(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getAuditExport(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetAuditExport(r.Context(), actorFrom(r), chi.URLParam(r, "export_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) downloadAuditExport(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.DownloadAuditExport(r.Context(), actorFrom(r), chi.URLParam(r, "export_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", item.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", item.Filename))
	w.Header().Set("X-Webhookery-Export-SHA256", item.Export.SHA256)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(item.Body)
}

func (s *Server) listRetentionPolicies(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListRetentionPolicies(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) createRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	var req app.CreateRetentionPolicyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateRetentionPolicy(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) updateRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateRetentionPolicyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateRetentionPolicy(r.Context(), actorFrom(r), chi.URLParam(r, "policy_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
