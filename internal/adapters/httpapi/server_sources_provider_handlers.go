package httpapi

import (
	"net/http"

	"webhookery/internal/app"

	"github.com/go-chi/chi/v5"
)

func (s *Server) createSource(w http.ResponseWriter, r *http.Request) {
	var req app.CreateSourceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	source, err := s.cfg.Control.CreateSource(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, publicSource(source))
}

func (s *Server) listSources(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListSources(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, publicSource(item))
	}
	writeJSON(w, http.StatusOK, page(out))
}

func (s *Server) getSource(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetSource(r.Context(), actorFrom(r), chi.URLParam(r, "source_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, publicSource(item))
}

func (s *Server) updateSource(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateSourceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateSource(r.Context(), actorFrom(r), chi.URLParam(r, "source_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, publicSource(item))
}

func (s *Server) deleteSource(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DeleteSource(r.Context(), actorFrom(r), chi.URLParam(r, "source_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, publicSource(item))
}

func (s *Server) createProviderConnection(w http.ResponseWriter, r *http.Request) {
	var req app.CreateProviderConnectionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateProviderConnection(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listProviderConnections(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListProviderConnections(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getProviderConnection(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetProviderConnection(r.Context(), actorFrom(r), chi.URLParam(r, "connection_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) verifyProviderConnection(w http.ResponseWriter, r *http.Request) {
	var req app.ProviderConnectionStateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.VerifyProviderConnection(r.Context(), actorFrom(r), chi.URLParam(r, "connection_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) revokeProviderConnection(w http.ResponseWriter, r *http.Request) {
	var req app.ProviderConnectionStateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.RevokeProviderConnection(r.Context(), actorFrom(r), chi.URLParam(r, "connection_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) rotateSourceSecret(w http.ResponseWriter, r *http.Request) {
	var req app.RotateSourceSecretRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.RotateSourceSecret(r.Context(), actorFrom(r), chi.URLParam(r, "source_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
