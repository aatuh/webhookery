package httpapi

import (
	"net/http"

	"webhookery/internal/app"

	"github.com/go-chi/chi/v5"
)

func (s *Server) createProviderAdapter(w http.ResponseWriter, r *http.Request) {
	var req app.CreateProviderAdapterRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateProviderAdapter(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listProviderAdapters(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListProviderAdapters(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getProviderAdapter(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetProviderAdapter(r.Context(), actorFrom(r), chi.URLParam(r, "adapter_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createAdapterVersion(w http.ResponseWriter, r *http.Request) {
	var req app.CreateAdapterVersionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateAdapterVersion(r.Context(), actorFrom(r), chi.URLParam(r, "adapter_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listAdapterVersions(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListAdapterVersions(r.Context(), actorFrom(r), chi.URLParam(r, "adapter_id"), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) createAdapterTestVector(w http.ResponseWriter, r *http.Request) {
	var req app.CreateAdapterTestVectorRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateAdapterTestVector(r.Context(), actorFrom(r), chi.URLParam(r, "adapter_id"), chi.URLParam(r, "version_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) transitionAdapterVersion(w http.ResponseWriter, r *http.Request) {
	var req app.AdapterVersionTransitionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.TransitionAdapterVersion(r.Context(), actorFrom(r), chi.URLParam(r, "adapter_id"), chi.URLParam(r, "version_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
