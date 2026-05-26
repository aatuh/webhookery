package httpapi

import (
	"net/http"

	"webhookery/internal/app"

	"github.com/go-chi/chi/v5"
)

func (s *Server) createRoute(w http.ResponseWriter, r *http.Request) {
	var req app.CreateRouteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateRoute(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listRoutes(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListRoutes(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getRoute(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetRoute(r.Context(), actorFrom(r), chi.URLParam(r, "route_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateRoute(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateRouteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateRoute(r.Context(), actorFrom(r), chi.URLParam(r, "route_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteRoute(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DeleteRoute(r.Context(), actorFrom(r), chi.URLParam(r, "route_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) listRouteVersions(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListRouteVersions(r.Context(), actorFrom(r), chi.URLParam(r, "route_id"), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) activateRoute(w http.ResponseWriter, r *http.Request) {
	var req app.ActivateRouteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.ActivateRoute(r.Context(), actorFrom(r), chi.URLParam(r, "route_id"), req.Reason)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) dryRunRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EventID string `json:"event_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DryRunRoute(r.Context(), actorFrom(r), chi.URLParam(r, "route_id"), req.EventID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
