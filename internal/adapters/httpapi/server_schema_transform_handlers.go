package httpapi

import (
	"net/http"

	"webhookery/internal/app"

	"github.com/go-chi/chi/v5"
)

func (s *Server) createEventType(w http.ResponseWriter, r *http.Request) {
	var req app.CreateEventTypeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateEventType(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listEventTypes(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListEventTypes(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getEventType(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetEventType(r.Context(), actorFrom(r), chi.URLParam(r, "event_type"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateEventType(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateEventTypeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateEventType(r.Context(), actorFrom(r), chi.URLParam(r, "event_type"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteEventType(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DeleteEventType(r.Context(), actorFrom(r), chi.URLParam(r, "event_type"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createEventSchema(w http.ResponseWriter, r *http.Request) {
	var req app.CreateEventSchemaRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateEventSchema(r.Context(), actorFrom(r), chi.URLParam(r, "event_type"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listEventSchemas(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListEventSchemas(r.Context(), actorFrom(r), chi.URLParam(r, "event_type"), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getEventSchema(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetEventSchema(r.Context(), actorFrom(r), chi.URLParam(r, "event_type"), chi.URLParam(r, "schema_version"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateEventSchema(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateEventSchemaRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateEventSchema(r.Context(), actorFrom(r), chi.URLParam(r, "event_type"), chi.URLParam(r, "schema_version"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteEventSchema(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DeleteEventSchema(r.Context(), actorFrom(r), chi.URLParam(r, "event_type"), chi.URLParam(r, "schema_version"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) validateEventSchema(w http.ResponseWriter, r *http.Request) {
	var req app.ValidateSchemaRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.ValidateEventSchema(r.Context(), actorFrom(r), chi.URLParam(r, "event_type"), chi.URLParam(r, "schema_version"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) checkEventSchemaCompatibility(w http.ResponseWriter, r *http.Request) {
	var req app.CheckSchemaCompatibilityRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CheckEventSchemaCompatibility(r.Context(), actorFrom(r), chi.URLParam(r, "event_type"), chi.URLParam(r, "schema_version"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createTransformation(w http.ResponseWriter, r *http.Request) {
	var req app.CreateTransformationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateTransformation(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listTransformations(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListTransformations(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getTransformation(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetTransformation(r.Context(), actorFrom(r), chi.URLParam(r, "transformation_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createTransformationVersion(w http.ResponseWriter, r *http.Request) {
	var req app.CreateTransformationVersionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateTransformationVersion(r.Context(), actorFrom(r), chi.URLParam(r, "transformation_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listTransformationVersions(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListTransformationVersions(r.Context(), actorFrom(r), chi.URLParam(r, "transformation_id"), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) activateTransformationVersion(w http.ResponseWriter, r *http.Request) {
	var req app.ActivateTransformationVersionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.ActivateTransformationVersion(r.Context(), actorFrom(r), chi.URLParam(r, "transformation_id"), chi.URLParam(r, "version_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
