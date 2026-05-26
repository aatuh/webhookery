package httpapi

import (
	"net/http"

	"webhookery/internal/app"

	"github.com/go-chi/chi/v5"
)

func (s *Server) createEndpoint(w http.ResponseWriter, r *http.Request) {
	var req app.CreateEndpointRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	endpoint, validation, err := s.cfg.Control.CreateEndpoint(r.Context(), actorFrom(r), req)
	if err != nil {
		if len(validation.BlockedReasons) > 0 {
			writeJSON(w, http.StatusUnprocessableEntity, validation)
			return
		}
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"endpoint": endpoint, "ssrf": validation})
}

func (s *Server) listEndpoints(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListEndpoints(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getEndpoint(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetEndpoint(r.Context(), actorFrom(r), chi.URLParam(r, "endpoint_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateEndpoint(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateEndpointRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, validation, err := s.cfg.Control.UpdateEndpoint(r.Context(), actorFrom(r), chi.URLParam(r, "endpoint_id"), req)
	if err != nil {
		if len(validation.BlockedReasons) > 0 {
			writeJSON(w, http.StatusUnprocessableEntity, validation)
			return
		}
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DeleteEndpoint(r.Context(), actorFrom(r), chi.URLParam(r, "endpoint_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) testEndpoint(w http.ResponseWriter, r *http.Request) {
	var req app.TestEndpointRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.TestEndpoint(r.Context(), actorFrom(r), chi.URLParam(r, "endpoint_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) validateEndpointURL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	writeJSON(w, http.StatusOK, s.cfg.Control.ValidateEndpointURL(r.Context(), req.URL))
}

func (s *Server) rotateEndpointSecret(w http.ResponseWriter, r *http.Request) {
	var req app.RotateEndpointSecretRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.RotateEndpointSecret(r.Context(), actorFrom(r), chi.URLParam(r, "endpoint_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createSubscription(w http.ResponseWriter, r *http.Request) {
	var req app.CreateSubscriptionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateSubscription(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listSubscriptions(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListSubscriptions(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getSubscription(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetSubscription(r.Context(), actorFrom(r), chi.URLParam(r, "subscription_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateSubscription(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateSubscriptionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateSubscription(r.Context(), actorFrom(r), chi.URLParam(r, "subscription_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DeleteSubscription(r.Context(), actorFrom(r), chi.URLParam(r, "subscription_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createRetryPolicy(w http.ResponseWriter, r *http.Request) {
	var req app.CreateRetryPolicyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateRetryPolicy(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listRetryPolicies(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListRetryPolicies(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getRetryPolicy(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetRetryPolicy(r.Context(), actorFrom(r), chi.URLParam(r, "retry_policy_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateRetryPolicy(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateRetryPolicyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateRetryPolicy(r.Context(), actorFrom(r), chi.URLParam(r, "retry_policy_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteRetryPolicy(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DeleteRetryPolicy(r.Context(), actorFrom(r), chi.URLParam(r, "retry_policy_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
