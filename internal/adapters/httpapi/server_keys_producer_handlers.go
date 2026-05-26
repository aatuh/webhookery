package httpapi

import (
	"net/http"

	"webhookery/internal/app"

	"github.com/go-chi/chi/v5"
)

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var req app.CreateAPIKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateAPIKey(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListAPIKeys(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	var req app.RevokeAPIKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.RevokeAPIKey(r.Context(), actorFrom(r), chi.URLParam(r, "api_key_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createProducerClient(w http.ResponseWriter, r *http.Request) {
	var req app.CreateProducerClientRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateProducerClient(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listProducerClients(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListProducerClients(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getProducerClient(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetProducerClient(r.Context(), actorFrom(r), chi.URLParam(r, "client_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateProducerClient(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateProducerClientRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateProducerClient(r.Context(), actorFrom(r), chi.URLParam(r, "client_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteProducerClient(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DeleteProducerClient(r.Context(), actorFrom(r), chi.URLParam(r, "client_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) rotateProducerClientSecret(w http.ResponseWriter, r *http.Request) {
	var req app.RotateProducerClientSecretRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.RotateProducerClientSecret(r.Context(), actorFrom(r), chi.URLParam(r, "client_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createProducerMTLSIdentity(w http.ResponseWriter, r *http.Request) {
	var req app.CreateProducerMTLSIdentityRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateProducerMTLSIdentity(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listProducerMTLSIdentities(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListProducerMTLSIdentities(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getProducerMTLSIdentity(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetProducerMTLSIdentity(r.Context(), actorFrom(r), chi.URLParam(r, "identity_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateProducerMTLSIdentity(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateProducerMTLSIdentityRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateProducerMTLSIdentity(r.Context(), actorFrom(r), chi.URLParam(r, "identity_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteProducerMTLSIdentity(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DeleteProducerMTLSIdentity(r.Context(), actorFrom(r), chi.URLParam(r, "identity_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) verifyProducerMTLSIdentity(w http.ResponseWriter, r *http.Request) {
	var req app.VerifyProducerMTLSIdentityRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.VerifyProducerMTLSIdentity(r.Context(), actorFrom(r), chi.URLParam(r, "identity_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
