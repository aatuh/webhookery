package httpapi

import (
	"context"
	"net/http"

	"webhookery/internal/app"
	"webhookery/internal/authz"

	"github.com/go-chi/chi/v5"
)

func (s *Server) listDeliveries(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListDeliveries(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) listDeliveryAttempts(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListDeliveryAttempts(r.Context(), actorFrom(r), chi.URLParam(r, "delivery_id"), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getDeliveryAttempt(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetDeliveryAttempt(r.Context(), actorFrom(r), chi.URLParam(r, "attempt_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) retryDelivery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.RetryDelivery(r.Context(), actorFrom(r), chi.URLParam(r, "delivery_id"), req.Reason)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) cancelDelivery(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CancelDelivery(r.Context(), actorFrom(r), chi.URLParam(r, "delivery_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) dryRunReplay(w http.ResponseWriter, r *http.Request) {
	var req app.ReplayRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	res, err := s.cfg.Control.DryRunReplay(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) createReplay(w http.ResponseWriter, r *http.Request) {
	var req app.ReplayRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	res, err := s.cfg.Control.CreateReplay(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, res)
}

func (s *Server) listReplayJobs(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListReplayJobs(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) approveReplayJob(w http.ResponseWriter, r *http.Request) {
	s.changeReplayJobState(w, r, s.cfg.Control.ApproveReplayJob)
}

func (s *Server) pauseReplayJob(w http.ResponseWriter, r *http.Request) {
	s.changeReplayJobState(w, r, s.cfg.Control.PauseReplayJob)
}

func (s *Server) resumeReplayJob(w http.ResponseWriter, r *http.Request) {
	s.changeReplayJobState(w, r, s.cfg.Control.ResumeReplayJob)
}

func (s *Server) cancelReplayJob(w http.ResponseWriter, r *http.Request) {
	s.changeReplayJobState(w, r, s.cfg.Control.CancelReplayJob)
}

func (s *Server) listReplayApprovalPolicies(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListReplayApprovalPolicies(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) createReplayApprovalPolicy(w http.ResponseWriter, r *http.Request) {
	var req app.CreateReplayApprovalPolicyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateReplayApprovalPolicy(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) disableReplayApprovalPolicy(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DisableReplayApprovalPolicy(r.Context(), actorFrom(r), chi.URLParam(r, "policy_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) changeReplayJobState(w http.ResponseWriter, r *http.Request, fn func(context.Context, authz.Actor, string, app.StateChangeRequest) (app.ReplayJob, error)) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := fn(r.Context(), actorFrom(r), chi.URLParam(r, "replay_job_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) dryRunReconciliation(w http.ResponseWriter, r *http.Request) {
	var req app.ReconciliationJobRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DryRunReconciliation(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createReconciliationJob(w http.ResponseWriter, r *http.Request) {
	var req app.ReconciliationJobRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateReconciliationJob(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listReconciliationJobs(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListReconciliationJobs(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getReconciliationJob(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetReconciliationJob(r.Context(), actorFrom(r), chi.URLParam(r, "job_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) listReconciliationItems(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListReconciliationItems(r.Context(), actorFrom(r), chi.URLParam(r, "job_id"), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) cancelReconciliationJob(w http.ResponseWriter, r *http.Request) {
	var req app.ProviderConnectionStateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CancelReconciliationJob(r.Context(), actorFrom(r), chi.URLParam(r, "job_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) listDeadLetter(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListDeadLetter(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) releaseDeadLetter(w http.ResponseWriter, r *http.Request) {
	var req app.DeadLetterReleaseRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.ReleaseDeadLetter(r.Context(), actorFrom(r), chi.URLParam(r, "entry_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) bulkReleaseDeadLetter(w http.ResponseWriter, r *http.Request) {
	var req app.DeadLetterBulkReleaseRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	items, err := s.cfg.Control.BulkReleaseDeadLetter(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"data": items})
}

func (s *Server) listQuarantine(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListQuarantine(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) approveQuarantine(w http.ResponseWriter, r *http.Request) {
	var req app.QuarantineDecisionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.ApproveQuarantine(r.Context(), actorFrom(r), chi.URLParam(r, "entry_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) rejectQuarantine(w http.ResponseWriter, r *http.Request) {
	var req app.QuarantineDecisionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.RejectQuarantine(r.Context(), actorFrom(r), chi.URLParam(r, "entry_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
