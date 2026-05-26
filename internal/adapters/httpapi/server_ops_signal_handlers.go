package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"webhookery/internal/app"
	"webhookery/internal/problem"

	"github.com/go-chi/chi/v5"
)

func (s *Server) listEndpointHealth(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListEndpointHealth(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) opsMetrics(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.OpsMetrics(r.Context(), actorFrom(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) listMetricRollups(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListMetricRollups(r.Context(), actorFrom(r), r.URL.Query().Get("metric_name"), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) listWorkers(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListWorkers(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getWorker(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetWorker(r.Context(), actorFrom(r), chi.URLParam(r, "worker_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) listQueues(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListQueues(r.Context(), actorFrom(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) opsStorage(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.OpsStorage(r.Context(), actorFrom(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) opsConfig(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.OpsConfig(r.Context(), actorFrom(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createAlertRule(w http.ResponseWriter, r *http.Request) {
	var req app.CreateAlertRuleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateAlertRule(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listAlertRules(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListAlertRules(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getAlertRule(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetAlertRule(r.Context(), actorFrom(r), chi.URLParam(r, "alert_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateAlertRule(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateAlertRuleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateAlertRule(r.Context(), actorFrom(r), chi.URLParam(r, "alert_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteAlertRule(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DeleteAlertRule(r.Context(), actorFrom(r), chi.URLParam(r, "alert_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) listAlertFirings(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListAlertFirings(r.Context(), actorFrom(r), r.URL.Query().Get("state"), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getAlertFiring(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetAlertFiring(r.Context(), actorFrom(r), chi.URLParam(r, "firing_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) acknowledgeAlertFiring(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.AcknowledgeAlertFiring(r.Context(), actorFrom(r), chi.URLParam(r, "firing_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createNotificationChannel(w http.ResponseWriter, r *http.Request) {
	var req app.CreateNotificationChannelRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, result, err := s.cfg.Control.CreateNotificationChannel(r.Context(), actorFrom(r), req)
	if err != nil {
		if errors.Is(err, app.ErrInvalidInput) && len(result.BlockedReasons) > 0 {
			writeProblem(w, problem.BadRequest(requestID(r), "notification_channel_url_blocked", strings.Join(result.BlockedReasons, ",")))
			return
		}
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listNotificationChannels(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListNotificationChannels(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getNotificationChannel(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetNotificationChannel(r.Context(), actorFrom(r), chi.URLParam(r, "channel_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateNotificationChannelRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, result, err := s.cfg.Control.UpdateNotificationChannel(r.Context(), actorFrom(r), chi.URLParam(r, "channel_id"), req)
	if err != nil {
		if errors.Is(err, app.ErrInvalidInput) && len(result.BlockedReasons) > 0 {
			writeProblem(w, problem.BadRequest(requestID(r), "notification_channel_url_blocked", strings.Join(result.BlockedReasons, ",")))
			return
		}
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteNotificationChannel(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DeleteNotificationChannel(r.Context(), actorFrom(r), chi.URLParam(r, "channel_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) testNotificationChannel(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.TestNotificationChannel(r.Context(), actorFrom(r), chi.URLParam(r, "channel_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) listNotificationDeliveries(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListNotificationDeliveries(r.Context(), actorFrom(r), r.URL.Query().Get("state"), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) listNotificationDeliveryAttempts(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListNotificationDeliveryAttempts(r.Context(), actorFrom(r), chi.URLParam(r, "delivery_id"), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) retryNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.RetryNotificationDelivery(r.Context(), actorFrom(r), chi.URLParam(r, "delivery_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createSIEMSink(w http.ResponseWriter, r *http.Request) {
	var req app.CreateSIEMSinkRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, result, err := s.cfg.Control.CreateSIEMSink(r.Context(), actorFrom(r), req)
	if err != nil {
		if errors.Is(err, app.ErrInvalidInput) && len(result.BlockedReasons) > 0 {
			writeProblem(w, problem.BadRequest(requestID(r), "siem_sink_url_blocked", strings.Join(result.BlockedReasons, ",")))
			return
		}
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listSIEMSinks(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListSIEMSinks(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getSIEMSink(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetSIEMSink(r.Context(), actorFrom(r), chi.URLParam(r, "sink_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateSIEMSink(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateSIEMSinkRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, result, err := s.cfg.Control.UpdateSIEMSink(r.Context(), actorFrom(r), chi.URLParam(r, "sink_id"), req)
	if err != nil {
		if errors.Is(err, app.ErrInvalidInput) && len(result.BlockedReasons) > 0 {
			writeProblem(w, problem.BadRequest(requestID(r), "siem_sink_url_blocked", strings.Join(result.BlockedReasons, ",")))
			return
		}
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteSIEMSink(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DeleteSIEMSink(r.Context(), actorFrom(r), chi.URLParam(r, "sink_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) testSIEMSink(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.TestSIEMSink(r.Context(), actorFrom(r), chi.URLParam(r, "sink_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) listSIEMDeliveries(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListSIEMDeliveries(r.Context(), actorFrom(r), r.URL.Query().Get("state"), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) listSIEMDeliveryAttempts(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListSIEMDeliveryAttempts(r.Context(), actorFrom(r), chi.URLParam(r, "delivery_id"), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) retrySIEMDelivery(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.RetrySIEMDelivery(r.Context(), actorFrom(r), chi.URLParam(r, "delivery_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
