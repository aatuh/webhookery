package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/aatuh/api-toolkit/v2/httpx/identity"
	"github.com/go-chi/chi/v5"

	"webhookery/internal/adapters/httpui"
	"webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/problem"
)

const (
	maxIngressBodyBytes = 2 << 20
	maxHeaderBytes      = 64 << 10
	maxHeaderPairs      = 128
	maxHeaderValueBytes = 8 << 10
	sessionCookieName   = "webhookery_session"
)

type ServerConfig struct {
	Control             *app.ControlService
	Ingest              *app.IngestService
	Auth                app.Authenticator
	SessionAuth         app.Authenticator
	ProducerAuth        app.Authenticator
	OpenAPI             []byte
	EnableUI            bool
	SessionCookieSecure bool
	Health              func(context.Context) error
}

type Server struct {
	cfg ServerConfig
}

func NewServer(cfg ServerConfig) *Server {
	return &Server{cfg: cfg}
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(rejectOversizedHeaders)
	r.Get("/healthz", s.health)
	r.Get("/readyz", s.ready)
	r.Get("/metrics", s.prometheusMetrics)
	r.Get("/openapi.yaml", s.openapi)

	r.Route("/v1", func(r chi.Router) {
		r.Post("/ingest/{tenant_id}/{source_id}", s.ingestGeneric)
		r.Post("/ingest/{provider}/{source_id}", s.ingestProvider)
		r.Post("/oauth/token", s.issueOAuthToken)
		r.With(s.requireProducerAuth).Post("/events", s.ingestProductEvent)
		r.Get("/auth/oidc/login", s.oidcLogin)
		r.Get("/auth/oidc/callback", s.oidcCallback)
		r.Route("/scim/v2", func(r chi.Router) {
			r.Use(s.requireSCIMAuth)
			r.Get("/Users", s.scimListUsers)
			r.Post("/Users", s.scimCreateUser)
			r.Get("/Users/{user_id}", s.scimGetUser)
			r.Put("/Users/{user_id}", s.scimReplaceUser)
			r.Patch("/Users/{user_id}", s.scimPatchUser)
			r.Delete("/Users/{user_id}", s.scimDeleteUser)
			r.Get("/Groups", s.scimListGroups)
			r.Post("/Groups", s.scimCreateGroup)
			r.Get("/Groups/{group_id}", s.scimGetGroup)
			r.Put("/Groups/{group_id}", s.scimReplaceGroup)
			r.Patch("/Groups/{group_id}", s.scimPatchGroup)
			r.Delete("/Groups/{group_id}", s.scimDeleteGroup)
		})

		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Post("/auth/logout", s.logout)
			r.Get("/auth/session", s.currentSession)
			r.Get("/auth/sessions", s.listAuthSessions)
			r.Post("/auth/sessions/{session_id}:revoke", s.revokeAuthSession)
			r.Get("/identity-providers", s.listIdentityProviders)
			r.Post("/identity-providers", s.createIdentityProvider)
			r.Get("/identity-providers/{provider_id}", s.getIdentityProvider)
			r.Patch("/identity-providers/{provider_id}", s.updateIdentityProvider)
			r.Delete("/identity-providers/{provider_id}", s.disableIdentityProvider)
			r.Post("/identity-providers/{provider_id}:test", s.testIdentityProvider)
			r.Get("/scim-tokens", s.listSCIMTokens)
			r.Post("/scim-tokens", s.createSCIMToken)
			r.Delete("/scim-tokens/{token_id}", s.revokeSCIMToken)
			r.Get("/role-bindings", s.listRoleBindings)
			r.Post("/role-bindings", s.createRoleBinding)
			r.Patch("/role-bindings/{binding_id}", s.updateRoleBinding)
			r.Delete("/role-bindings/{binding_id}", s.disableRoleBinding)
			r.Get("/access-policies", s.listAccessPolicyRules)
			r.Post("/access-policies", s.createAccessPolicyRule)
			r.Patch("/access-policies/{policy_id}", s.updateAccessPolicyRule)
			r.Delete("/access-policies/{policy_id}", s.disableAccessPolicyRule)
			r.Post("/authz:explain", s.authzExplain)
			r.Get("/api-keys", s.listAPIKeys)
			r.Post("/api-keys", s.createAPIKey)
			r.Post("/api-keys/{api_key_id}:revoke", s.revokeAPIKey)
			r.Get("/producer-clients", s.listProducerClients)
			r.Post("/producer-clients", s.createProducerClient)
			r.Get("/producer-clients/{client_id}", s.getProducerClient)
			r.Patch("/producer-clients/{client_id}", s.updateProducerClient)
			r.Delete("/producer-clients/{client_id}", s.deleteProducerClient)
			r.Post("/producer-clients/{client_id}/secrets:rotate", s.rotateProducerClientSecret)
			r.Get("/sources", s.listSources)
			r.Post("/sources", s.createSource)
			r.Get("/sources/{source_id}", s.getSource)
			r.Patch("/sources/{source_id}", s.updateSource)
			r.Delete("/sources/{source_id}", s.deleteSource)
			r.Post("/sources/{source_id}/secrets:rotate", s.rotateSourceSecret)
			r.Get("/provider-connections", s.listProviderConnections)
			r.Post("/provider-connections", s.createProviderConnection)
			r.Get("/provider-connections/{connection_id}", s.getProviderConnection)
			r.Post("/provider-connections/{connection_id}:verify", s.verifyProviderConnection)
			r.Post("/provider-connections/{connection_id}:revoke", s.revokeProviderConnection)
			r.Get("/adapters", s.listProviderAdapters)
			r.Post("/adapters", s.createProviderAdapter)
			r.Get("/adapters/{adapter_id}", s.getProviderAdapter)
			r.Get("/adapters/{adapter_id}/versions", s.listAdapterVersions)
			r.Post("/adapters/{adapter_id}/versions", s.createAdapterVersion)
			r.Post("/adapters/{adapter_id}/versions/{version_id}/test-vectors", s.createAdapterTestVector)
			r.Post("/adapters/{adapter_id}/versions/{version_id}:transition", s.transitionAdapterVersion)
			r.Get("/endpoints", s.listEndpoints)
			r.Post("/endpoints", s.createEndpoint)
			r.Get("/endpoints/{endpoint_id}", s.getEndpoint)
			r.Patch("/endpoints/{endpoint_id}", s.updateEndpoint)
			r.Delete("/endpoints/{endpoint_id}", s.deleteEndpoint)
			r.Post("/endpoints:validate-url", s.validateEndpointURL)
			r.Post("/endpoints/{endpoint_id}:test", s.testEndpoint)
			r.Post("/endpoints/{endpoint_id}/secrets:rotate", s.rotateEndpointSecret)
			r.Get("/subscriptions", s.listSubscriptions)
			r.Post("/subscriptions", s.createSubscription)
			r.Get("/subscriptions/{subscription_id}", s.getSubscription)
			r.Patch("/subscriptions/{subscription_id}", s.updateSubscription)
			r.Delete("/subscriptions/{subscription_id}", s.deleteSubscription)
			r.Get("/retry-policies", s.listRetryPolicies)
			r.Post("/retry-policies", s.createRetryPolicy)
			r.Get("/retry-policies/{retry_policy_id}", s.getRetryPolicy)
			r.Patch("/retry-policies/{retry_policy_id}", s.updateRetryPolicy)
			r.Delete("/retry-policies/{retry_policy_id}", s.deleteRetryPolicy)
			r.Get("/routes", s.listRoutes)
			r.Post("/routes", s.createRoute)
			r.Get("/routes/{route_id}", s.getRoute)
			r.Patch("/routes/{route_id}", s.updateRoute)
			r.Delete("/routes/{route_id}", s.deleteRoute)
			r.Get("/routes/{route_id}/versions", s.listRouteVersions)
			r.Post("/routes/{route_id}:activate", s.activateRoute)
			r.Post("/routes/{route_id}:dry-run", s.dryRunRoute)
			r.Get("/event-types", s.listEventTypes)
			r.Post("/event-types", s.createEventType)
			r.Get("/event-types/{event_type}", s.getEventType)
			r.Patch("/event-types/{event_type}", s.updateEventType)
			r.Delete("/event-types/{event_type}", s.deleteEventType)
			r.Get("/event-types/{event_type}/schemas", s.listEventSchemas)
			r.Post("/event-types/{event_type}/schemas", s.createEventSchema)
			r.Get("/event-types/{event_type}/schemas/{schema_version}", s.getEventSchema)
			r.Patch("/event-types/{event_type}/schemas/{schema_version}", s.updateEventSchema)
			r.Delete("/event-types/{event_type}/schemas/{schema_version}", s.deleteEventSchema)
			r.Post("/event-types/{event_type}/schemas/{schema_version}:validate", s.validateEventSchema)
			r.Post("/event-types/{event_type}/schemas/{schema_version}:check-compatibility", s.checkEventSchemaCompatibility)
			r.Get("/events", s.listEvents)
			r.Get("/events/{event_id}", s.getEvent)
			r.Get("/events/{event_id}/raw", s.getRawPayload)
			r.Get("/events/{event_id}/normalized", s.getNormalizedEvent)
			r.Get("/events/{event_id}/timeline", s.getEventTimeline)
			r.Get("/transformations", s.listTransformations)
			r.Post("/transformations", s.createTransformation)
			r.Get("/transformations/{transformation_id}", s.getTransformation)
			r.Get("/transformations/{transformation_id}/versions", s.listTransformationVersions)
			r.Post("/transformations/{transformation_id}/versions", s.createTransformationVersion)
			r.Post("/transformations/{transformation_id}/versions/{version_id}:activate", s.activateTransformationVersion)
			r.Get("/deliveries", s.listDeliveries)
			r.Get("/deliveries/{delivery_id}/attempts", s.listDeliveryAttempts)
			r.Post("/deliveries/{delivery_id}:retry", s.retryDelivery)
			r.Post("/deliveries/{delivery_id}:cancel", s.cancelDelivery)
			r.Get("/delivery-attempts/{attempt_id}", s.getDeliveryAttempt)
			r.Post("/replay-jobs:dry-run", s.dryRunReplay)
			r.Get("/replay-jobs", s.listReplayJobs)
			r.Post("/replay-jobs", s.createReplay)
			r.Post("/replay-jobs/{replay_job_id}:approve", s.approveReplayJob)
			r.Post("/replay-jobs/{replay_job_id}:pause", s.pauseReplayJob)
			r.Post("/replay-jobs/{replay_job_id}:resume", s.resumeReplayJob)
			r.Post("/replay-jobs/{replay_job_id}:cancel", s.cancelReplayJob)
			r.Post("/reconciliation-jobs:dry-run", s.dryRunReconciliation)
			r.Get("/reconciliation-jobs", s.listReconciliationJobs)
			r.Post("/reconciliation-jobs", s.createReconciliationJob)
			r.Get("/reconciliation-jobs/{job_id}", s.getReconciliationJob)
			r.Get("/reconciliation-jobs/{job_id}/items", s.listReconciliationItems)
			r.Post("/reconciliation-jobs/{job_id}:cancel", s.cancelReconciliationJob)
			r.Get("/dead-letter", s.listDeadLetter)
			r.Post("/dead-letter/{entry_id}:release", s.releaseDeadLetter)
			r.Post("/dead-letter:bulk-release", s.bulkReleaseDeadLetter)
			r.Get("/quarantine", s.listQuarantine)
			r.Post("/quarantine/{entry_id}:approve", s.approveQuarantine)
			r.Post("/quarantine/{entry_id}:reject", s.rejectQuarantine)
			r.Get("/audit-events", s.listAuditEvents)
			r.Get("/audit-chain/head", s.getAuditChainHead)
			r.Post("/audit-chain:verify", s.verifyAuditChain)
			r.Post("/audit-chain:anchor", s.createAuditChainAnchor)
			r.Get("/audit-chain/anchors", s.listAuditChainAnchors)
			r.Get("/audit-chain/anchors/{anchor_id}", s.getAuditChainAnchor)
			r.Post("/audit-events:export", s.createAuditExport)
			r.Get("/audit-exports", s.listAuditExports)
			r.Get("/audit-exports/{export_id}", s.getAuditExport)
			r.Get("/audit-exports/{export_id}:download", s.downloadAuditExport)
			r.Get("/admin/retention-policies", s.listRetentionPolicies)
			r.Post("/admin/retention-policies", s.createRetentionPolicy)
			r.Patch("/admin/retention-policies/{policy_id}", s.updateRetentionPolicy)
			r.Get("/endpoint-health", s.listEndpointHealth)
			r.Get("/ops/metrics", s.opsMetrics)
			r.Get("/ops/metrics/rollups", s.listMetricRollups)
			r.Get("/ops/storage", s.opsStorage)
			r.Get("/ops/config", s.opsConfig)
			r.Get("/ops/workers", s.listWorkers)
			r.Get("/ops/workers/{worker_id}", s.getWorker)
			r.Get("/ops/queues", s.listQueues)
			r.Get("/alerts", s.listAlertRules)
			r.Post("/alerts", s.createAlertRule)
			r.Get("/alerts/{alert_id}", s.getAlertRule)
			r.Patch("/alerts/{alert_id}", s.updateAlertRule)
			r.Delete("/alerts/{alert_id}", s.deleteAlertRule)
			r.Get("/alert-firings", s.listAlertFirings)
			r.Get("/alert-firings/{firing_id}", s.getAlertFiring)
			r.Post("/alert-firings/{firing_id}:acknowledge", s.acknowledgeAlertFiring)
			r.Get("/notification-channels", s.listNotificationChannels)
			r.Post("/notification-channels", s.createNotificationChannel)
			r.Get("/notification-channels/{channel_id}", s.getNotificationChannel)
			r.Patch("/notification-channels/{channel_id}", s.updateNotificationChannel)
			r.Delete("/notification-channels/{channel_id}", s.deleteNotificationChannel)
			r.Post("/notification-channels/{channel_id}:test", s.testNotificationChannel)
			r.Get("/notification-deliveries", s.listNotificationDeliveries)
			r.Get("/notification-deliveries/{delivery_id}/attempts", s.listNotificationDeliveryAttempts)
			r.Post("/notification-deliveries/{delivery_id}:retry", s.retryNotificationDelivery)
			r.Get("/siem-sinks", s.listSIEMSinks)
			r.Post("/siem-sinks", s.createSIEMSink)
			r.Get("/siem-sinks/{sink_id}", s.getSIEMSink)
			r.Patch("/siem-sinks/{sink_id}", s.updateSIEMSink)
			r.Delete("/siem-sinks/{sink_id}", s.deleteSIEMSink)
			r.Post("/siem-sinks/{sink_id}:test", s.testSIEMSink)
			r.Get("/siem-deliveries", s.listSIEMDeliveries)
			r.Get("/siem-deliveries/{delivery_id}/attempts", s.listSIEMDeliveryAttempts)
			r.Post("/siem-deliveries/{delivery_id}:retry", s.retrySIEMDelivery)
		})
	})

	if s.cfg.EnableUI {
		r.Get("/", httpui.Index())
	}
	return r
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Health != nil {
		if err := s.cfg.Health(r.Context()); err != nil {
			writeProblem(w, problem.New(http.StatusServiceUnavailable, "not_ready", "Not ready", "A required dependency is unavailable.", requestID(r), true))
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) prometheusMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := s.cfg.Control.PublicOpsMetrics(r.Context())
	if err != nil {
		writeProblem(w, problem.Internal(requestID(r)))
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(formatPrometheus(metrics)))
}

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(s.cfg.OpenAPI)
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := requestID(r)
		token := app.BearerToken(r.Header.Get("Authorization"))
		authenticator := s.cfg.Auth
		if token == "" && s.cfg.SessionAuth != nil {
			if cookie, err := r.Cookie(sessionCookieName); err == nil {
				token = cookie.Value
				authenticator = s.cfg.SessionAuth
			}
		}
		if authenticator == nil {
			writeProblem(w, problem.Unauthorized(requestID))
			return
		}
		actor, err := authenticator.Authenticate(r.Context(), token)
		if err != nil {
			writeProblem(w, problem.Unauthorized(requestID))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorContextKey{}, actor)))
	})
}

func (s *Server) requireProducerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := requestID(r)
		token := app.BearerToken(r.Header.Get("Authorization"))
		if s.cfg.ProducerAuth != nil {
			actor, err := s.cfg.ProducerAuth.Authenticate(r.Context(), token)
			if err == nil {
				if !authz.Can(actor, "events:write", actor.TenantID) {
					writeProblem(w, problem.Forbidden(requestID))
					return
				}
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorContextKey{}, actor)))
				return
			}
			if !errors.Is(err, app.ErrUnauthorized) {
				writeProblem(w, problem.Internal(requestID))
				return
			}
		}
		if s.cfg.Auth == nil {
			writeProblem(w, problem.Unauthorized(requestID))
			return
		}
		actor, err := s.cfg.Auth.Authenticate(r.Context(), token)
		if err != nil {
			writeProblem(w, problem.Unauthorized(requestID))
			return
		}
		if !authz.Can(actor, "events:write", actor.TenantID) {
			writeProblem(w, problem.Forbidden(requestID))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorContextKey{}, actor)))
	})
}

func (s *Server) requireSCIMAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Control == nil {
			writeProblem(w, problem.Unauthorized(requestID(r)))
			return
		}
		actor, err := s.cfg.Control.AuthenticateSCIMToken(r.Context(), app.BearerToken(r.Header.Get("Authorization")))
		if err != nil {
			writeProblem(w, problem.Unauthorized(requestID(r)))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorContextKey{}, actor)))
	})
}

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

func (s *Server) issueOAuthToken(w http.ResponseWriter, r *http.Request) {
	body, ok := readLimitedBody(w, r, 64<<10)
	if !ok {
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		writeProblem(w, problem.BadRequest(requestID(r), "validation_error", "Invalid form body."))
		return
	}
	if form.Get("grant_type") != "client_credentials" {
		writeProblem(w, problem.BadRequest(requestID(r), "unsupported_grant_type", "Only client_credentials grant is supported."))
		return
	}
	if form.Get("client_secret") != "" {
		writeProblem(w, problem.BadRequest(requestID(r), "invalid_request", "Client credentials must use HTTP Basic authentication."))
		return
	}
	clientID, clientSecret, basicOK := r.BasicAuth()
	if !basicOK || strings.TrimSpace(clientID) == "" || clientSecret == "" {
		writeProblem(w, problem.Unauthorized(requestID(r)))
		return
	}
	result, err := s.cfg.Control.IssueProducerToken(r.Context(), clientID, clientSecret)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, result)
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

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListEvents(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetEvent(r.Context(), actorFrom(r), chi.URLParam(r, "event_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) getRawPayload(w http.ResponseWriter, r *http.Request) {
	raw, err := s.cfg.Control.GetRawPayload(r.Context(), actorFrom(r), chi.URLParam(r, "event_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"event_id":         raw.EventID,
		"raw_payload_hash": raw.SHA256,
		"content_type":     raw.ContentType,
		"size_bytes":       raw.SizeBytes,
		"storage_backend":  raw.StorageBackend,
		"storage_status":   raw.StorageStatus,
		"body_base64":      base64.StdEncoding.EncodeToString(raw.Body),
	})
}

func (s *Server) getNormalizedEvent(w http.ResponseWriter, r *http.Request) {
	includeData := strings.EqualFold(r.URL.Query().Get("include_data"), "true")
	item, err := s.cfg.Control.GetNormalizedEvent(r.Context(), actorFrom(r), chi.URLParam(r, "event_id"), includeData)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) getEventTimeline(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListEventTimeline(r.Context(), actorFrom(r), chi.URLParam(r, "event_id"), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
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

func (s *Server) ingestProductEvent(w http.ResponseWriter, r *http.Request) {
	body, ok := readLimitedBody(w, r, maxIngressBodyBytes)
	if !ok {
		return
	}
	sourceID := productSourceID(body)
	if sourceID == "" {
		writeProblem(w, problem.BadRequest(requestID(r), "validation_error", "Product event body must include source_id."))
		return
	}
	actor := actorFrom(r)
	if actor.SourceID != "" && actor.SourceID != sourceID {
		writeProblem(w, problem.Forbidden(requestID(r)))
		return
	}
	result, err := s.cfg.Ingest.Ingest(r.Context(), app.IngestRequest{
		TenantID:    actor.TenantID,
		SourceID:    sourceID,
		Provider:    "internal",
		RawBody:     body,
		Headers:     headers(r.Header),
		ContentType: r.Header.Get("Content-Type"),
		RemoteIP:    r.RemoteAddr,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func productSourceID(raw []byte) string {
	var req struct {
		SourceID string `json:"source_id"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return ""
	}
	return strings.TrimSpace(req.SourceID)
}

func (s *Server) ingestGeneric(w http.ResponseWriter, r *http.Request) {
	body, ok := readLimitedBody(w, r, maxIngressBodyBytes)
	if !ok {
		return
	}
	result, err := s.cfg.Ingest.Ingest(r.Context(), app.IngestRequest{
		TenantID:    chi.URLParam(r, "tenant_id"),
		SourceID:    chi.URLParam(r, "source_id"),
		Provider:    "generic-hmac",
		RawBody:     body,
		Headers:     headers(r.Header),
		ContentType: r.Header.Get("Content-Type"),
		RemoteIP:    r.RemoteAddr,
	})
	s.writeIngestResult(w, r, result, err)
}

func (s *Server) ingestProvider(w http.ResponseWriter, r *http.Request) {
	body, ok := readLimitedBody(w, r, maxIngressBodyBytes)
	if !ok {
		return
	}
	providerName := chi.URLParam(r, "provider")
	result, err := s.cfg.Ingest.IngestProviderPath(r.Context(), providerName, chi.URLParam(r, "source_id"), app.IngestRequest{
		Provider:    providerName,
		RawBody:     body,
		Headers:     headers(r.Header),
		ContentType: r.Header.Get("Content-Type"),
		RemoteIP:    r.RemoteAddr,
	})
	if err == nil && result.Accepted && strings.EqualFold(providerName, "slack") {
		if challenge := slackChallenge(body); challenge != "" {
			writeJSON(w, http.StatusOK, map[string]string{"challenge": challenge})
			return
		}
	}
	s.writeIngestResult(w, r, result, err)
}

func slackChallenge(raw []byte) string {
	var payload struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ""
	}
	if payload.Type != "url_verification" {
		return ""
	}
	return strings.TrimSpace(payload.Challenge)
}

func (s *Server) writeIngestResult(w http.ResponseWriter, r *http.Request, result app.IngestResult, err error) {
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if !result.Accepted {
		writeProblem(w, problem.New(http.StatusUnauthorized, "invalid_signature", "Invalid webhook signature", "Webhook evidence was captured, but the signature did not verify.", requestID(r), false))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"received": true, "event_id": result.EventID, "duplicate": result.DedupeStatus != domain.DedupeUnique})
}

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

func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	result, err := s.cfg.Control.BeginOIDCLogin(r.Context(), r.URL.Query().Get("tenant_id"), r.URL.Query().Get("provider_id"), r.URL.Query().Get("redirect_after"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.setCookie(w, &http.Cookie{Name: "webhookery_oidc_state", Value: result.State, Path: "/v1/auth/oidc", MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, result.AuthURL, http.StatusFound)
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie("webhookery_oidc_state")
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(cookie.Value)) != 1 {
		writeProblem(w, problem.Unauthorized(requestID(r)))
		return
	}
	result, err := s.cfg.Control.CompleteOIDCCallback(r.Context(), state, r.URL.Query().Get("code"), r.UserAgent(), remoteAddr(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.setCookie(w, &http.Cookie{Name: sessionCookieName, Value: result.SessionToken, Path: "/", Expires: result.Session.ExpiresAt, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	s.setCookie(w, &http.Cookie{Name: "webhookery_oidc_state", Value: "", Path: "/v1/auth/oidc", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]any{"session": result.Session, "actor": result.Actor})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		writeProblem(w, problem.Unauthorized(requestID(r)))
		return
	}
	if err := s.cfg.Control.LogoutSession(r.Context(), actorFrom(r), cookie.Value); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.setCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) currentSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		writeProblem(w, problem.Unauthorized(requestID(r)))
		return
	}
	item, err := s.cfg.Control.CurrentAuthSession(r.Context(), actorFrom(r), cookie.Value)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) listAuthSessions(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListAuthSessions(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) revokeAuthSession(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.RevokeAuthSessionByID(r.Context(), actorFrom(r), chi.URLParam(r, "session_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) setCookie(w http.ResponseWriter, cookie *http.Cookie) {
	cookie.Secure = true
	cookie.HttpOnly = true
	if cookie.SameSite == http.SameSiteDefaultMode {
		cookie.SameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, cookie)
}

func (s *Server) createIdentityProvider(w http.ResponseWriter, r *http.Request) {
	var req app.CreateIdentityProviderRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateIdentityProvider(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listIdentityProviders(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListIdentityProviders(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getIdentityProvider(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetIdentityProvider(r.Context(), actorFrom(r), chi.URLParam(r, "provider_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateIdentityProvider(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateIdentityProviderRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateIdentityProvider(r.Context(), actorFrom(r), chi.URLParam(r, "provider_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) disableIdentityProvider(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DisableIdentityProvider(r.Context(), actorFrom(r), chi.URLParam(r, "provider_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) testIdentityProvider(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.TestIdentityProvider(r.Context(), actorFrom(r), chi.URLParam(r, "provider_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createSCIMToken(w http.ResponseWriter, r *http.Request) {
	var req app.CreateSCIMTokenRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateSCIMToken(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listSCIMTokens(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListSCIMTokens(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) revokeSCIMToken(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.RevokeSCIMToken(r.Context(), actorFrom(r), chi.URLParam(r, "token_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimListUsers(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.SCIMListUsers(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, scimListResponse(items))
}

func (s *Server) scimCreateUser(w http.ResponseWriter, r *http.Request) {
	var req app.SCIMUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.SCIMCreateUser(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) scimGetUser(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.SCIMGetUser(r.Context(), actorFrom(r), chi.URLParam(r, "user_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimReplaceUser(w http.ResponseWriter, r *http.Request) {
	var req app.SCIMUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.ID = chi.URLParam(r, "user_id")
	item, err := s.cfg.Control.SCIMReplaceUser(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimPatchUser(w http.ResponseWriter, r *http.Request) {
	var req app.SCIMPatchRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.SCIMPatchUser(r.Context(), actorFrom(r), chi.URLParam(r, "user_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimDeleteUser(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.SCIMDeactivateUser(r.Context(), actorFrom(r), chi.URLParam(r, "user_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimListGroups(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.SCIMListGroups(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, scimListResponse(items))
}

func (s *Server) scimCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req app.SCIMGroupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.SCIMCreateGroup(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) scimGetGroup(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.SCIMGetGroup(r.Context(), actorFrom(r), chi.URLParam(r, "group_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimReplaceGroup(w http.ResponseWriter, r *http.Request) {
	var req app.SCIMGroupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.ID = chi.URLParam(r, "group_id")
	item, err := s.cfg.Control.SCIMReplaceGroup(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimPatchGroup(w http.ResponseWriter, r *http.Request) {
	var req app.SCIMPatchRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.SCIMPatchGroup(r.Context(), actorFrom(r), chi.URLParam(r, "group_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimDeleteGroup(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.SCIMDeactivateGroup(r.Context(), actorFrom(r), chi.URLParam(r, "group_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createRoleBinding(w http.ResponseWriter, r *http.Request) {
	var req app.CreateRoleBindingRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateRoleBinding(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listRoleBindings(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListRoleBindings(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) updateRoleBinding(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateRoleBindingRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateRoleBinding(r.Context(), actorFrom(r), chi.URLParam(r, "binding_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) disableRoleBinding(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DisableRoleBinding(r.Context(), actorFrom(r), chi.URLParam(r, "binding_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createAccessPolicyRule(w http.ResponseWriter, r *http.Request) {
	var req app.CreateAccessPolicyRuleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateAccessPolicyRule(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listAccessPolicyRules(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListAccessPolicyRules(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) updateAccessPolicyRule(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateAccessPolicyRuleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateAccessPolicyRule(r.Context(), actorFrom(r), chi.URLParam(r, "policy_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) disableAccessPolicyRule(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DisableAccessPolicyRule(r.Context(), actorFrom(r), chi.URLParam(r, "policy_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) authzExplain(w http.ResponseWriter, r *http.Request) {
	var req app.AuthzExplainRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.ExplainAuthorization(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

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

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	requestID := requestID(r)
	switch {
	case errors.Is(err, app.ErrUnauthorized):
		writeProblem(w, problem.Unauthorized(requestID))
	case errors.Is(err, app.ErrForbidden):
		writeProblem(w, problem.Forbidden(requestID))
	case errors.Is(err, app.ErrNotFound):
		writeProblem(w, problem.New(http.StatusNotFound, "not_found", "Not found", "The requested resource was not found.", requestID, false))
	case errors.Is(err, app.ErrGone):
		writeProblem(w, problem.New(http.StatusGone, "payload_expired", "Payload unavailable", "The requested payload body has expired or was removed by retention policy; metadata and hashes remain available.", requestID, false))
	case errors.Is(err, app.ErrInvalidInput):
		writeProblem(w, problem.BadRequest(requestID, "validation_error", err.Error()))
	default:
		writeProblem(w, problem.Internal(requestID))
	}
}

type actorContextKey struct{}

func actorFrom(r *http.Request) authz.Actor {
	actor, _ := r.Context().Value(actorContextKey{}).(authz.Actor)
	return actor
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeProblem(w, problem.BadRequest(requestID(r), "validation_error", "Invalid JSON body."))
		return false
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		writeProblem(w, problem.BadRequest(requestID(r), "validation_error", "JSON body must contain a single value."))
		return false
	}
	return true
}

func readLimitedBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		writeProblem(w, problem.BadRequest(requestID(r), "validation_error", "Could not read request body."))
		return nil, false
	}
	if int64(len(body)) > max {
		writeProblem(w, problem.New(http.StatusRequestEntityTooLarge, "payload_too_large", "Payload too large", "The webhook payload exceeds the configured limit.", requestID(r), false))
		return nil, false
	}
	return body, true
}

func rejectOversizedHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requestHeadersWithinLimits(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestHeadersWithinLimits(w http.ResponseWriter, r *http.Request) bool {
	var pairs int
	var total int
	for name, values := range r.Header {
		if len(values) == 0 {
			pairs++
			total += len(name)
			if pairs > maxHeaderPairs || total > maxHeaderBytes {
				writeProblem(w, problem.New(http.StatusRequestHeaderFieldsTooLarge, "headers_too_large", "Headers too large", "The request headers exceed the configured limit.", requestID(r), false))
				return false
			}
			continue
		}
		for _, value := range values {
			pairs++
			total += len(name) + len(value)
			if len(value) > maxHeaderValueBytes || pairs > maxHeaderPairs || total > maxHeaderBytes {
				writeProblem(w, problem.New(http.StatusRequestHeaderFieldsTooLarge, "headers_too_large", "Headers too large", "The request headers exceed the configured limit.", requestID(r), false))
				return false
			}
		}
	}
	return true
}

func headers(h http.Header) []domain.HeaderPair {
	var out []domain.HeaderPair
	for name, values := range h {
		for _, value := range values {
			out = append(out, domain.HeaderPair{Name: name, Value: value})
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeProblem(w http.ResponseWriter, p problem.Problem) {
	writeJSON(w, p.Status, p)
}

func page[T any](items []T) map[string]any {
	if items == nil {
		items = []T{}
	}
	return map[string]any{"data": items, "next_cursor": nil, "has_more": false}
}

func scimListResponse[T any](items []T) map[string]any {
	if items == nil {
		items = []T{}
	}
	return map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(items),
		"Resources":    items,
		"startIndex":   1,
		"itemsPerPage": len(items),
	}
}

func remoteAddr(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		first, _, _ := strings.Cut(forwarded, ",")
		return strings.TrimSpace(first)
	}
	return r.RemoteAddr
}

func formatPrometheus(metrics domain.OpsMetrics) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# HELP webhookery_events_total Total captured canonical events.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_events_total counter\n")
	fmt.Fprintf(&b, "webhookery_events_total %d\n", metrics.EventsTotal)
	fmt.Fprintf(&b, "# HELP webhookery_outbox_pending Pending durable outbox rows.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_outbox_pending gauge\n")
	fmt.Fprintf(&b, "webhookery_outbox_pending %d\n", metrics.OutboxPending)
	fmt.Fprintf(&b, "# HELP webhookery_outbox_oldest_age_seconds Oldest pending outbox age.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_outbox_oldest_age_seconds gauge\n")
	fmt.Fprintf(&b, "webhookery_outbox_oldest_age_seconds %d\n", metrics.OldestOutboxAgeSec)
	fmt.Fprintf(&b, "# HELP webhookery_dead_letter_open Open dead-letter entries.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_dead_letter_open gauge\n")
	fmt.Fprintf(&b, "webhookery_dead_letter_open %d\n", metrics.DeadLetterOpen)
	fmt.Fprintf(&b, "# HELP webhookery_quarantine_open Open quarantine entries.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_quarantine_open gauge\n")
	fmt.Fprintf(&b, "webhookery_quarantine_open %d\n", metrics.QuarantineOpen)
	fmt.Fprintf(&b, "# HELP webhookery_endpoint_circuit_open Open endpoint circuits.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_endpoint_circuit_open gauge\n")
	fmt.Fprintf(&b, "webhookery_endpoint_circuit_open %d\n", metrics.EndpointCircuitOpen)
	fmt.Fprintf(&b, "# HELP webhookery_audit_chain_unchained_events Audit events without chain entries.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_audit_chain_unchained_events gauge\n")
	fmt.Fprintf(&b, "webhookery_audit_chain_unchained_events %d\n", metrics.AuditChainUnchainedEvents)
	fmt.Fprintf(&b, "# HELP webhookery_audit_chain_verification_failures Audit chain entries that cannot verify against available audit rows.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_audit_chain_verification_failures gauge\n")
	fmt.Fprintf(&b, "webhookery_audit_chain_verification_failures %d\n", metrics.AuditChainVerificationFailures)
	fmt.Fprintf(&b, "# HELP webhookery_audit_chain_last_anchor_age_seconds Age of the newest audit chain anchor.\n")
	fmt.Fprintf(&b, "# TYPE webhookery_audit_chain_last_anchor_age_seconds gauge\n")
	fmt.Fprintf(&b, "webhookery_audit_chain_last_anchor_age_seconds %d\n", metrics.AuditChainLastAnchorAgeSec)
	for state, count := range metrics.DeliveriesByState {
		fmt.Fprintf(&b, "webhookery_deliveries{state=%q} %d\n", state, count)
	}
	for state, count := range metrics.ReplayJobsByState {
		fmt.Fprintf(&b, "webhookery_replay_jobs{state=%q} %d\n", state, count)
	}
	for state, count := range metrics.ReconciliationJobsByState {
		fmt.Fprintf(&b, "webhookery_reconciliation_jobs{state=%q} %d\n", state, count)
	}
	for outcome, count := range metrics.ReconciliationItemsByOutcome {
		fmt.Fprintf(&b, "webhookery_reconciliation_items{outcome=%q} %d\n", outcome, count)
	}
	return b.String()
}

func publicSource(source domain.Source) map[string]any {
	return map[string]any{
		"id":        source.ID,
		"tenant_id": source.TenantID,
		"name":      source.Name,
		"provider":  source.Provider,
		"adapter":   source.Adapter,
		"state":     source.State,
	}
}

func queryLimit(r *http.Request) int {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return 50
	}
	limit, err := strconv.Atoi(raw)
	if err != nil {
		return 50
	}
	return limit
}

func requestID(r *http.Request) string {
	reqID := identity.RequestID(r)
	if strings.TrimSpace(reqID) == "" {
		return "req_unknown"
	}
	return reqID
}
