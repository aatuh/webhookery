package httpapi

import (
	"context"
	"net/http"
	"net/netip"

	"github.com/go-chi/chi/v5"

	"webhookery/internal/adapters/httpui"
	"webhookery/internal/app"
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
	ProducerMTLSAuth    app.ProducerMTLSAuthenticator
	OpenAPI             []byte
	EnableUI            bool
	SessionCookieSecure bool
	TrustedProxyCIDRs   []netip.Prefix
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
		r.Post("/ingest/{tenant_id}/{source_id}", s.ingestGenericOrProvider)
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
			r.Get("/producer-mtls-identities", s.listProducerMTLSIdentities)
			r.Post("/producer-mtls-identities", s.createProducerMTLSIdentity)
			r.Get("/producer-mtls-identities/{identity_id}", s.getProducerMTLSIdentity)
			r.Patch("/producer-mtls-identities/{identity_id}", s.updateProducerMTLSIdentity)
			r.Delete("/producer-mtls-identities/{identity_id}", s.deleteProducerMTLSIdentity)
			r.Post("/producer-mtls-identities/{identity_id}:verify", s.verifyProducerMTLSIdentity)
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

type actorContextKey struct{}
