package app

import (
	"context"

	"webhookery/internal/domain"
)

type APIKeyStore interface {
	CreateAPIKey(ctx context.Context, input APIKeyCreateInput) (domain.APIKey, error)
	ListAPIKeys(ctx context.Context, tenantID string, limit int) ([]domain.APIKey, error)
	RevokeAPIKey(ctx context.Context, tenantID, apiKeyID, actorID, reason string) (domain.APIKey, error)
}

type SourceStore interface {
	CreateSource(ctx context.Context, source domain.Source) (domain.Source, error)
	ListSources(ctx context.Context, tenantID string, limit int) ([]domain.Source, error)
	GetSource(ctx context.Context, tenantID, sourceID string) (domain.Source, error)
	UpdateSource(ctx context.Context, tenantID, sourceID, actorID string, req UpdateSourceRequest) (domain.Source, error)
	DeleteSource(ctx context.Context, tenantID, sourceID, actorID, reason string) (domain.Source, error)
	RotateSourceSecret(ctx context.Context, tenantID, sourceID, actorID string, req RotateSourceSecretRequest) (domain.SourceSecretVersion, error)
}

type EndpointStore interface {
	CreateEndpoint(ctx context.Context, endpoint domain.Endpoint) (domain.Endpoint, error)
	ListEndpoints(ctx context.Context, tenantID string, limit int) ([]domain.Endpoint, error)
	GetEndpoint(ctx context.Context, tenantID, endpointID string) (domain.Endpoint, error)
	UpdateEndpoint(ctx context.Context, tenantID, endpointID, actorID string, req UpdateEndpointRequest) (domain.Endpoint, error)
	DeleteEndpoint(ctx context.Context, tenantID, endpointID, actorID, reason string) (domain.Endpoint, error)
	TestEndpoint(ctx context.Context, tenantID, endpointID, actorID, reason string) (domain.Delivery, error)
	RotateEndpointSecret(ctx context.Context, tenantID, endpointID, actorID string, req RotateEndpointSecretRequest) (domain.EndpointSecretVersion, error)
	ListEndpointHealth(ctx context.Context, tenantID string, limit int) ([]domain.EndpointHealth, error)
}

type SubscriptionStore interface {
	CreateSubscription(ctx context.Context, subscription domain.Subscription) (domain.Subscription, error)
	ListSubscriptions(ctx context.Context, tenantID string, limit int) ([]domain.Subscription, error)
	GetSubscription(ctx context.Context, tenantID, subscriptionID string) (domain.Subscription, error)
	UpdateSubscription(ctx context.Context, tenantID, subscriptionID, actorID string, req UpdateSubscriptionRequest) (domain.Subscription, error)
	DeleteSubscription(ctx context.Context, tenantID, subscriptionID, actorID, reason string) (domain.Subscription, error)
}

type RouteStore interface {
	CreateRoute(ctx context.Context, route domain.Route) (domain.Route, error)
	ListRoutes(ctx context.Context, tenantID string, limit int) ([]domain.Route, error)
	GetRoute(ctx context.Context, tenantID, routeID string) (domain.Route, error)
	UpdateRoute(ctx context.Context, tenantID, routeID, actorID string, req UpdateRouteRequest) (domain.Route, error)
	DeleteRoute(ctx context.Context, tenantID, routeID, actorID, reason string) (domain.Route, error)
	ListRouteVersions(ctx context.Context, tenantID, routeID string, limit int) ([]domain.RouteVersion, error)
	ActivateRoute(ctx context.Context, tenantID, routeID, actorID, reason string) (domain.Route, error)
	DryRunRoute(ctx context.Context, tenantID, routeID, eventID string) (RouteDryRun, error)
	CreateRetryPolicy(ctx context.Context, tenantID, actorID string, req CreateRetryPolicyRequest) (domain.RetryPolicy, error)
	ListRetryPolicies(ctx context.Context, tenantID string, limit int) ([]domain.RetryPolicy, error)
	GetRetryPolicy(ctx context.Context, tenantID, retryPolicyID string) (domain.RetryPolicy, error)
	UpdateRetryPolicy(ctx context.Context, tenantID, retryPolicyID, actorID string, req UpdateRetryPolicyRequest) (domain.RetryPolicy, error)
	DeleteRetryPolicy(ctx context.Context, tenantID, retryPolicyID, actorID, reason string) (domain.RetryPolicy, error)
}

type SchemaStore interface {
	CreateEventType(ctx context.Context, eventType domain.EventType) (domain.EventType, error)
	ListEventTypes(ctx context.Context, tenantID string, limit int) ([]domain.EventType, error)
	GetEventType(ctx context.Context, tenantID, eventType string) (domain.EventType, error)
	UpdateEventType(ctx context.Context, tenantID, eventType, actorID string, req UpdateEventTypeRequest) (domain.EventType, error)
	DeleteEventType(ctx context.Context, tenantID, eventType, actorID, reason string) (domain.EventType, error)
	CreateEventSchema(ctx context.Context, schema domain.EventSchema) (domain.EventSchema, error)
	ListEventSchemas(ctx context.Context, tenantID, eventType string, limit int) ([]domain.EventSchema, error)
	GetEventSchema(ctx context.Context, tenantID, eventType, version string) (domain.EventSchema, error)
	UpdateEventSchema(ctx context.Context, tenantID, eventType, version, actorID string, req UpdateEventSchemaRequest) (domain.EventSchema, error)
	DeleteEventSchema(ctx context.Context, tenantID, eventType, version, actorID, reason string) (domain.EventSchema, error)
}

type EventStore interface {
	ListEvents(ctx context.Context, tenantID string, limit int) ([]domain.Event, error)
	GetEvent(ctx context.Context, tenantID, eventID string) (domain.Event, error)
	GetRawPayload(ctx context.Context, tenantID, eventID, actorID string) (domain.RawPayload, error)
	GetNormalizedEvent(ctx context.Context, tenantID, eventID, actorID string, includeData bool) (domain.NormalizedEnvelope, error)
	ListEventTimeline(ctx context.Context, tenantID, eventID string, limit int) ([]map[string]any, error)
}

type DeliveryStore interface {
	ListDeliveries(ctx context.Context, tenantID string, limit int) ([]domain.Delivery, error)
	ListDeliveryAttempts(ctx context.Context, tenantID, deliveryID string, limit int) ([]domain.DeliveryAttempt, error)
	GetDeliveryAttempt(ctx context.Context, tenantID, attemptID string) (domain.DeliveryAttempt, error)
	RetryDelivery(ctx context.Context, tenantID, deliveryID, actorID, reason string) (domain.Delivery, error)
	CancelDelivery(ctx context.Context, tenantID, deliveryID, actorID, reason string) (domain.Delivery, error)
}

type OpsStore interface {
	OpsMetrics(ctx context.Context, tenantID string) (domain.OpsMetrics, error)
	ListWorkers(ctx context.Context, tenantID string, limit int) ([]domain.WorkerStatus, error)
	GetWorker(ctx context.Context, tenantID, workerID string) (domain.WorkerStatus, error)
	ListQueues(ctx context.Context, tenantID string) ([]domain.QueueStats, error)
	OpsStorage(ctx context.Context, tenantID string) (domain.OpsStorageStatus, error)
	ListMetricRollups(ctx context.Context, tenantID, metricName string, limit int) ([]domain.MetricRollup, error)
}

type SignalStore interface {
	CreateAlertRule(ctx context.Context, tenantID, actorID string, req CreateAlertRuleRequest) (domain.AlertRule, error)
	ListAlertRules(ctx context.Context, tenantID string, limit int) ([]domain.AlertRule, error)
	GetAlertRule(ctx context.Context, tenantID, alertID string) (domain.AlertRule, error)
	UpdateAlertRule(ctx context.Context, tenantID, alertID, actorID string, req UpdateAlertRuleRequest) (domain.AlertRule, error)
	DeleteAlertRule(ctx context.Context, tenantID, alertID, actorID, reason string) (domain.AlertRule, error)
	ListAlertFirings(ctx context.Context, tenantID, state string, limit int) ([]domain.AlertFiring, error)
	GetAlertFiring(ctx context.Context, tenantID, firingID string) (domain.AlertFiring, error)
	AcknowledgeAlertFiring(ctx context.Context, tenantID, firingID, actorID, reason string) (domain.AlertFiring, error)
	CreateNotificationChannel(ctx context.Context, tenantID, actorID string, req CreateNotificationChannelRequest) (domain.NotificationChannel, error)
	ListNotificationChannels(ctx context.Context, tenantID string, limit int) ([]domain.NotificationChannel, error)
	GetNotificationChannel(ctx context.Context, tenantID, channelID string) (domain.NotificationChannel, error)
	UpdateNotificationChannel(ctx context.Context, tenantID, channelID, actorID string, req UpdateNotificationChannelRequest) (domain.NotificationChannel, error)
	DeleteNotificationChannel(ctx context.Context, tenantID, channelID, actorID, reason string) (domain.NotificationChannel, error)
	TestNotificationChannel(ctx context.Context, tenantID, channelID, actorID, reason string) (domain.NotificationDelivery, error)
	ListNotificationDeliveries(ctx context.Context, tenantID, state string, limit int) ([]domain.NotificationDelivery, error)
	ListNotificationDeliveryAttempts(ctx context.Context, tenantID, deliveryID string, limit int) ([]domain.NotificationDeliveryAttempt, error)
	RetryNotificationDelivery(ctx context.Context, tenantID, deliveryID, actorID, reason string) (domain.NotificationDelivery, error)
	CreateSIEMSink(ctx context.Context, tenantID, actorID string, req CreateSIEMSinkRequest) (domain.SIEMSink, error)
	ListSIEMSinks(ctx context.Context, tenantID string, limit int) ([]domain.SIEMSink, error)
	GetSIEMSink(ctx context.Context, tenantID, sinkID string) (domain.SIEMSink, error)
	UpdateSIEMSink(ctx context.Context, tenantID, sinkID, actorID string, req UpdateSIEMSinkRequest) (domain.SIEMSink, error)
	DeleteSIEMSink(ctx context.Context, tenantID, sinkID, actorID, reason string) (domain.SIEMSink, error)
	TestSIEMSink(ctx context.Context, tenantID, sinkID, actorID, reason string) (domain.SIEMDelivery, error)
	ListSIEMDeliveries(ctx context.Context, tenantID, state string, limit int) ([]domain.SIEMDelivery, error)
	ListSIEMDeliveryAttempts(ctx context.Context, tenantID, deliveryID string, limit int) ([]domain.SIEMDeliveryAttempt, error)
	RetrySIEMDelivery(ctx context.Context, tenantID, deliveryID, actorID, reason string) (domain.SIEMDelivery, error)
}

type AuditStore interface {
	ListAuditEvents(ctx context.Context, tenantID string, limit int) ([]domain.AuditEvent, error)
	GetAuditChainHead(ctx context.Context, tenantID string) (domain.AuditChainHead, error)
	VerifyAuditChain(ctx context.Context, tenantID string, req AuditChainVerifyRequest) (domain.AuditChainVerification, error)
	CreateAuditChainAnchor(ctx context.Context, tenantID, actorID string, req AuditChainAnchorRequest) (domain.AuditChainAnchor, error)
	ListAuditChainAnchors(ctx context.Context, tenantID string, limit int) ([]domain.AuditChainAnchor, error)
	GetAuditChainAnchor(ctx context.Context, tenantID, anchorID string) (domain.AuditChainAnchor, error)
}

type RetentionStore interface {
	ListRetentionPolicies(ctx context.Context, tenantID string, limit int) ([]domain.RetentionPolicy, error)
	CreateRetentionPolicy(ctx context.Context, tenantID, actorID string, req CreateRetentionPolicyRequest) (domain.RetentionPolicy, error)
	UpdateRetentionPolicy(ctx context.Context, tenantID, policyID, actorID string, req UpdateRetentionPolicyRequest) (domain.RetentionPolicy, error)
}

type ProviderConnectionStore interface {
	CreateProviderConnection(ctx context.Context, tenantID, actorID string, req CreateProviderConnectionRequest) (domain.ProviderConnection, error)
	ListProviderConnections(ctx context.Context, tenantID string, limit int) ([]domain.ProviderConnection, error)
	GetProviderConnection(ctx context.Context, tenantID, connectionID string) (domain.ProviderConnection, error)
	VerifyProviderConnection(ctx context.Context, tenantID, connectionID, actorID, reason string) (domain.ProviderConnection, error)
	RevokeProviderConnection(ctx context.Context, tenantID, connectionID, actorID, reason string) (domain.ProviderConnection, error)
}

type ReconciliationStore interface {
	DryRunReconciliation(ctx context.Context, tenantID string, req ReconciliationJobRequest) (domain.ReconciliationJob, error)
	CreateReconciliationJob(ctx context.Context, tenantID, actorID string, req ReconciliationJobRequest) (domain.ReconciliationJob, error)
	ListReconciliationJobs(ctx context.Context, tenantID string, limit int) ([]domain.ReconciliationJob, error)
	GetReconciliationJob(ctx context.Context, tenantID, jobID string) (domain.ReconciliationJob, error)
	ListReconciliationItems(ctx context.Context, tenantID, jobID string, limit int) ([]domain.ReconciliationItem, error)
	CancelReconciliationJob(ctx context.Context, tenantID, jobID, actorID, reason string) (domain.ReconciliationJob, error)
}

type ProviderAdapterStore interface {
	CreateProviderAdapter(ctx context.Context, tenantID, actorID string, req CreateProviderAdapterRequest) (domain.ProviderAdapter, error)
	ListProviderAdapters(ctx context.Context, tenantID string, limit int) ([]domain.ProviderAdapter, error)
	GetProviderAdapter(ctx context.Context, tenantID, adapterID string) (domain.ProviderAdapter, error)
	CreateAdapterVersion(ctx context.Context, tenantID, adapterID, actorID string, req CreateAdapterVersionRequest) (domain.AdapterVersion, error)
	ListAdapterVersions(ctx context.Context, tenantID, adapterID string, limit int) ([]domain.AdapterVersion, error)
	CreateAdapterTestVector(ctx context.Context, tenantID, adapterID, versionID, actorID string, req CreateAdapterTestVectorRequest) (domain.AdapterTestVector, error)
	TransitionAdapterVersion(ctx context.Context, tenantID, adapterID, versionID, actorID string, req AdapterVersionTransitionRequest) (domain.AdapterVersion, error)
}

type EvidenceExportStore interface {
	CreateAuditExport(ctx context.Context, tenantID, actorID string, req CreateAuditExportRequest) (domain.EvidenceExport, error)
	ListAuditExports(ctx context.Context, tenantID string, limit int) ([]domain.EvidenceExport, error)
	GetAuditExport(ctx context.Context, tenantID, exportID string) (domain.EvidenceExport, error)
	DownloadAuditExport(ctx context.Context, tenantID, exportID, actorID string) (EvidenceExportDownload, error)
}

type DeadLetterStore interface {
	ListDeadLetter(ctx context.Context, tenantID string, limit int) ([]map[string]any, error)
	ReleaseDeadLetter(ctx context.Context, tenantID, entryID, actorID, reason string) (ReplayJob, error)
	BulkReleaseDeadLetter(ctx context.Context, tenantID string, entryIDs []string, actorID, reason string) ([]ReplayJob, error)
	ListQuarantine(ctx context.Context, tenantID string, limit int) ([]map[string]any, error)
	ApproveQuarantine(ctx context.Context, tenantID, entryID, actorID, reason string, routeAfterRelease bool) (map[string]any, error)
	RejectQuarantine(ctx context.Context, tenantID, entryID, actorID, reason string) (map[string]any, error)
}

type ReplayStore interface {
	DryRunReplay(ctx context.Context, tenantID string, req ReplayRequest) (ReplayDryRun, error)
	CreateReplay(ctx context.Context, tenantID, actorID string, req ReplayRequest) (ReplayJob, error)
	ListReplayJobs(ctx context.Context, tenantID string, limit int) ([]ReplayJob, error)
	ApproveReplayJob(ctx context.Context, tenantID, replayJobID, actorID, reason string) (ReplayJob, error)
	PauseReplayJob(ctx context.Context, tenantID, replayJobID, actorID, reason string) (ReplayJob, error)
	ResumeReplayJob(ctx context.Context, tenantID, replayJobID, actorID, reason string) (ReplayJob, error)
	CancelReplayJob(ctx context.Context, tenantID, replayJobID, actorID, reason string) (ReplayJob, error)
}

type TransformationStore interface {
	CreateTransformation(ctx context.Context, tenantID, actorID string, req CreateTransformationRequest) (domain.Transformation, error)
	ListTransformations(ctx context.Context, tenantID string, limit int) ([]domain.Transformation, error)
	GetTransformation(ctx context.Context, tenantID, transformationID string) (domain.Transformation, error)
	CreateTransformationVersion(ctx context.Context, tenantID, transformationID, actorID string, req CreateTransformationVersionRequest) (domain.TransformationVersion, error)
	ListTransformationVersions(ctx context.Context, tenantID, transformationID string, limit int) ([]domain.TransformationVersion, error)
	ActivateTransformationVersion(ctx context.Context, tenantID, transformationID, versionID, actorID, reason string) (domain.TransformationVersion, error)
}
