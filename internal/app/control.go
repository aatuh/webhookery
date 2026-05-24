package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/random"
	"webhookery/internal/ssrf"
	"webhookery/internal/transform"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrInvalidInput = errors.New("invalid input")
)

type ControlStore interface {
	CreateAPIKey(ctx context.Context, input APIKeyCreateInput) (domain.APIKey, error)
	ListAPIKeys(ctx context.Context, tenantID string, limit int) ([]domain.APIKey, error)
	RevokeAPIKey(ctx context.Context, tenantID, apiKeyID, actorID, reason string) (domain.APIKey, error)
	CreateSource(ctx context.Context, source domain.Source) (domain.Source, error)
	ListSources(ctx context.Context, tenantID string, limit int) ([]domain.Source, error)
	GetSource(ctx context.Context, tenantID, sourceID string) (domain.Source, error)
	UpdateSource(ctx context.Context, tenantID, sourceID, actorID string, req UpdateSourceRequest) (domain.Source, error)
	DeleteSource(ctx context.Context, tenantID, sourceID, actorID, reason string) (domain.Source, error)
	CreateEndpoint(ctx context.Context, endpoint domain.Endpoint) (domain.Endpoint, error)
	ListEndpoints(ctx context.Context, tenantID string, limit int) ([]domain.Endpoint, error)
	GetEndpoint(ctx context.Context, tenantID, endpointID string) (domain.Endpoint, error)
	UpdateEndpoint(ctx context.Context, tenantID, endpointID, actorID string, req UpdateEndpointRequest) (domain.Endpoint, error)
	DeleteEndpoint(ctx context.Context, tenantID, endpointID, actorID, reason string) (domain.Endpoint, error)
	TestEndpoint(ctx context.Context, tenantID, endpointID, actorID, reason string) (domain.Delivery, error)
	CreateSubscription(ctx context.Context, subscription domain.Subscription) (domain.Subscription, error)
	ListSubscriptions(ctx context.Context, tenantID string, limit int) ([]domain.Subscription, error)
	GetSubscription(ctx context.Context, tenantID, subscriptionID string) (domain.Subscription, error)
	UpdateSubscription(ctx context.Context, tenantID, subscriptionID, actorID string, req UpdateSubscriptionRequest) (domain.Subscription, error)
	DeleteSubscription(ctx context.Context, tenantID, subscriptionID, actorID, reason string) (domain.Subscription, error)
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
	RotateSourceSecret(ctx context.Context, tenantID, sourceID, actorID string, req RotateSourceSecretRequest) (domain.SourceSecretVersion, error)
	RotateEndpointSecret(ctx context.Context, tenantID, endpointID, actorID string, req RotateEndpointSecretRequest) (domain.EndpointSecretVersion, error)
	ListEvents(ctx context.Context, tenantID string, limit int) ([]domain.Event, error)
	GetEvent(ctx context.Context, tenantID, eventID string) (domain.Event, error)
	GetRawPayload(ctx context.Context, tenantID, eventID, actorID string) (domain.RawPayload, error)
	GetNormalizedEvent(ctx context.Context, tenantID, eventID, actorID string, includeData bool) (domain.NormalizedEnvelope, error)
	ListEventTimeline(ctx context.Context, tenantID, eventID string, limit int) ([]map[string]any, error)
	ListDeliveries(ctx context.Context, tenantID string, limit int) ([]domain.Delivery, error)
	ListDeliveryAttempts(ctx context.Context, tenantID, deliveryID string, limit int) ([]domain.DeliveryAttempt, error)
	GetDeliveryAttempt(ctx context.Context, tenantID, attemptID string) (domain.DeliveryAttempt, error)
	RetryDelivery(ctx context.Context, tenantID, deliveryID, actorID, reason string) (domain.Delivery, error)
	CancelDelivery(ctx context.Context, tenantID, deliveryID, actorID, reason string) (domain.Delivery, error)
	ListEndpointHealth(ctx context.Context, tenantID string, limit int) ([]domain.EndpointHealth, error)
	OpsMetrics(ctx context.Context, tenantID string) (domain.OpsMetrics, error)
	ListWorkers(ctx context.Context, tenantID string, limit int) ([]domain.WorkerStatus, error)
	GetWorker(ctx context.Context, tenantID, workerID string) (domain.WorkerStatus, error)
	ListQueues(ctx context.Context, tenantID string) ([]domain.QueueStats, error)
	OpsStorage(ctx context.Context, tenantID string) (domain.OpsStorageStatus, error)
	ListMetricRollups(ctx context.Context, tenantID, metricName string, limit int) ([]domain.MetricRollup, error)
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
	ListAuditEvents(ctx context.Context, tenantID string, limit int) ([]domain.AuditEvent, error)
	GetAuditChainHead(ctx context.Context, tenantID string) (domain.AuditChainHead, error)
	VerifyAuditChain(ctx context.Context, tenantID string, req AuditChainVerifyRequest) (domain.AuditChainVerification, error)
	CreateAuditChainAnchor(ctx context.Context, tenantID, actorID string, req AuditChainAnchorRequest) (domain.AuditChainAnchor, error)
	ListAuditChainAnchors(ctx context.Context, tenantID string, limit int) ([]domain.AuditChainAnchor, error)
	GetAuditChainAnchor(ctx context.Context, tenantID, anchorID string) (domain.AuditChainAnchor, error)
	ListRetentionPolicies(ctx context.Context, tenantID string, limit int) ([]domain.RetentionPolicy, error)
	CreateRetentionPolicy(ctx context.Context, tenantID, actorID string, req CreateRetentionPolicyRequest) (domain.RetentionPolicy, error)
	UpdateRetentionPolicy(ctx context.Context, tenantID, policyID, actorID string, req UpdateRetentionPolicyRequest) (domain.RetentionPolicy, error)
	CreateProviderConnection(ctx context.Context, tenantID, actorID string, req CreateProviderConnectionRequest) (domain.ProviderConnection, error)
	ListProviderConnections(ctx context.Context, tenantID string, limit int) ([]domain.ProviderConnection, error)
	GetProviderConnection(ctx context.Context, tenantID, connectionID string) (domain.ProviderConnection, error)
	VerifyProviderConnection(ctx context.Context, tenantID, connectionID, actorID, reason string) (domain.ProviderConnection, error)
	RevokeProviderConnection(ctx context.Context, tenantID, connectionID, actorID, reason string) (domain.ProviderConnection, error)
	DryRunReconciliation(ctx context.Context, tenantID string, req ReconciliationJobRequest) (domain.ReconciliationJob, error)
	CreateReconciliationJob(ctx context.Context, tenantID, actorID string, req ReconciliationJobRequest) (domain.ReconciliationJob, error)
	ListReconciliationJobs(ctx context.Context, tenantID string, limit int) ([]domain.ReconciliationJob, error)
	GetReconciliationJob(ctx context.Context, tenantID, jobID string) (domain.ReconciliationJob, error)
	ListReconciliationItems(ctx context.Context, tenantID, jobID string, limit int) ([]domain.ReconciliationItem, error)
	CancelReconciliationJob(ctx context.Context, tenantID, jobID, actorID, reason string) (domain.ReconciliationJob, error)
	CreateProviderAdapter(ctx context.Context, tenantID, actorID string, req CreateProviderAdapterRequest) (domain.ProviderAdapter, error)
	ListProviderAdapters(ctx context.Context, tenantID string, limit int) ([]domain.ProviderAdapter, error)
	GetProviderAdapter(ctx context.Context, tenantID, adapterID string) (domain.ProviderAdapter, error)
	CreateAdapterVersion(ctx context.Context, tenantID, adapterID, actorID string, req CreateAdapterVersionRequest) (domain.AdapterVersion, error)
	ListAdapterVersions(ctx context.Context, tenantID, adapterID string, limit int) ([]domain.AdapterVersion, error)
	CreateAdapterTestVector(ctx context.Context, tenantID, adapterID, versionID, actorID string, req CreateAdapterTestVectorRequest) (domain.AdapterTestVector, error)
	TransitionAdapterVersion(ctx context.Context, tenantID, adapterID, versionID, actorID string, req AdapterVersionTransitionRequest) (domain.AdapterVersion, error)
	CreateAuditExport(ctx context.Context, tenantID, actorID string, req CreateAuditExportRequest) (domain.EvidenceExport, error)
	ListAuditExports(ctx context.Context, tenantID string, limit int) ([]domain.EvidenceExport, error)
	GetAuditExport(ctx context.Context, tenantID, exportID string) (domain.EvidenceExport, error)
	DownloadAuditExport(ctx context.Context, tenantID, exportID, actorID string) (EvidenceExportDownload, error)
	ListDeadLetter(ctx context.Context, tenantID string, limit int) ([]map[string]any, error)
	ReleaseDeadLetter(ctx context.Context, tenantID, entryID, actorID, reason string) (ReplayJob, error)
	BulkReleaseDeadLetter(ctx context.Context, tenantID string, entryIDs []string, actorID, reason string) ([]ReplayJob, error)
	ListQuarantine(ctx context.Context, tenantID string, limit int) ([]map[string]any, error)
	ApproveQuarantine(ctx context.Context, tenantID, entryID, actorID, reason string, routeAfterRelease bool) (map[string]any, error)
	RejectQuarantine(ctx context.Context, tenantID, entryID, actorID, reason string) (map[string]any, error)
	DryRunReplay(ctx context.Context, tenantID string, req ReplayRequest) (ReplayDryRun, error)
	CreateReplay(ctx context.Context, tenantID, actorID string, req ReplayRequest) (ReplayJob, error)
	ListReplayJobs(ctx context.Context, tenantID string, limit int) ([]ReplayJob, error)
	ApproveReplayJob(ctx context.Context, tenantID, replayJobID, actorID, reason string) (ReplayJob, error)
	PauseReplayJob(ctx context.Context, tenantID, replayJobID, actorID, reason string) (ReplayJob, error)
	ResumeReplayJob(ctx context.Context, tenantID, replayJobID, actorID, reason string) (ReplayJob, error)
	CancelReplayJob(ctx context.Context, tenantID, replayJobID, actorID, reason string) (ReplayJob, error)
	CreateTransformation(ctx context.Context, tenantID, actorID string, req CreateTransformationRequest) (domain.Transformation, error)
	ListTransformations(ctx context.Context, tenantID string, limit int) ([]domain.Transformation, error)
	GetTransformation(ctx context.Context, tenantID, transformationID string) (domain.Transformation, error)
	CreateTransformationVersion(ctx context.Context, tenantID, transformationID, actorID string, req CreateTransformationVersionRequest) (domain.TransformationVersion, error)
	ListTransformationVersions(ctx context.Context, tenantID, transformationID string, limit int) ([]domain.TransformationVersion, error)
	ActivateTransformationVersion(ctx context.Context, tenantID, transformationID, versionID, actorID, reason string) (domain.TransformationVersion, error)
}

type ControlService struct {
	store         ControlStore
	ssrfValidator ssrf.Validator
	runtimeConfig domain.OpsConfig
}

func NewControlService(store ControlStore, validator ssrf.Validator) *ControlService {
	return &ControlService{store: store, ssrfValidator: validator}
}

func NewControlServiceWithRuntimeConfig(store ControlStore, validator ssrf.Validator, runtimeConfig domain.OpsConfig) *ControlService {
	return &ControlService{store: store, ssrfValidator: validator, runtimeConfig: runtimeConfig}
}

type CreateSourceRequest struct {
	Name               string `json:"name"`
	Provider           string `json:"provider"`
	Adapter            string `json:"adapter"`
	VerificationSecret string `json:"verification_secret"`
}

type UpdateSourceRequest struct {
	Name   *string `json:"name,omitempty"`
	State  *string `json:"state,omitempty"`
	Reason string  `json:"reason"`
}

type APIKeyCreateInput struct {
	Key     domain.APIKey
	Role    authz.Role
	Email   string
	ActorID string
}

type CreateAPIKeyRequest struct {
	Name   string     `json:"name"`
	UserID string     `json:"user_id"`
	Email  string     `json:"email"`
	Role   authz.Role `json:"role"`
	Scopes []string   `json:"scopes"`
}

type APIKeyCreated struct {
	Key   domain.APIKey `json:"key"`
	Token string        `json:"token"`
}

type RevokeAPIKeyRequest struct {
	Reason string `json:"reason"`
}

type CreateEndpointRequest struct {
	Name              string `json:"name"`
	URL               string `json:"url"`
	RetryPolicyID     string `json:"retry_policy_id,omitempty"`
	MTLSClientCertPEM string `json:"mtls_client_cert_pem,omitempty"`
	MTLSClientKeyPEM  string `json:"mtls_client_key_pem,omitempty"`
}

type UpdateEndpointRequest struct {
	Name          *string `json:"name,omitempty"`
	URL           *string `json:"url,omitempty"`
	State         *string `json:"state,omitempty"`
	RetryPolicyID *string `json:"retry_policy_id,omitempty"`
	Reason        string  `json:"reason"`
}

type TestEndpointRequest struct {
	Reason string `json:"reason"`
}

type CreateSubscriptionRequest struct {
	EndpointID       string   `json:"endpoint_id"`
	EventTypes       []string `json:"event_types"`
	PayloadFormat    string   `json:"payload_format"`
	TransformationID string   `json:"transformation_id,omitempty"`
}

type UpdateSubscriptionRequest struct {
	EndpointID       *string  `json:"endpoint_id,omitempty"`
	EventTypes       []string `json:"event_types,omitempty"`
	PayloadFormat    *string  `json:"payload_format,omitempty"`
	TransformationID *string  `json:"transformation_id,omitempty"`
	State            *string  `json:"state,omitempty"`
	Reason           string   `json:"reason"`
}

type CreateRouteRequest struct {
	SourceID         string   `json:"source_id"`
	Name             string   `json:"name"`
	Priority         int      `json:"priority"`
	EventTypes       []string `json:"event_types"`
	EndpointID       string   `json:"endpoint_id"`
	RetryPolicyID    string   `json:"retry_policy_id,omitempty"`
	TransformationID string   `json:"transformation_id,omitempty"`
	State            string   `json:"state"`
}

type UpdateRouteRequest struct {
	SourceID         *string  `json:"source_id,omitempty"`
	Name             *string  `json:"name,omitempty"`
	Priority         *int     `json:"priority,omitempty"`
	EventTypes       []string `json:"event_types,omitempty"`
	EndpointID       *string  `json:"endpoint_id,omitempty"`
	RetryPolicyID    *string  `json:"retry_policy_id,omitempty"`
	TransformationID *string  `json:"transformation_id,omitempty"`
	State            *string  `json:"state,omitempty"`
	Reason           string   `json:"reason"`
}

type ActivateRouteRequest struct {
	Reason string `json:"reason"`
}

type RouteDryRun struct {
	Matched               bool             `json:"matched"`
	WouldCreateDeliveries []map[string]any `json:"would_create_deliveries"`
	Explanation           []map[string]any `json:"explanation"`
}

type CreateEventTypeRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type UpdateEventTypeRequest struct {
	Description *string `json:"description,omitempty"`
	State       *string `json:"state,omitempty"`
	Reason      string  `json:"reason"`
}

type CreateEventSchemaRequest struct {
	Version string `json:"version"`
	Schema  string `json:"schema"`
}

type UpdateEventSchemaRequest struct {
	State  *string `json:"state,omitempty"`
	Reason string  `json:"reason"`
}

type ValidateSchemaRequest struct {
	Payload string `json:"payload"`
}

type SchemaValidationResult struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

type CheckSchemaCompatibilityRequest struct {
	NewSchema string `json:"new_schema"`
}

type SchemaCompatibilityResult struct {
	Compatible bool     `json:"compatible"`
	Errors     []string `json:"errors,omitempty"`
}

type RotateSourceSecretRequest struct {
	NewSecret        string `json:"new_secret"`
	GracePeriodHours int    `json:"grace_period_hours,omitempty"`
	Reason           string `json:"reason"`
}

type RotateEndpointSecretRequest struct {
	GracePeriodHours int    `json:"grace_period_hours,omitempty"`
	Reason           string `json:"reason"`
}

type CreateRetryPolicyRequest struct {
	Name                string `json:"name"`
	MaxAttempts         int    `json:"max_attempts"`
	MaxDurationSeconds  int    `json:"max_duration_seconds"`
	InitialDelaySeconds int    `json:"initial_delay_seconds"`
	MaxDelaySeconds     int    `json:"max_delay_seconds"`
	RateLimitPerMinute  int    `json:"rate_limit_per_minute,omitempty"`
	State               string `json:"state,omitempty"`
}

type UpdateRetryPolicyRequest struct {
	Name                *string `json:"name,omitempty"`
	MaxAttempts         *int    `json:"max_attempts,omitempty"`
	MaxDurationSeconds  *int    `json:"max_duration_seconds,omitempty"`
	InitialDelaySeconds *int    `json:"initial_delay_seconds,omitempty"`
	MaxDelaySeconds     *int    `json:"max_delay_seconds,omitempty"`
	RateLimitPerMinute  *int    `json:"rate_limit_per_minute,omitempty"`
	State               *string `json:"state,omitempty"`
	Reason              string  `json:"reason"`
}

const (
	ReplayConfigCurrent  = "current"
	ReplayConfigOriginal = "original"
)

type ReplayRequest struct {
	EventID            string `json:"event_id"`
	DeliveryID         string `json:"delivery_id"`
	EndpointID         string `json:"endpoint_id"`
	Reason             string `json:"reason"`
	DryRun             bool   `json:"dry_run"`
	ConfigMode         string `json:"config_mode,omitempty"`
	RateLimitPerMinute int    `json:"rate_limit_per_minute,omitempty"`
	RequireApproval    bool   `json:"require_approval,omitempty"`
}

type DeadLetterReleaseRequest struct {
	Reason string `json:"reason"`
}

type DeadLetterBulkReleaseRequest struct {
	EntryIDs []string `json:"entry_ids"`
	Reason   string   `json:"reason"`
}

type QuarantineDecisionRequest struct {
	Reason            string `json:"reason"`
	RouteAfterRelease bool   `json:"route_after_release"`
}

type ReplayDryRun struct {
	WouldReplayEvents     int      `json:"would_replay_events"`
	WouldCreateDeliveries int      `json:"would_create_deliveries"`
	Warnings              []string `json:"warnings"`
}

type ReplayJob struct {
	ID                 string     `json:"id"`
	State              string     `json:"state"`
	ScopeHash          string     `json:"scope_hash"`
	ConfigMode         string     `json:"config_mode,omitempty"`
	RateLimitPerMinute int        `json:"rate_limit_per_minute,omitempty"`
	TotalItems         int        `json:"total_items"`
	ProcessedItems     int        `json:"processed_items"`
	FailedItems        int        `json:"failed_items"`
	ApprovalRequired   bool       `json:"approval_required"`
	ApprovedBy         string     `json:"approved_by,omitempty"`
	ApprovedAt         *time.Time `json:"approved_at,omitempty"`
}

type StateChangeRequest struct {
	Reason string `json:"reason"`
}

type CreateRetentionPolicyRequest struct {
	ResourceType  string `json:"resource_type"`
	SourceID      string `json:"source_id,omitempty"`
	RetentionDays int    `json:"retention_days"`
	State         string `json:"state,omitempty"`
	LegalHold     bool   `json:"legal_hold,omitempty"`
	HoldReason    string `json:"hold_reason,omitempty"`
}

type UpdateRetentionPolicyRequest struct {
	RetentionDays *int    `json:"retention_days,omitempty"`
	State         string  `json:"state,omitempty"`
	SourceID      *string `json:"source_id,omitempty"`
	LegalHold     *bool   `json:"legal_hold,omitempty"`
	HoldReason    *string `json:"hold_reason,omitempty"`
}

type CreateProviderConnectionRequest struct {
	Name           string            `json:"name"`
	Provider       string            `json:"provider"`
	CredentialType string            `json:"credential_type,omitempty"`
	Credential     string            `json:"credential"`
	Config         map[string]string `json:"config,omitempty"`
}

type ProviderConnectionStateRequest struct {
	Reason string `json:"reason"`
}

type ReconciliationJobRequest struct {
	ConnectionID    string    `json:"connection_id"`
	DryRun          bool      `json:"dry_run,omitempty"`
	CaptureMissing  bool      `json:"capture_missing,omitempty"`
	RouteRecovered  bool      `json:"route_recovered,omitempty"`
	RedeliverFailed bool      `json:"redeliver_failed,omitempty"`
	ScopeObjectID   string    `json:"scope_object_id,omitempty"`
	WindowStart     time.Time `json:"window_start,omitempty"`
	WindowEnd       time.Time `json:"window_end,omitempty"`
	Reason          string    `json:"reason,omitempty"`
}

type CreateAuditExportRequest struct {
	From                 time.Time `json:"from,omitempty"`
	To                   time.Time `json:"to,omitempty"`
	IncludeRawPayloads   bool      `json:"include_raw_payloads"`
	IncludeTimelines     bool      `json:"include_timelines"`
	IncludePayloadBodies bool      `json:"include_payload_bodies"`
	Reason               string    `json:"reason,omitempty"`
}

type AuditChainVerifyRequest struct {
	FromSequence int64 `json:"from_sequence,omitempty"`
	ToSequence   int64 `json:"to_sequence,omitempty"`
}

type AuditChainAnchorRequest struct {
	FromSequence int64  `json:"from_sequence,omitempty"`
	ToSequence   int64  `json:"to_sequence,omitempty"`
	Reason       string `json:"reason"`
}

type CreateTransformationRequest struct {
	Name       string          `json:"name"`
	Operations json.RawMessage `json:"operations,omitempty"`
}

type CreateTransformationVersionRequest struct {
	Operations json.RawMessage `json:"operations"`
}

type ActivateTransformationVersionRequest struct {
	Reason string `json:"reason"`
}

type CreateAlertRuleRequest struct {
	Name          string            `json:"name"`
	RuleType      string            `json:"rule_type"`
	MetricName    string            `json:"metric_name,omitempty"`
	Threshold     float64           `json:"threshold"`
	Comparator    string            `json:"comparator,omitempty"`
	WindowSeconds int               `json:"window_seconds,omitempty"`
	Dimensions    map[string]string `json:"dimensions,omitempty"`
	State         string            `json:"state,omitempty"`
	ChannelIDs    []string          `json:"channel_ids,omitempty"`
}

type UpdateAlertRuleRequest struct {
	Name          *string           `json:"name,omitempty"`
	Threshold     *float64          `json:"threshold,omitempty"`
	Comparator    *string           `json:"comparator,omitempty"`
	WindowSeconds *int              `json:"window_seconds,omitempty"`
	Dimensions    map[string]string `json:"dimensions,omitempty"`
	State         *string           `json:"state,omitempty"`
	ChannelIDs    *[]string         `json:"channel_ids,omitempty"`
	Reason        string            `json:"reason"`
}

type CreateNotificationChannelRequest struct {
	Name          string `json:"name"`
	ChannelType   string `json:"channel_type,omitempty"`
	URL           string `json:"url"`
	SigningSecret string `json:"signing_secret"`
}

type UpdateNotificationChannelRequest struct {
	Name          *string `json:"name,omitempty"`
	URL           *string `json:"url,omitempty"`
	SigningSecret *string `json:"signing_secret,omitempty"`
	State         *string `json:"state,omitempty"`
	Reason        string  `json:"reason"`
}

type CreateSIEMSinkRequest struct {
	Name          string `json:"name"`
	SinkType      string `json:"sink_type,omitempty"`
	URL           string `json:"url"`
	SigningSecret string `json:"signing_secret"`
}

type UpdateSIEMSinkRequest struct {
	Name          *string `json:"name,omitempty"`
	URL           *string `json:"url,omitempty"`
	SigningSecret *string `json:"signing_secret,omitempty"`
	State         *string `json:"state,omitempty"`
	Reason        string  `json:"reason"`
}

type EvidenceExportDownload struct {
	Export      domain.EvidenceExport
	Filename    string
	ContentType string
	Body        []byte
}

func (s *ControlService) CreateAPIKey(ctx context.Context, actor authz.Actor, req CreateAPIKeyRequest) (APIKeyCreated, error) {
	if !authz.Can(actor, "api_keys:write", actor.TenantID) {
		return APIKeyCreated{}, ErrForbidden
	}
	if strings.TrimSpace(req.Name) == "" {
		return APIKeyCreated{}, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	role := req.Role
	if role == "" {
		role = actor.Role
	}
	if !validRole(role) {
		return APIKeyCreated{}, fmt.Errorf("%w: role is invalid", ErrInvalidInput)
	}
	scopes := normalizeScopes(req.Scopes)
	if len(scopes) == 0 {
		return APIKeyCreated{}, fmt.Errorf("%w: scopes are required", ErrInvalidInput)
	}
	userID := strings.TrimSpace(req.UserID)
	if userID == "" {
		id, err := random.Token("usr", 18)
		if err != nil {
			return APIKeyCreated{}, err
		}
		userID = id
	}
	token, err := random.Token("whkey", 32)
	if err != nil {
		return APIKeyCreated{}, err
	}
	key := domain.APIKey{
		TenantID: actor.TenantID,
		UserID:   userID,
		Name:     strings.TrimSpace(req.Name),
		Prefix:   tokenPrefix(token),
		Last4:    tokenLast4(token),
		Hash:     HashToken(token),
		Scopes:   scopes,
		State:    domain.StateActive,
	}
	stored, err := s.store.CreateAPIKey(ctx, APIKeyCreateInput{Key: key, Role: role, Email: strings.TrimSpace(req.Email), ActorID: actor.ID})
	if err != nil {
		return APIKeyCreated{}, err
	}
	stored.Hash = ""
	return APIKeyCreated{Key: stored, Token: token}, nil
}

func (s *ControlService) ListAPIKeys(ctx context.Context, actor authz.Actor, limit int) ([]domain.APIKey, error) {
	if !authz.Can(actor, "api_keys:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	keys, err := s.store.ListAPIKeys(ctx, actor.TenantID, normalizeLimit(limit))
	if err != nil {
		return nil, err
	}
	for i := range keys {
		keys[i].Hash = ""
	}
	return keys, nil
}

func (s *ControlService) RevokeAPIKey(ctx context.Context, actor authz.Actor, apiKeyID string, req RevokeAPIKeyRequest) (domain.APIKey, error) {
	if !authz.Can(actor, "api_keys:write", actor.TenantID) {
		return domain.APIKey{}, ErrForbidden
	}
	if strings.TrimSpace(req.Reason) == "" {
		return domain.APIKey{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	key, err := s.store.RevokeAPIKey(ctx, actor.TenantID, apiKeyID, actor.ID, req.Reason)
	key.Hash = ""
	return key, err
}

func (s *ControlService) CreateSource(ctx context.Context, actor authz.Actor, req CreateSourceRequest) (domain.Source, error) {
	if !authz.Can(actor, "sources:write", actor.TenantID) {
		return domain.Source{}, ErrForbidden
	}
	if req.Provider == "" || (req.Provider != "internal" && req.VerificationSecret == "") {
		return domain.Source{}, fmt.Errorf("%w: provider and verification_secret are required", ErrInvalidInput)
	}
	adapter := req.Adapter
	if adapter == "" {
		adapter = req.Provider
	}
	return s.store.CreateSource(ctx, domain.Source{
		TenantID:           actor.TenantID,
		Name:               req.Name,
		Provider:           req.Provider,
		Adapter:            adapter,
		State:              domain.StateActive,
		VerificationSecret: []byte(req.VerificationSecret),
	})
}

func (s *ControlService) ListSources(ctx context.Context, actor authz.Actor, limit int) ([]domain.Source, error) {
	if !authz.Can(actor, "sources:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListSources(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetSource(ctx context.Context, actor authz.Actor, sourceID string) (domain.Source, error) {
	if !authz.Can(actor, "sources:read", actor.TenantID) {
		return domain.Source{}, ErrForbidden
	}
	if strings.TrimSpace(sourceID) == "" {
		return domain.Source{}, fmt.Errorf("%w: source_id is required", ErrInvalidInput)
	}
	return s.store.GetSource(ctx, actor.TenantID, sourceID)
}

func (s *ControlService) UpdateSource(ctx context.Context, actor authz.Actor, sourceID string, req UpdateSourceRequest) (domain.Source, error) {
	if !authz.Can(actor, "sources:write", actor.TenantID) {
		return domain.Source{}, ErrForbidden
	}
	if strings.TrimSpace(sourceID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.Source{}, fmt.Errorf("%w: source_id and reason are required", ErrInvalidInput)
	}
	if req.Name == nil && req.State == nil {
		return domain.Source{}, fmt.Errorf("%w: at least one source field is required", ErrInvalidInput)
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			return domain.Source{}, fmt.Errorf("%w: name cannot be empty", ErrInvalidInput)
		}
		req.Name = &name
	}
	if req.State != nil {
		state := strings.TrimSpace(*req.State)
		if state != domain.StateActive && state != domain.StateDisabled {
			return domain.Source{}, fmt.Errorf("%w: source state must be active or disabled", ErrInvalidInput)
		}
		req.State = &state
	}
	return s.store.UpdateSource(ctx, actor.TenantID, sourceID, actor.ID, req)
}

func (s *ControlService) DeleteSource(ctx context.Context, actor authz.Actor, sourceID string, req StateChangeRequest) (domain.Source, error) {
	if !authz.Can(actor, "sources:write", actor.TenantID) {
		return domain.Source{}, ErrForbidden
	}
	if strings.TrimSpace(sourceID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.Source{}, fmt.Errorf("%w: source_id and reason are required", ErrInvalidInput)
	}
	return s.store.DeleteSource(ctx, actor.TenantID, sourceID, actor.ID, req.Reason)
}

func (s *ControlService) CreateEndpoint(ctx context.Context, actor authz.Actor, req CreateEndpointRequest) (domain.Endpoint, ssrf.Result, error) {
	if !authz.Can(actor, "endpoints:write", actor.TenantID) {
		return domain.Endpoint{}, ssrf.Result{}, ErrForbidden
	}
	if req.URL == "" {
		return domain.Endpoint{}, ssrf.Result{}, fmt.Errorf("%w: url is required", ErrInvalidInput)
	}
	result := s.ssrfValidator.Validate(ctx, req.URL, ssrf.DefaultPolicy())
	if !result.Allowed {
		return domain.Endpoint{}, result, fmt.Errorf("%w: endpoint_url_blocked", ErrInvalidInput)
	}
	mtlsEnabled, mtlsSubject, mtlsCertPEM, mtlsKeyPEM, err := validateEndpointMTLS(req.MTLSClientCertPEM, req.MTLSClientKeyPEM)
	if err != nil {
		return domain.Endpoint{}, result, err
	}
	endpoint, err := s.store.CreateEndpoint(ctx, domain.Endpoint{
		TenantID:          actor.TenantID,
		Name:              req.Name,
		URL:               result.NormalizedURL,
		State:             domain.StateActive,
		RetryPolicyID:     strings.TrimSpace(req.RetryPolicyID),
		MTLSEnabled:       mtlsEnabled,
		MTLSCertSubject:   mtlsSubject,
		MTLSClientCertPEM: mtlsCertPEM,
		MTLSClientKeyPEM:  mtlsKeyPEM,
	})
	return endpoint, result, err
}

func (s *ControlService) ValidateEndpointURL(ctx context.Context, rawURL string) ssrf.Result {
	return s.ssrfValidator.Validate(ctx, rawURL, ssrf.DefaultPolicy())
}

func (s *ControlService) ListEndpoints(ctx context.Context, actor authz.Actor, limit int) ([]domain.Endpoint, error) {
	if !authz.Can(actor, "endpoints:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListEndpoints(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetEndpoint(ctx context.Context, actor authz.Actor, endpointID string) (domain.Endpoint, error) {
	if !authz.Can(actor, "endpoints:read", actor.TenantID) {
		return domain.Endpoint{}, ErrForbidden
	}
	if strings.TrimSpace(endpointID) == "" {
		return domain.Endpoint{}, fmt.Errorf("%w: endpoint_id is required", ErrInvalidInput)
	}
	return s.store.GetEndpoint(ctx, actor.TenantID, endpointID)
}

func (s *ControlService) UpdateEndpoint(ctx context.Context, actor authz.Actor, endpointID string, req UpdateEndpointRequest) (domain.Endpoint, ssrf.Result, error) {
	if !s.authorized(ctx, actor, "endpoints:write", "endpoint", endpointID, "production") {
		return domain.Endpoint{}, ssrf.Result{}, ErrForbidden
	}
	if strings.TrimSpace(endpointID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.Endpoint{}, ssrf.Result{}, fmt.Errorf("%w: endpoint_id and reason are required", ErrInvalidInput)
	}
	if req.Name == nil && req.URL == nil && req.State == nil && req.RetryPolicyID == nil {
		return domain.Endpoint{}, ssrf.Result{}, fmt.Errorf("%w: at least one endpoint field is required", ErrInvalidInput)
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			return domain.Endpoint{}, ssrf.Result{}, fmt.Errorf("%w: name cannot be empty", ErrInvalidInput)
		}
		req.Name = &name
	}
	var result ssrf.Result
	if req.URL != nil {
		rawURL := strings.TrimSpace(*req.URL)
		if rawURL == "" {
			return domain.Endpoint{}, ssrf.Result{}, fmt.Errorf("%w: url cannot be empty", ErrInvalidInput)
		}
		result = s.ssrfValidator.Validate(ctx, rawURL, ssrf.DefaultPolicy())
		if !result.Allowed {
			return domain.Endpoint{}, result, fmt.Errorf("%w: endpoint_url_blocked", ErrInvalidInput)
		}
		req.URL = &result.NormalizedURL
	}
	if req.State != nil {
		state := strings.TrimSpace(*req.State)
		if state != domain.StateActive && state != domain.StateDisabled {
			return domain.Endpoint{}, result, fmt.Errorf("%w: endpoint state must be active or disabled", ErrInvalidInput)
		}
		req.State = &state
	}
	if req.RetryPolicyID != nil {
		retryPolicyID := strings.TrimSpace(*req.RetryPolicyID)
		req.RetryPolicyID = &retryPolicyID
	}
	endpoint, err := s.store.UpdateEndpoint(ctx, actor.TenantID, endpointID, actor.ID, req)
	return endpoint, result, err
}

func (s *ControlService) DeleteEndpoint(ctx context.Context, actor authz.Actor, endpointID string, req StateChangeRequest) (domain.Endpoint, error) {
	if !authz.Can(actor, "endpoints:write", actor.TenantID) {
		return domain.Endpoint{}, ErrForbidden
	}
	if strings.TrimSpace(endpointID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.Endpoint{}, fmt.Errorf("%w: endpoint_id and reason are required", ErrInvalidInput)
	}
	return s.store.DeleteEndpoint(ctx, actor.TenantID, endpointID, actor.ID, req.Reason)
}

func (s *ControlService) TestEndpoint(ctx context.Context, actor authz.Actor, endpointID string, req TestEndpointRequest) (domain.Delivery, error) {
	if !authz.Can(actor, "endpoints:write", actor.TenantID) {
		return domain.Delivery{}, ErrForbidden
	}
	if strings.TrimSpace(endpointID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.Delivery{}, fmt.Errorf("%w: endpoint_id and reason are required", ErrInvalidInput)
	}
	return s.store.TestEndpoint(ctx, actor.TenantID, endpointID, actor.ID, req.Reason)
}

func (s *ControlService) CreateSubscription(ctx context.Context, actor authz.Actor, req CreateSubscriptionRequest) (domain.Subscription, error) {
	if !authz.Can(actor, "subscriptions:write", actor.TenantID) {
		return domain.Subscription{}, ErrForbidden
	}
	eventTypes := normalizeEventTypes(req.EventTypes)
	if strings.TrimSpace(req.EndpointID) == "" || len(eventTypes) == 0 {
		return domain.Subscription{}, fmt.Errorf("%w: endpoint_id and event_types are required", ErrInvalidInput)
	}
	payloadFormat := req.PayloadFormat
	if payloadFormat == "" {
		payloadFormat = "canonical_json"
	}
	return s.store.CreateSubscription(ctx, domain.Subscription{
		TenantID:         actor.TenantID,
		EndpointID:       strings.TrimSpace(req.EndpointID),
		EventTypes:       eventTypes,
		PayloadFormat:    strings.TrimSpace(payloadFormat),
		TransformationID: strings.TrimSpace(req.TransformationID),
		State:            domain.StateActive,
	})
}

func (s *ControlService) ListSubscriptions(ctx context.Context, actor authz.Actor, limit int) ([]domain.Subscription, error) {
	if !authz.Can(actor, "subscriptions:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListSubscriptions(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetSubscription(ctx context.Context, actor authz.Actor, subscriptionID string) (domain.Subscription, error) {
	if !authz.Can(actor, "subscriptions:read", actor.TenantID) {
		return domain.Subscription{}, ErrForbidden
	}
	if strings.TrimSpace(subscriptionID) == "" {
		return domain.Subscription{}, fmt.Errorf("%w: subscription_id is required", ErrInvalidInput)
	}
	return s.store.GetSubscription(ctx, actor.TenantID, subscriptionID)
}

func (s *ControlService) UpdateSubscription(ctx context.Context, actor authz.Actor, subscriptionID string, req UpdateSubscriptionRequest) (domain.Subscription, error) {
	if !authz.Can(actor, "subscriptions:write", actor.TenantID) {
		return domain.Subscription{}, ErrForbidden
	}
	if strings.TrimSpace(subscriptionID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.Subscription{}, fmt.Errorf("%w: subscription_id and reason are required", ErrInvalidInput)
	}
	if req.EndpointID == nil && req.EventTypes == nil && req.PayloadFormat == nil && req.TransformationID == nil && req.State == nil {
		return domain.Subscription{}, fmt.Errorf("%w: at least one subscription field is required", ErrInvalidInput)
	}
	if req.EndpointID != nil {
		endpointID := strings.TrimSpace(*req.EndpointID)
		if endpointID == "" {
			return domain.Subscription{}, fmt.Errorf("%w: endpoint_id cannot be empty", ErrInvalidInput)
		}
		req.EndpointID = &endpointID
	}
	if req.EventTypes != nil {
		req.EventTypes = normalizeEventTypes(req.EventTypes)
		if len(req.EventTypes) == 0 {
			return domain.Subscription{}, fmt.Errorf("%w: event_types cannot be empty", ErrInvalidInput)
		}
	}
	if req.PayloadFormat != nil {
		payloadFormat := strings.TrimSpace(*req.PayloadFormat)
		if payloadFormat == "" {
			return domain.Subscription{}, fmt.Errorf("%w: payload_format cannot be empty", ErrInvalidInput)
		}
		req.PayloadFormat = &payloadFormat
	}
	if req.TransformationID != nil {
		transformationID := strings.TrimSpace(*req.TransformationID)
		req.TransformationID = &transformationID
	}
	if req.State != nil {
		state := strings.TrimSpace(*req.State)
		if state != domain.StateActive && state != domain.StateDisabled {
			return domain.Subscription{}, fmt.Errorf("%w: subscription state must be active or disabled", ErrInvalidInput)
		}
		req.State = &state
	}
	return s.store.UpdateSubscription(ctx, actor.TenantID, subscriptionID, actor.ID, req)
}

func (s *ControlService) DeleteSubscription(ctx context.Context, actor authz.Actor, subscriptionID string, req StateChangeRequest) (domain.Subscription, error) {
	if !authz.Can(actor, "subscriptions:write", actor.TenantID) {
		return domain.Subscription{}, ErrForbidden
	}
	if strings.TrimSpace(subscriptionID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.Subscription{}, fmt.Errorf("%w: subscription_id and reason are required", ErrInvalidInput)
	}
	return s.store.DeleteSubscription(ctx, actor.TenantID, subscriptionID, actor.ID, req.Reason)
}

func (s *ControlService) CreateRoute(ctx context.Context, actor authz.Actor, req CreateRouteRequest) (domain.Route, error) {
	if !authz.Can(actor, "routes:write", actor.TenantID) {
		return domain.Route{}, ErrForbidden
	}
	eventTypes := normalizeEventTypes(req.EventTypes)
	if strings.TrimSpace(req.SourceID) == "" || strings.TrimSpace(req.EndpointID) == "" || len(eventTypes) == 0 {
		return domain.Route{}, fmt.Errorf("%w: source_id, endpoint_id, and event_types are required", ErrInvalidInput)
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return domain.Route{}, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	state := strings.TrimSpace(req.State)
	if state == "" {
		state = domain.StateDraft
	}
	if !validRouteState(state) {
		return domain.Route{}, fmt.Errorf("%w: route state must be draft, active, or inactive", ErrInvalidInput)
	}
	priority := req.Priority
	if priority == 0 {
		priority = 100
	}
	if priority < 0 {
		return domain.Route{}, fmt.Errorf("%w: priority must be non-negative", ErrInvalidInput)
	}
	return s.store.CreateRoute(ctx, domain.Route{
		TenantID:         actor.TenantID,
		SourceID:         strings.TrimSpace(req.SourceID),
		Name:             name,
		Priority:         priority,
		EventTypes:       eventTypes,
		EndpointID:       strings.TrimSpace(req.EndpointID),
		RetryPolicyID:    strings.TrimSpace(req.RetryPolicyID),
		TransformationID: strings.TrimSpace(req.TransformationID),
		State:            state,
		Version:          1,
	})
}

func (s *ControlService) ListRoutes(ctx context.Context, actor authz.Actor, limit int) ([]domain.Route, error) {
	if !authz.Can(actor, "routes:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListRoutes(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetRoute(ctx context.Context, actor authz.Actor, routeID string) (domain.Route, error) {
	if !authz.Can(actor, "routes:read", actor.TenantID) {
		return domain.Route{}, ErrForbidden
	}
	if strings.TrimSpace(routeID) == "" {
		return domain.Route{}, fmt.Errorf("%w: route_id is required", ErrInvalidInput)
	}
	return s.store.GetRoute(ctx, actor.TenantID, routeID)
}

func (s *ControlService) UpdateRoute(ctx context.Context, actor authz.Actor, routeID string, req UpdateRouteRequest) (domain.Route, error) {
	if !authz.Can(actor, "routes:write", actor.TenantID) {
		return domain.Route{}, ErrForbidden
	}
	if strings.TrimSpace(routeID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.Route{}, fmt.Errorf("%w: route_id and reason are required", ErrInvalidInput)
	}
	if req.SourceID == nil && req.Name == nil && req.Priority == nil && req.EventTypes == nil && req.EndpointID == nil && req.RetryPolicyID == nil && req.TransformationID == nil && req.State == nil {
		return domain.Route{}, fmt.Errorf("%w: at least one route field is required", ErrInvalidInput)
	}
	if req.SourceID != nil {
		sourceID := strings.TrimSpace(*req.SourceID)
		if sourceID == "" {
			return domain.Route{}, fmt.Errorf("%w: source_id cannot be empty", ErrInvalidInput)
		}
		req.SourceID = &sourceID
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			return domain.Route{}, fmt.Errorf("%w: name cannot be empty", ErrInvalidInput)
		}
		req.Name = &name
	}
	if req.Priority != nil && *req.Priority < 0 {
		return domain.Route{}, fmt.Errorf("%w: priority must be non-negative", ErrInvalidInput)
	}
	if req.EventTypes != nil {
		req.EventTypes = normalizeEventTypes(req.EventTypes)
		if len(req.EventTypes) == 0 {
			return domain.Route{}, fmt.Errorf("%w: event_types cannot be empty", ErrInvalidInput)
		}
	}
	if req.EndpointID != nil {
		endpointID := strings.TrimSpace(*req.EndpointID)
		if endpointID == "" {
			return domain.Route{}, fmt.Errorf("%w: endpoint_id cannot be empty", ErrInvalidInput)
		}
		req.EndpointID = &endpointID
	}
	if req.RetryPolicyID != nil {
		retryPolicyID := strings.TrimSpace(*req.RetryPolicyID)
		req.RetryPolicyID = &retryPolicyID
	}
	if req.TransformationID != nil {
		transformationID := strings.TrimSpace(*req.TransformationID)
		req.TransformationID = &transformationID
	}
	if req.State != nil {
		state := strings.TrimSpace(*req.State)
		if !validRouteState(state) {
			return domain.Route{}, fmt.Errorf("%w: route state must be draft, active, or inactive", ErrInvalidInput)
		}
		req.State = &state
	}
	return s.store.UpdateRoute(ctx, actor.TenantID, routeID, actor.ID, req)
}

func (s *ControlService) DeleteRoute(ctx context.Context, actor authz.Actor, routeID string, req StateChangeRequest) (domain.Route, error) {
	if !authz.Can(actor, "routes:write", actor.TenantID) {
		return domain.Route{}, ErrForbidden
	}
	if strings.TrimSpace(routeID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.Route{}, fmt.Errorf("%w: route_id and reason are required", ErrInvalidInput)
	}
	return s.store.DeleteRoute(ctx, actor.TenantID, routeID, actor.ID, req.Reason)
}

func (s *ControlService) ListRouteVersions(ctx context.Context, actor authz.Actor, routeID string, limit int) ([]domain.RouteVersion, error) {
	if !authz.Can(actor, "routes:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	if strings.TrimSpace(routeID) == "" {
		return nil, fmt.Errorf("%w: route_id is required", ErrInvalidInput)
	}
	return s.store.ListRouteVersions(ctx, actor.TenantID, routeID, normalizeLimit(limit))
}

func (s *ControlService) ActivateRoute(ctx context.Context, actor authz.Actor, routeID, reason string) (domain.Route, error) {
	if !authz.Can(actor, "routes:write", actor.TenantID) {
		return domain.Route{}, ErrForbidden
	}
	if strings.TrimSpace(routeID) == "" || strings.TrimSpace(reason) == "" {
		return domain.Route{}, fmt.Errorf("%w: route_id and reason are required", ErrInvalidInput)
	}
	return s.store.ActivateRoute(ctx, actor.TenantID, routeID, actor.ID, reason)
}

func (s *ControlService) DryRunRoute(ctx context.Context, actor authz.Actor, routeID, eventID string) (RouteDryRun, error) {
	if !authz.Can(actor, "routes:read", actor.TenantID) {
		return RouteDryRun{}, ErrForbidden
	}
	if strings.TrimSpace(routeID) == "" || strings.TrimSpace(eventID) == "" {
		return RouteDryRun{}, fmt.Errorf("%w: route_id and event_id are required", ErrInvalidInput)
	}
	return s.store.DryRunRoute(ctx, actor.TenantID, routeID, eventID)
}

func (s *ControlService) CreateRetryPolicy(ctx context.Context, actor authz.Actor, req CreateRetryPolicyRequest) (domain.RetryPolicy, error) {
	if !authz.Can(actor, "routes:write", actor.TenantID) {
		return domain.RetryPolicy{}, ErrForbidden
	}
	req.Name = strings.TrimSpace(req.Name)
	req.State = normalizeState(req.State)
	if req.Name == "" {
		return domain.RetryPolicy{}, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if err := validateRetryPolicy(req); err != nil {
		return domain.RetryPolicy{}, err
	}
	return s.store.CreateRetryPolicy(ctx, actor.TenantID, actor.ID, req)
}

func (s *ControlService) ListRetryPolicies(ctx context.Context, actor authz.Actor, limit int) ([]domain.RetryPolicy, error) {
	if !authz.Can(actor, "routes:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListRetryPolicies(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetRetryPolicy(ctx context.Context, actor authz.Actor, retryPolicyID string) (domain.RetryPolicy, error) {
	if !authz.Can(actor, "routes:read", actor.TenantID) {
		return domain.RetryPolicy{}, ErrForbidden
	}
	if strings.TrimSpace(retryPolicyID) == "" {
		return domain.RetryPolicy{}, fmt.Errorf("%w: retry_policy_id is required", ErrInvalidInput)
	}
	return s.store.GetRetryPolicy(ctx, actor.TenantID, retryPolicyID)
}

func (s *ControlService) UpdateRetryPolicy(ctx context.Context, actor authz.Actor, retryPolicyID string, req UpdateRetryPolicyRequest) (domain.RetryPolicy, error) {
	if !authz.Can(actor, "routes:write", actor.TenantID) {
		return domain.RetryPolicy{}, ErrForbidden
	}
	if strings.TrimSpace(retryPolicyID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.RetryPolicy{}, fmt.Errorf("%w: retry_policy_id and reason are required", ErrInvalidInput)
	}
	if req.Name == nil && req.MaxAttempts == nil && req.MaxDurationSeconds == nil && req.InitialDelaySeconds == nil && req.MaxDelaySeconds == nil && req.RateLimitPerMinute == nil && req.State == nil {
		return domain.RetryPolicy{}, fmt.Errorf("%w: at least one retry policy field is required", ErrInvalidInput)
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			return domain.RetryPolicy{}, fmt.Errorf("%w: name cannot be empty", ErrInvalidInput)
		}
		req.Name = &name
	}
	if req.MaxAttempts != nil && (*req.MaxAttempts <= 0 || *req.MaxAttempts > 100) {
		return domain.RetryPolicy{}, fmt.Errorf("%w: max_attempts must be between 1 and 100", ErrInvalidInput)
	}
	if req.MaxDurationSeconds != nil && (*req.MaxDurationSeconds <= 0 || *req.MaxDurationSeconds > int((30*24*time.Hour)/time.Second)) {
		return domain.RetryPolicy{}, fmt.Errorf("%w: max_duration_seconds must be between 1 and 2592000", ErrInvalidInput)
	}
	if req.InitialDelaySeconds != nil && *req.InitialDelaySeconds <= 0 {
		return domain.RetryPolicy{}, fmt.Errorf("%w: initial_delay_seconds must be positive", ErrInvalidInput)
	}
	if req.MaxDelaySeconds != nil && (*req.MaxDelaySeconds <= 0 || *req.MaxDelaySeconds > int((24*time.Hour)/time.Second)) {
		return domain.RetryPolicy{}, fmt.Errorf("%w: max_delay_seconds must be between 1 and 86400", ErrInvalidInput)
	}
	if req.InitialDelaySeconds != nil && req.MaxDelaySeconds != nil && *req.InitialDelaySeconds > *req.MaxDelaySeconds {
		return domain.RetryPolicy{}, fmt.Errorf("%w: initial_delay_seconds must be no greater than max_delay_seconds", ErrInvalidInput)
	}
	if req.RateLimitPerMinute != nil && (*req.RateLimitPerMinute < 0 || *req.RateLimitPerMinute > 60000) {
		return domain.RetryPolicy{}, fmt.Errorf("%w: rate_limit_per_minute must be between 0 and 60000", ErrInvalidInput)
	}
	if req.State != nil {
		state := strings.TrimSpace(*req.State)
		if state != domain.StateActive && state != domain.StateDisabled {
			return domain.RetryPolicy{}, fmt.Errorf("%w: state must be active or disabled", ErrInvalidInput)
		}
		req.State = &state
	}
	return s.store.UpdateRetryPolicy(ctx, actor.TenantID, retryPolicyID, actor.ID, req)
}

func (s *ControlService) DeleteRetryPolicy(ctx context.Context, actor authz.Actor, retryPolicyID string, req StateChangeRequest) (domain.RetryPolicy, error) {
	if !authz.Can(actor, "routes:write", actor.TenantID) {
		return domain.RetryPolicy{}, ErrForbidden
	}
	if strings.TrimSpace(retryPolicyID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.RetryPolicy{}, fmt.Errorf("%w: retry_policy_id and reason are required", ErrInvalidInput)
	}
	return s.store.DeleteRetryPolicy(ctx, actor.TenantID, retryPolicyID, actor.ID, req.Reason)
}

func (s *ControlService) CreateEventType(ctx context.Context, actor authz.Actor, req CreateEventTypeRequest) (domain.EventType, error) {
	if !authz.Can(actor, "schemas:write", actor.TenantID) {
		return domain.EventType{}, ErrForbidden
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if req.Name == "" {
		return domain.EventType{}, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	return s.store.CreateEventType(ctx, domain.EventType{
		TenantID:    actor.TenantID,
		Name:        req.Name,
		Description: req.Description,
		State:       domain.StateActive,
	})
}

func (s *ControlService) ListEventTypes(ctx context.Context, actor authz.Actor, limit int) ([]domain.EventType, error) {
	if !authz.Can(actor, "schemas:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListEventTypes(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetEventType(ctx context.Context, actor authz.Actor, eventType string) (domain.EventType, error) {
	if !authz.Can(actor, "schemas:read", actor.TenantID) {
		return domain.EventType{}, ErrForbidden
	}
	if strings.TrimSpace(eventType) == "" {
		return domain.EventType{}, fmt.Errorf("%w: event_type is required", ErrInvalidInput)
	}
	return s.store.GetEventType(ctx, actor.TenantID, eventType)
}

func (s *ControlService) UpdateEventType(ctx context.Context, actor authz.Actor, eventType string, req UpdateEventTypeRequest) (domain.EventType, error) {
	if !authz.Can(actor, "schemas:write", actor.TenantID) {
		return domain.EventType{}, ErrForbidden
	}
	if strings.TrimSpace(eventType) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.EventType{}, fmt.Errorf("%w: event_type and reason are required", ErrInvalidInput)
	}
	if req.Description == nil && req.State == nil {
		return domain.EventType{}, fmt.Errorf("%w: at least one event type field is required", ErrInvalidInput)
	}
	if req.Description != nil {
		description := strings.TrimSpace(*req.Description)
		req.Description = &description
	}
	if req.State != nil {
		state := strings.TrimSpace(*req.State)
		if state != domain.StateActive && state != domain.StateDisabled {
			return domain.EventType{}, fmt.Errorf("%w: event type state must be active or disabled", ErrInvalidInput)
		}
		req.State = &state
	}
	return s.store.UpdateEventType(ctx, actor.TenantID, eventType, actor.ID, req)
}

func (s *ControlService) DeleteEventType(ctx context.Context, actor authz.Actor, eventType string, req StateChangeRequest) (domain.EventType, error) {
	if !authz.Can(actor, "schemas:write", actor.TenantID) {
		return domain.EventType{}, ErrForbidden
	}
	if strings.TrimSpace(eventType) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.EventType{}, fmt.Errorf("%w: event_type and reason are required", ErrInvalidInput)
	}
	return s.store.DeleteEventType(ctx, actor.TenantID, eventType, actor.ID, req.Reason)
}

func (s *ControlService) CreateEventSchema(ctx context.Context, actor authz.Actor, eventType string, req CreateEventSchemaRequest) (domain.EventSchema, error) {
	if !authz.Can(actor, "schemas:write", actor.TenantID) {
		return domain.EventSchema{}, ErrForbidden
	}
	if eventType == "" || req.Version == "" || req.Schema == "" {
		return domain.EventSchema{}, fmt.Errorf("%w: event_type, version, and schema are required", ErrInvalidInput)
	}
	return s.store.CreateEventSchema(ctx, domain.EventSchema{
		TenantID:  actor.TenantID,
		EventType: eventType,
		Version:   req.Version,
		Schema:    req.Schema,
		State:     domain.StateActive,
	})
}

func (s *ControlService) ListEventSchemas(ctx context.Context, actor authz.Actor, eventType string, limit int) ([]domain.EventSchema, error) {
	if !authz.Can(actor, "schemas:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListEventSchemas(ctx, actor.TenantID, eventType, normalizeLimit(limit))
}

func (s *ControlService) GetEventSchema(ctx context.Context, actor authz.Actor, eventType, version string) (domain.EventSchema, error) {
	if !authz.Can(actor, "schemas:read", actor.TenantID) {
		return domain.EventSchema{}, ErrForbidden
	}
	if strings.TrimSpace(eventType) == "" || strings.TrimSpace(version) == "" {
		return domain.EventSchema{}, fmt.Errorf("%w: event_type and schema_version are required", ErrInvalidInput)
	}
	return s.store.GetEventSchema(ctx, actor.TenantID, eventType, version)
}

func (s *ControlService) UpdateEventSchema(ctx context.Context, actor authz.Actor, eventType, version string, req UpdateEventSchemaRequest) (domain.EventSchema, error) {
	if !authz.Can(actor, "schemas:write", actor.TenantID) {
		return domain.EventSchema{}, ErrForbidden
	}
	if strings.TrimSpace(eventType) == "" || strings.TrimSpace(version) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.EventSchema{}, fmt.Errorf("%w: event_type, schema_version, and reason are required", ErrInvalidInput)
	}
	if req.State == nil {
		return domain.EventSchema{}, fmt.Errorf("%w: at least one schema field is required", ErrInvalidInput)
	}
	state := strings.TrimSpace(*req.State)
	if !validSchemaState(state) {
		return domain.EventSchema{}, fmt.Errorf("%w: schema state must be active, deprecated, or retired", ErrInvalidInput)
	}
	req.State = &state
	return s.store.UpdateEventSchema(ctx, actor.TenantID, eventType, version, actor.ID, req)
}

func (s *ControlService) DeleteEventSchema(ctx context.Context, actor authz.Actor, eventType, version string, req StateChangeRequest) (domain.EventSchema, error) {
	if !authz.Can(actor, "schemas:write", actor.TenantID) {
		return domain.EventSchema{}, ErrForbidden
	}
	if strings.TrimSpace(eventType) == "" || strings.TrimSpace(version) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.EventSchema{}, fmt.Errorf("%w: event_type, schema_version, and reason are required", ErrInvalidInput)
	}
	return s.store.DeleteEventSchema(ctx, actor.TenantID, eventType, version, actor.ID, req.Reason)
}

func (s *ControlService) ValidateEventSchema(ctx context.Context, actor authz.Actor, eventType, version string, req ValidateSchemaRequest) (SchemaValidationResult, error) {
	if !authz.Can(actor, "schemas:read", actor.TenantID) {
		return SchemaValidationResult{}, ErrForbidden
	}
	if strings.TrimSpace(eventType) == "" || strings.TrimSpace(version) == "" || strings.TrimSpace(req.Payload) == "" {
		return SchemaValidationResult{}, fmt.Errorf("%w: event_type, version, and payload are required", ErrInvalidInput)
	}
	schema, err := s.store.GetEventSchema(ctx, actor.TenantID, eventType, version)
	if err != nil {
		return SchemaValidationResult{}, err
	}
	return ValidateJSONPayload(schema.Schema, req.Payload)
}

func (s *ControlService) CheckEventSchemaCompatibility(ctx context.Context, actor authz.Actor, eventType, baseVersion string, req CheckSchemaCompatibilityRequest) (SchemaCompatibilityResult, error) {
	if !authz.Can(actor, "schemas:read", actor.TenantID) {
		return SchemaCompatibilityResult{}, ErrForbidden
	}
	if strings.TrimSpace(eventType) == "" || strings.TrimSpace(baseVersion) == "" || strings.TrimSpace(req.NewSchema) == "" {
		return SchemaCompatibilityResult{}, fmt.Errorf("%w: event_type, base_version, and new_schema are required", ErrInvalidInput)
	}
	current, err := s.store.GetEventSchema(ctx, actor.TenantID, eventType, baseVersion)
	if err != nil {
		return SchemaCompatibilityResult{}, err
	}
	return CheckJSONSchemaCompatibility(current.Schema, req.NewSchema)
}

func (s *ControlService) RotateSourceSecret(ctx context.Context, actor authz.Actor, sourceID string, req RotateSourceSecretRequest) (domain.SourceSecretVersion, error) {
	if !s.authorized(ctx, actor, "security:write", "source", sourceID, "") {
		return domain.SourceSecretVersion{}, ErrForbidden
	}
	if strings.TrimSpace(sourceID) == "" || strings.TrimSpace(req.NewSecret) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.SourceSecretVersion{}, fmt.Errorf("%w: source_id, new_secret, and reason are required", ErrInvalidInput)
	}
	if req.GracePeriodHours < 0 || req.GracePeriodHours > 24*30 {
		return domain.SourceSecretVersion{}, fmt.Errorf("%w: grace_period_hours must be between 0 and 720", ErrInvalidInput)
	}
	return s.store.RotateSourceSecret(ctx, actor.TenantID, sourceID, actor.ID, req)
}

func (s *ControlService) RotateEndpointSecret(ctx context.Context, actor authz.Actor, endpointID string, req RotateEndpointSecretRequest) (domain.EndpointSecretVersion, error) {
	if !s.authorized(ctx, actor, "security:write", "endpoint", endpointID, "") {
		return domain.EndpointSecretVersion{}, ErrForbidden
	}
	if strings.TrimSpace(endpointID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.EndpointSecretVersion{}, fmt.Errorf("%w: endpoint_id and reason are required", ErrInvalidInput)
	}
	if req.GracePeriodHours < 0 || req.GracePeriodHours > 24*30 {
		return domain.EndpointSecretVersion{}, fmt.Errorf("%w: grace_period_hours must be between 0 and 720", ErrInvalidInput)
	}
	return s.store.RotateEndpointSecret(ctx, actor.TenantID, endpointID, actor.ID, req)
}

func (s *ControlService) ListEvents(ctx context.Context, actor authz.Actor, limit int) ([]domain.Event, error) {
	if !authz.Can(actor, "events:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListEvents(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetEvent(ctx context.Context, actor authz.Actor, eventID string) (domain.Event, error) {
	if !authz.Can(actor, "events:read", actor.TenantID) {
		return domain.Event{}, ErrForbidden
	}
	return s.store.GetEvent(ctx, actor.TenantID, eventID)
}

func (s *ControlService) GetRawPayload(ctx context.Context, actor authz.Actor, eventID string) (domain.RawPayload, error) {
	if !s.authorized(ctx, actor, "events:raw", "event", eventID, "") {
		return domain.RawPayload{}, ErrForbidden
	}
	return s.store.GetRawPayload(ctx, actor.TenantID, eventID, actor.ID)
}

func (s *ControlService) GetNormalizedEvent(ctx context.Context, actor authz.Actor, eventID string, includeData bool) (domain.NormalizedEnvelope, error) {
	if !authz.Can(actor, "events:read", actor.TenantID) {
		return domain.NormalizedEnvelope{}, ErrForbidden
	}
	if includeData && !s.authorized(ctx, actor, "events:raw", "event", eventID, "") {
		return domain.NormalizedEnvelope{}, ErrForbidden
	}
	return s.store.GetNormalizedEvent(ctx, actor.TenantID, eventID, actor.ID, includeData)
}

func (s *ControlService) ListEventTimeline(ctx context.Context, actor authz.Actor, eventID string, limit int) ([]map[string]any, error) {
	if !authz.Can(actor, "events:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListEventTimeline(ctx, actor.TenantID, eventID, normalizeLimit(limit))
}

func (s *ControlService) ListDeliveries(ctx context.Context, actor authz.Actor, limit int) ([]domain.Delivery, error) {
	if !authz.Can(actor, "deliveries:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListDeliveries(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) ListDeliveryAttempts(ctx context.Context, actor authz.Actor, deliveryID string, limit int) ([]domain.DeliveryAttempt, error) {
	if !authz.Can(actor, "deliveries:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListDeliveryAttempts(ctx, actor.TenantID, deliveryID, normalizeLimit(limit))
}

func (s *ControlService) GetDeliveryAttempt(ctx context.Context, actor authz.Actor, attemptID string) (domain.DeliveryAttempt, error) {
	if !authz.Can(actor, "deliveries:read", actor.TenantID) {
		return domain.DeliveryAttempt{}, ErrForbidden
	}
	return s.store.GetDeliveryAttempt(ctx, actor.TenantID, attemptID)
}

func (s *ControlService) RetryDelivery(ctx context.Context, actor authz.Actor, deliveryID, reason string) (domain.Delivery, error) {
	if !authz.Can(actor, "deliveries:retry", actor.TenantID) {
		return domain.Delivery{}, ErrForbidden
	}
	if reason == "" {
		return domain.Delivery{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	return s.store.RetryDelivery(ctx, actor.TenantID, deliveryID, actor.ID, reason)
}

func (s *ControlService) CancelDelivery(ctx context.Context, actor authz.Actor, deliveryID string, req StateChangeRequest) (domain.Delivery, error) {
	if !authz.Can(actor, "deliveries:retry", actor.TenantID) {
		return domain.Delivery{}, ErrForbidden
	}
	if strings.TrimSpace(req.Reason) == "" {
		return domain.Delivery{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	return s.store.CancelDelivery(ctx, actor.TenantID, deliveryID, actor.ID, req.Reason)
}

func (s *ControlService) ListEndpointHealth(ctx context.Context, actor authz.Actor, limit int) ([]domain.EndpointHealth, error) {
	if !authz.Can(actor, "endpoints:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListEndpointHealth(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) OpsMetrics(ctx context.Context, actor authz.Actor) (domain.OpsMetrics, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return domain.OpsMetrics{}, ErrForbidden
	}
	return s.store.OpsMetrics(ctx, actor.TenantID)
}

func (s *ControlService) PublicOpsMetrics(ctx context.Context) (domain.OpsMetrics, error) {
	return s.store.OpsMetrics(ctx, "")
}

func (s *ControlService) ListWorkers(ctx context.Context, actor authz.Actor, limit int) ([]domain.WorkerStatus, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListWorkers(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetWorker(ctx context.Context, actor authz.Actor, workerID string) (domain.WorkerStatus, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return domain.WorkerStatus{}, ErrForbidden
	}
	if strings.TrimSpace(workerID) == "" {
		return domain.WorkerStatus{}, fmt.Errorf("%w: worker_id is required", ErrInvalidInput)
	}
	return s.store.GetWorker(ctx, actor.TenantID, workerID)
}

func (s *ControlService) ListQueues(ctx context.Context, actor authz.Actor) ([]domain.QueueStats, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListQueues(ctx, actor.TenantID)
}

func (s *ControlService) OpsStorage(ctx context.Context, actor authz.Actor) (domain.OpsStorageStatus, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return domain.OpsStorageStatus{}, ErrForbidden
	}
	return s.store.OpsStorage(ctx, actor.TenantID)
}

func (s *ControlService) OpsConfig(ctx context.Context, actor authz.Actor) (domain.OpsConfig, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return domain.OpsConfig{}, ErrForbidden
	}
	return s.runtimeConfig, nil
}

func (s *ControlService) ListMetricRollups(ctx context.Context, actor authz.Actor, metricName string, limit int) ([]domain.MetricRollup, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	metricName = strings.TrimSpace(metricName)
	if metricName != "" && !validMetricName(metricName) {
		return nil, fmt.Errorf("%w: metric_name is invalid", ErrInvalidInput)
	}
	return s.store.ListMetricRollups(ctx, actor.TenantID, metricName, normalizeLimit(limit))
}

func (s *ControlService) CreateAlertRule(ctx context.Context, actor authz.Actor, req CreateAlertRuleRequest) (domain.AlertRule, error) {
	if !authz.Can(actor, "ops:write", actor.TenantID) {
		return domain.AlertRule{}, ErrForbidden
	}
	if err := normalizeCreateAlertRule(&req); err != nil {
		return domain.AlertRule{}, err
	}
	return s.store.CreateAlertRule(ctx, actor.TenantID, actor.ID, req)
}

func (s *ControlService) ListAlertRules(ctx context.Context, actor authz.Actor, limit int) ([]domain.AlertRule, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListAlertRules(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetAlertRule(ctx context.Context, actor authz.Actor, alertID string) (domain.AlertRule, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return domain.AlertRule{}, ErrForbidden
	}
	if strings.TrimSpace(alertID) == "" {
		return domain.AlertRule{}, fmt.Errorf("%w: alert_id is required", ErrInvalidInput)
	}
	return s.store.GetAlertRule(ctx, actor.TenantID, alertID)
}

func (s *ControlService) UpdateAlertRule(ctx context.Context, actor authz.Actor, alertID string, req UpdateAlertRuleRequest) (domain.AlertRule, error) {
	if !authz.Can(actor, "ops:write", actor.TenantID) {
		return domain.AlertRule{}, ErrForbidden
	}
	if strings.TrimSpace(alertID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.AlertRule{}, fmt.Errorf("%w: alert_id and reason are required", ErrInvalidInput)
	}
	if err := normalizeUpdateAlertRule(&req); err != nil {
		return domain.AlertRule{}, err
	}
	return s.store.UpdateAlertRule(ctx, actor.TenantID, alertID, actor.ID, req)
}

func (s *ControlService) DeleteAlertRule(ctx context.Context, actor authz.Actor, alertID string, req StateChangeRequest) (domain.AlertRule, error) {
	if !authz.Can(actor, "ops:write", actor.TenantID) {
		return domain.AlertRule{}, ErrForbidden
	}
	if strings.TrimSpace(alertID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.AlertRule{}, fmt.Errorf("%w: alert_id and reason are required", ErrInvalidInput)
	}
	return s.store.DeleteAlertRule(ctx, actor.TenantID, alertID, actor.ID, req.Reason)
}

func (s *ControlService) ListAlertFirings(ctx context.Context, actor authz.Actor, state string, limit int) ([]domain.AlertFiring, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	state = strings.TrimSpace(state)
	if state != "" && !validAlertFiringState(state) {
		return nil, fmt.Errorf("%w: alert firing state is invalid", ErrInvalidInput)
	}
	return s.store.ListAlertFirings(ctx, actor.TenantID, state, normalizeLimit(limit))
}

func (s *ControlService) GetAlertFiring(ctx context.Context, actor authz.Actor, firingID string) (domain.AlertFiring, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return domain.AlertFiring{}, ErrForbidden
	}
	if strings.TrimSpace(firingID) == "" {
		return domain.AlertFiring{}, fmt.Errorf("%w: firing_id is required", ErrInvalidInput)
	}
	return s.store.GetAlertFiring(ctx, actor.TenantID, firingID)
}

func (s *ControlService) AcknowledgeAlertFiring(ctx context.Context, actor authz.Actor, firingID string, req StateChangeRequest) (domain.AlertFiring, error) {
	if !authz.Can(actor, "ops:write", actor.TenantID) {
		return domain.AlertFiring{}, ErrForbidden
	}
	if strings.TrimSpace(firingID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.AlertFiring{}, fmt.Errorf("%w: firing_id and reason are required", ErrInvalidInput)
	}
	return s.store.AcknowledgeAlertFiring(ctx, actor.TenantID, firingID, actor.ID, req.Reason)
}

func (s *ControlService) CreateNotificationChannel(ctx context.Context, actor authz.Actor, req CreateNotificationChannelRequest) (domain.NotificationChannel, ssrf.Result, error) {
	if !s.authorized(ctx, actor, "ops:write", "notification_channel", "", "") {
		return domain.NotificationChannel{}, ssrf.Result{}, ErrForbidden
	}
	if err := normalizeCreateNotificationChannel(&req); err != nil {
		return domain.NotificationChannel{}, ssrf.Result{}, err
	}
	result := s.ssrfValidator.Validate(ctx, req.URL, ssrf.DefaultPolicy())
	if !result.Allowed {
		return domain.NotificationChannel{}, result, fmt.Errorf("%w: notification_channel_url_blocked", ErrInvalidInput)
	}
	req.URL = result.NormalizedURL
	item, err := s.store.CreateNotificationChannel(ctx, actor.TenantID, actor.ID, req)
	return item, result, err
}

func (s *ControlService) ListNotificationChannels(ctx context.Context, actor authz.Actor, limit int) ([]domain.NotificationChannel, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListNotificationChannels(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetNotificationChannel(ctx context.Context, actor authz.Actor, channelID string) (domain.NotificationChannel, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return domain.NotificationChannel{}, ErrForbidden
	}
	if strings.TrimSpace(channelID) == "" {
		return domain.NotificationChannel{}, fmt.Errorf("%w: channel_id is required", ErrInvalidInput)
	}
	return s.store.GetNotificationChannel(ctx, actor.TenantID, channelID)
}

func (s *ControlService) UpdateNotificationChannel(ctx context.Context, actor authz.Actor, channelID string, req UpdateNotificationChannelRequest) (domain.NotificationChannel, ssrf.Result, error) {
	if !s.authorized(ctx, actor, "ops:write", "notification_channel", channelID, "") {
		return domain.NotificationChannel{}, ssrf.Result{}, ErrForbidden
	}
	if strings.TrimSpace(channelID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.NotificationChannel{}, ssrf.Result{}, fmt.Errorf("%w: channel_id and reason are required", ErrInvalidInput)
	}
	if err := normalizeUpdateNotificationChannel(&req); err != nil {
		return domain.NotificationChannel{}, ssrf.Result{}, err
	}
	var result ssrf.Result
	if req.URL != nil {
		result = s.ssrfValidator.Validate(ctx, *req.URL, ssrf.DefaultPolicy())
		if !result.Allowed {
			return domain.NotificationChannel{}, result, fmt.Errorf("%w: notification_channel_url_blocked", ErrInvalidInput)
		}
		req.URL = &result.NormalizedURL
	}
	item, err := s.store.UpdateNotificationChannel(ctx, actor.TenantID, channelID, actor.ID, req)
	return item, result, err
}

func (s *ControlService) DeleteNotificationChannel(ctx context.Context, actor authz.Actor, channelID string, req StateChangeRequest) (domain.NotificationChannel, error) {
	if !s.authorized(ctx, actor, "ops:write", "notification_channel", channelID, "") {
		return domain.NotificationChannel{}, ErrForbidden
	}
	if strings.TrimSpace(channelID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.NotificationChannel{}, fmt.Errorf("%w: channel_id and reason are required", ErrInvalidInput)
	}
	return s.store.DeleteNotificationChannel(ctx, actor.TenantID, channelID, actor.ID, req.Reason)
}

func (s *ControlService) TestNotificationChannel(ctx context.Context, actor authz.Actor, channelID string, req StateChangeRequest) (domain.NotificationDelivery, error) {
	if !s.authorized(ctx, actor, "ops:write", "notification_channel", channelID, "") {
		return domain.NotificationDelivery{}, ErrForbidden
	}
	if strings.TrimSpace(channelID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.NotificationDelivery{}, fmt.Errorf("%w: channel_id and reason are required", ErrInvalidInput)
	}
	channel, err := s.store.GetNotificationChannel(ctx, actor.TenantID, channelID)
	if err != nil {
		return domain.NotificationDelivery{}, err
	}
	result := s.ssrfValidator.Validate(ctx, channel.URL, ssrf.DefaultPolicy())
	if !result.Allowed {
		return domain.NotificationDelivery{}, fmt.Errorf("%w: notification_channel_url_blocked", ErrInvalidInput)
	}
	return s.store.TestNotificationChannel(ctx, actor.TenantID, channelID, actor.ID, req.Reason)
}

func (s *ControlService) ListNotificationDeliveries(ctx context.Context, actor authz.Actor, state string, limit int) ([]domain.NotificationDelivery, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	state = strings.TrimSpace(state)
	if state != "" && !validSignalDeliveryState(state) {
		return nil, fmt.Errorf("%w: notification delivery state is invalid", ErrInvalidInput)
	}
	return s.store.ListNotificationDeliveries(ctx, actor.TenantID, state, normalizeLimit(limit))
}

func (s *ControlService) ListNotificationDeliveryAttempts(ctx context.Context, actor authz.Actor, deliveryID string, limit int) ([]domain.NotificationDeliveryAttempt, error) {
	if !authz.Can(actor, "ops:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	if strings.TrimSpace(deliveryID) == "" {
		return nil, fmt.Errorf("%w: delivery_id is required", ErrInvalidInput)
	}
	return s.store.ListNotificationDeliveryAttempts(ctx, actor.TenantID, deliveryID, normalizeLimit(limit))
}

func (s *ControlService) RetryNotificationDelivery(ctx context.Context, actor authz.Actor, deliveryID string, req StateChangeRequest) (domain.NotificationDelivery, error) {
	if !authz.Can(actor, "ops:write", actor.TenantID) {
		return domain.NotificationDelivery{}, ErrForbidden
	}
	if strings.TrimSpace(deliveryID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.NotificationDelivery{}, fmt.Errorf("%w: delivery_id and reason are required", ErrInvalidInput)
	}
	return s.store.RetryNotificationDelivery(ctx, actor.TenantID, deliveryID, actor.ID, req.Reason)
}

func (s *ControlService) CreateSIEMSink(ctx context.Context, actor authz.Actor, req CreateSIEMSinkRequest) (domain.SIEMSink, ssrf.Result, error) {
	if !s.authorized(ctx, actor, "security:write", "siem_sink", "", "") {
		return domain.SIEMSink{}, ssrf.Result{}, ErrForbidden
	}
	if err := normalizeCreateSIEMSink(&req); err != nil {
		return domain.SIEMSink{}, ssrf.Result{}, err
	}
	result := s.ssrfValidator.Validate(ctx, req.URL, ssrf.DefaultPolicy())
	if !result.Allowed {
		return domain.SIEMSink{}, result, fmt.Errorf("%w: siem_sink_url_blocked", ErrInvalidInput)
	}
	req.URL = result.NormalizedURL
	item, err := s.store.CreateSIEMSink(ctx, actor.TenantID, actor.ID, req)
	return item, result, err
}

func (s *ControlService) ListSIEMSinks(ctx context.Context, actor authz.Actor, limit int) ([]domain.SIEMSink, error) {
	if !authz.Can(actor, "audit:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListSIEMSinks(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetSIEMSink(ctx context.Context, actor authz.Actor, sinkID string) (domain.SIEMSink, error) {
	if !authz.Can(actor, "audit:read", actor.TenantID) {
		return domain.SIEMSink{}, ErrForbidden
	}
	if strings.TrimSpace(sinkID) == "" {
		return domain.SIEMSink{}, fmt.Errorf("%w: sink_id is required", ErrInvalidInput)
	}
	return s.store.GetSIEMSink(ctx, actor.TenantID, sinkID)
}

func (s *ControlService) UpdateSIEMSink(ctx context.Context, actor authz.Actor, sinkID string, req UpdateSIEMSinkRequest) (domain.SIEMSink, ssrf.Result, error) {
	if !s.authorized(ctx, actor, "security:write", "siem_sink", sinkID, "") {
		return domain.SIEMSink{}, ssrf.Result{}, ErrForbidden
	}
	if strings.TrimSpace(sinkID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.SIEMSink{}, ssrf.Result{}, fmt.Errorf("%w: sink_id and reason are required", ErrInvalidInput)
	}
	if err := normalizeUpdateSIEMSink(&req); err != nil {
		return domain.SIEMSink{}, ssrf.Result{}, err
	}
	var result ssrf.Result
	if req.URL != nil {
		result = s.ssrfValidator.Validate(ctx, *req.URL, ssrf.DefaultPolicy())
		if !result.Allowed {
			return domain.SIEMSink{}, result, fmt.Errorf("%w: siem_sink_url_blocked", ErrInvalidInput)
		}
		req.URL = &result.NormalizedURL
	}
	item, err := s.store.UpdateSIEMSink(ctx, actor.TenantID, sinkID, actor.ID, req)
	return item, result, err
}

func (s *ControlService) DeleteSIEMSink(ctx context.Context, actor authz.Actor, sinkID string, req StateChangeRequest) (domain.SIEMSink, error) {
	if !s.authorized(ctx, actor, "security:write", "siem_sink", sinkID, "") {
		return domain.SIEMSink{}, ErrForbidden
	}
	if strings.TrimSpace(sinkID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.SIEMSink{}, fmt.Errorf("%w: sink_id and reason are required", ErrInvalidInput)
	}
	return s.store.DeleteSIEMSink(ctx, actor.TenantID, sinkID, actor.ID, req.Reason)
}

func (s *ControlService) TestSIEMSink(ctx context.Context, actor authz.Actor, sinkID string, req StateChangeRequest) (domain.SIEMDelivery, error) {
	if !s.authorized(ctx, actor, "security:write", "siem_sink", sinkID, "") {
		return domain.SIEMDelivery{}, ErrForbidden
	}
	if strings.TrimSpace(sinkID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.SIEMDelivery{}, fmt.Errorf("%w: sink_id and reason are required", ErrInvalidInput)
	}
	sink, err := s.store.GetSIEMSink(ctx, actor.TenantID, sinkID)
	if err != nil {
		return domain.SIEMDelivery{}, err
	}
	result := s.ssrfValidator.Validate(ctx, sink.URL, ssrf.DefaultPolicy())
	if !result.Allowed {
		return domain.SIEMDelivery{}, fmt.Errorf("%w: siem_sink_url_blocked", ErrInvalidInput)
	}
	return s.store.TestSIEMSink(ctx, actor.TenantID, sinkID, actor.ID, req.Reason)
}

func (s *ControlService) ListSIEMDeliveries(ctx context.Context, actor authz.Actor, state string, limit int) ([]domain.SIEMDelivery, error) {
	if !authz.Can(actor, "audit:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	state = strings.TrimSpace(state)
	if state != "" && !validSignalDeliveryState(state) {
		return nil, fmt.Errorf("%w: siem delivery state is invalid", ErrInvalidInput)
	}
	return s.store.ListSIEMDeliveries(ctx, actor.TenantID, state, normalizeLimit(limit))
}

func (s *ControlService) ListSIEMDeliveryAttempts(ctx context.Context, actor authz.Actor, deliveryID string, limit int) ([]domain.SIEMDeliveryAttempt, error) {
	if !authz.Can(actor, "audit:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	if strings.TrimSpace(deliveryID) == "" {
		return nil, fmt.Errorf("%w: delivery_id is required", ErrInvalidInput)
	}
	return s.store.ListSIEMDeliveryAttempts(ctx, actor.TenantID, deliveryID, normalizeLimit(limit))
}

func (s *ControlService) RetrySIEMDelivery(ctx context.Context, actor authz.Actor, deliveryID string, req StateChangeRequest) (domain.SIEMDelivery, error) {
	if !authz.Can(actor, "security:write", actor.TenantID) {
		return domain.SIEMDelivery{}, ErrForbidden
	}
	if strings.TrimSpace(deliveryID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.SIEMDelivery{}, fmt.Errorf("%w: delivery_id and reason are required", ErrInvalidInput)
	}
	return s.store.RetrySIEMDelivery(ctx, actor.TenantID, deliveryID, actor.ID, req.Reason)
}

func (s *ControlService) DryRunReplay(ctx context.Context, actor authz.Actor, req ReplayRequest) (ReplayDryRun, error) {
	if !authz.Can(actor, "replay:read", actor.TenantID) {
		return ReplayDryRun{}, ErrForbidden
	}
	if err := normalizeReplayRequest(&req, false); err != nil {
		return ReplayDryRun{}, err
	}
	return s.store.DryRunReplay(ctx, actor.TenantID, req)
}

func (s *ControlService) CreateReplay(ctx context.Context, actor authz.Actor, req ReplayRequest) (ReplayJob, error) {
	if !s.authorized(ctx, actor, "replay:write", "replay", req.EventID, "") {
		return ReplayJob{}, ErrForbidden
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		return ReplayJob{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	if err := normalizeReplayRequest(&req, true); err != nil {
		return ReplayJob{}, err
	}
	return s.store.CreateReplay(ctx, actor.TenantID, actor.ID, req)
}

func (s *ControlService) ListReplayJobs(ctx context.Context, actor authz.Actor, limit int) ([]ReplayJob, error) {
	if !authz.Can(actor, "replay:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListReplayJobs(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) ApproveReplayJob(ctx context.Context, actor authz.Actor, replayJobID string, req StateChangeRequest) (ReplayJob, error) {
	return s.changeReplayState(ctx, actor, replayJobID, req, s.store.ApproveReplayJob)
}

func (s *ControlService) PauseReplayJob(ctx context.Context, actor authz.Actor, replayJobID string, req StateChangeRequest) (ReplayJob, error) {
	return s.changeReplayState(ctx, actor, replayJobID, req, s.store.PauseReplayJob)
}

func (s *ControlService) ResumeReplayJob(ctx context.Context, actor authz.Actor, replayJobID string, req StateChangeRequest) (ReplayJob, error) {
	return s.changeReplayState(ctx, actor, replayJobID, req, s.store.ResumeReplayJob)
}

func (s *ControlService) CancelReplayJob(ctx context.Context, actor authz.Actor, replayJobID string, req StateChangeRequest) (ReplayJob, error) {
	return s.changeReplayState(ctx, actor, replayJobID, req, s.store.CancelReplayJob)
}

func (s *ControlService) changeReplayState(ctx context.Context, actor authz.Actor, replayJobID string, req StateChangeRequest, fn func(context.Context, string, string, string, string) (ReplayJob, error)) (ReplayJob, error) {
	if !authz.Can(actor, "replay:write", actor.TenantID) {
		return ReplayJob{}, ErrForbidden
	}
	if strings.TrimSpace(req.Reason) == "" {
		return ReplayJob{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	return fn(ctx, actor.TenantID, replayJobID, actor.ID, req.Reason)
}

func (s *ControlService) ListAuditEvents(ctx context.Context, actor authz.Actor, limit int) ([]domain.AuditEvent, error) {
	if !authz.Can(actor, "audit:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListAuditEvents(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetAuditChainHead(ctx context.Context, actor authz.Actor) (domain.AuditChainHead, error) {
	if !authz.Can(actor, "audit:read", actor.TenantID) {
		return domain.AuditChainHead{}, ErrForbidden
	}
	return s.store.GetAuditChainHead(ctx, actor.TenantID)
}

func (s *ControlService) VerifyAuditChain(ctx context.Context, actor authz.Actor, req AuditChainVerifyRequest) (domain.AuditChainVerification, error) {
	if !authz.Can(actor, "audit:read", actor.TenantID) {
		return domain.AuditChainVerification{}, ErrForbidden
	}
	if req.FromSequence < 0 || req.ToSequence < 0 {
		return domain.AuditChainVerification{}, fmt.Errorf("%w: sequence values must be non-negative", ErrInvalidInput)
	}
	if req.FromSequence > 0 && req.ToSequence > 0 && req.FromSequence > req.ToSequence {
		return domain.AuditChainVerification{}, fmt.Errorf("%w: from_sequence must be before to_sequence", ErrInvalidInput)
	}
	return s.store.VerifyAuditChain(ctx, actor.TenantID, req)
}

func (s *ControlService) CreateAuditChainAnchor(ctx context.Context, actor authz.Actor, req AuditChainAnchorRequest) (domain.AuditChainAnchor, error) {
	if !authz.Can(actor, "security:write", actor.TenantID) {
		return domain.AuditChainAnchor{}, ErrForbidden
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		return domain.AuditChainAnchor{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	if req.FromSequence < 0 || req.ToSequence < 0 {
		return domain.AuditChainAnchor{}, fmt.Errorf("%w: sequence values must be non-negative", ErrInvalidInput)
	}
	if req.FromSequence > 0 && req.ToSequence > 0 && req.FromSequence > req.ToSequence {
		return domain.AuditChainAnchor{}, fmt.Errorf("%w: from_sequence must be before to_sequence", ErrInvalidInput)
	}
	return s.store.CreateAuditChainAnchor(ctx, actor.TenantID, actor.ID, req)
}

func (s *ControlService) ListAuditChainAnchors(ctx context.Context, actor authz.Actor, limit int) ([]domain.AuditChainAnchor, error) {
	if !authz.Can(actor, "audit:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListAuditChainAnchors(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetAuditChainAnchor(ctx context.Context, actor authz.Actor, anchorID string) (domain.AuditChainAnchor, error) {
	if !authz.Can(actor, "audit:read", actor.TenantID) {
		return domain.AuditChainAnchor{}, ErrForbidden
	}
	if strings.TrimSpace(anchorID) == "" {
		return domain.AuditChainAnchor{}, fmt.Errorf("%w: anchor_id is required", ErrInvalidInput)
	}
	return s.store.GetAuditChainAnchor(ctx, actor.TenantID, anchorID)
}

func (s *ControlService) ListRetentionPolicies(ctx context.Context, actor authz.Actor, limit int) ([]domain.RetentionPolicy, error) {
	if !authz.Can(actor, "security:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListRetentionPolicies(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) CreateRetentionPolicy(ctx context.Context, actor authz.Actor, req CreateRetentionPolicyRequest) (domain.RetentionPolicy, error) {
	if !authz.Can(actor, "security:write", actor.TenantID) {
		return domain.RetentionPolicy{}, ErrForbidden
	}
	req.ResourceType = strings.TrimSpace(req.ResourceType)
	req.SourceID = strings.TrimSpace(req.SourceID)
	req.State = normalizeState(req.State)
	req.HoldReason = strings.TrimSpace(req.HoldReason)
	if err := validateRetentionPolicyInput(req.ResourceType, req.RetentionDays, req.State); err != nil {
		return domain.RetentionPolicy{}, err
	}
	if req.LegalHold && req.HoldReason == "" {
		return domain.RetentionPolicy{}, fmt.Errorf("%w: hold_reason is required when legal_hold is true", ErrInvalidInput)
	}
	return s.store.CreateRetentionPolicy(ctx, actor.TenantID, actor.ID, req)
}

func (s *ControlService) UpdateRetentionPolicy(ctx context.Context, actor authz.Actor, policyID string, req UpdateRetentionPolicyRequest) (domain.RetentionPolicy, error) {
	if !authz.Can(actor, "security:write", actor.TenantID) {
		return domain.RetentionPolicy{}, ErrForbidden
	}
	if strings.TrimSpace(policyID) == "" {
		return domain.RetentionPolicy{}, fmt.Errorf("%w: policy id is required", ErrInvalidInput)
	}
	req.State = normalizeOptionalState(req.State)
	if req.RetentionDays != nil && (*req.RetentionDays <= 0 || *req.RetentionDays > 3650) {
		return domain.RetentionPolicy{}, fmt.Errorf("%w: retention_days must be between 1 and 3650", ErrInvalidInput)
	}
	if req.State != "" && req.State != domain.StateActive && req.State != domain.StateDisabled {
		return domain.RetentionPolicy{}, fmt.Errorf("%w: state must be active or disabled", ErrInvalidInput)
	}
	if req.SourceID != nil {
		trimmed := strings.TrimSpace(*req.SourceID)
		req.SourceID = &trimmed
	}
	if req.HoldReason != nil {
		trimmed := strings.TrimSpace(*req.HoldReason)
		req.HoldReason = &trimmed
	}
	if req.LegalHold != nil && *req.LegalHold && (req.HoldReason == nil || *req.HoldReason == "") {
		return domain.RetentionPolicy{}, fmt.Errorf("%w: hold_reason is required when legal_hold is true", ErrInvalidInput)
	}
	return s.store.UpdateRetentionPolicy(ctx, actor.TenantID, policyID, actor.ID, req)
}

func (s *ControlService) CreateProviderConnection(ctx context.Context, actor authz.Actor, req CreateProviderConnectionRequest) (domain.ProviderConnection, error) {
	if !authz.Can(actor, "sources:write", actor.TenantID) {
		return domain.ProviderConnection{}, ErrForbidden
	}
	if err := validateProviderConnectionRequest(&req); err != nil {
		return domain.ProviderConnection{}, err
	}
	return s.store.CreateProviderConnection(ctx, actor.TenantID, actor.ID, req)
}

func (s *ControlService) ListProviderConnections(ctx context.Context, actor authz.Actor, limit int) ([]domain.ProviderConnection, error) {
	if !authz.Can(actor, "sources:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListProviderConnections(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetProviderConnection(ctx context.Context, actor authz.Actor, connectionID string) (domain.ProviderConnection, error) {
	if !authz.Can(actor, "sources:read", actor.TenantID) {
		return domain.ProviderConnection{}, ErrForbidden
	}
	if strings.TrimSpace(connectionID) == "" {
		return domain.ProviderConnection{}, fmt.Errorf("%w: connection_id is required", ErrInvalidInput)
	}
	return s.store.GetProviderConnection(ctx, actor.TenantID, connectionID)
}

func (s *ControlService) VerifyProviderConnection(ctx context.Context, actor authz.Actor, connectionID string, req ProviderConnectionStateRequest) (domain.ProviderConnection, error) {
	if !authz.Can(actor, "sources:write", actor.TenantID) {
		return domain.ProviderConnection{}, ErrForbidden
	}
	if strings.TrimSpace(connectionID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.ProviderConnection{}, fmt.Errorf("%w: connection_id and reason are required", ErrInvalidInput)
	}
	return s.store.VerifyProviderConnection(ctx, actor.TenantID, connectionID, actor.ID, strings.TrimSpace(req.Reason))
}

func (s *ControlService) RevokeProviderConnection(ctx context.Context, actor authz.Actor, connectionID string, req ProviderConnectionStateRequest) (domain.ProviderConnection, error) {
	if !authz.Can(actor, "sources:write", actor.TenantID) {
		return domain.ProviderConnection{}, ErrForbidden
	}
	if strings.TrimSpace(connectionID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.ProviderConnection{}, fmt.Errorf("%w: connection_id and reason are required", ErrInvalidInput)
	}
	return s.store.RevokeProviderConnection(ctx, actor.TenantID, connectionID, actor.ID, strings.TrimSpace(req.Reason))
}

func (s *ControlService) DryRunReconciliation(ctx context.Context, actor authz.Actor, req ReconciliationJobRequest) (domain.ReconciliationJob, error) {
	if !authz.Can(actor, "replay:read", actor.TenantID) {
		return domain.ReconciliationJob{}, ErrForbidden
	}
	if err := validateReconciliationJobRequest(&req, false); err != nil {
		return domain.ReconciliationJob{}, err
	}
	req.DryRun = true
	return s.store.DryRunReconciliation(ctx, actor.TenantID, req)
}

func (s *ControlService) CreateReconciliationJob(ctx context.Context, actor authz.Actor, req ReconciliationJobRequest) (domain.ReconciliationJob, error) {
	if !authz.Can(actor, "replay:write", actor.TenantID) {
		return domain.ReconciliationJob{}, ErrForbidden
	}
	if err := validateReconciliationJobRequest(&req, true); err != nil {
		return domain.ReconciliationJob{}, err
	}
	return s.store.CreateReconciliationJob(ctx, actor.TenantID, actor.ID, req)
}

func (s *ControlService) ListReconciliationJobs(ctx context.Context, actor authz.Actor, limit int) ([]domain.ReconciliationJob, error) {
	if !authz.Can(actor, "replay:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListReconciliationJobs(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetReconciliationJob(ctx context.Context, actor authz.Actor, jobID string) (domain.ReconciliationJob, error) {
	if !authz.Can(actor, "replay:read", actor.TenantID) {
		return domain.ReconciliationJob{}, ErrForbidden
	}
	if strings.TrimSpace(jobID) == "" {
		return domain.ReconciliationJob{}, fmt.Errorf("%w: job_id is required", ErrInvalidInput)
	}
	return s.store.GetReconciliationJob(ctx, actor.TenantID, jobID)
}

func (s *ControlService) ListReconciliationItems(ctx context.Context, actor authz.Actor, jobID string, limit int) ([]domain.ReconciliationItem, error) {
	if !authz.Can(actor, "replay:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	if strings.TrimSpace(jobID) == "" {
		return nil, fmt.Errorf("%w: job_id is required", ErrInvalidInput)
	}
	return s.store.ListReconciliationItems(ctx, actor.TenantID, jobID, normalizeLimit(limit))
}

func (s *ControlService) CancelReconciliationJob(ctx context.Context, actor authz.Actor, jobID string, req ProviderConnectionStateRequest) (domain.ReconciliationJob, error) {
	if !authz.Can(actor, "replay:write", actor.TenantID) {
		return domain.ReconciliationJob{}, ErrForbidden
	}
	if strings.TrimSpace(jobID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.ReconciliationJob{}, fmt.Errorf("%w: job_id and reason are required", ErrInvalidInput)
	}
	return s.store.CancelReconciliationJob(ctx, actor.TenantID, jobID, actor.ID, strings.TrimSpace(req.Reason))
}

func (s *ControlService) CreateAuditExport(ctx context.Context, actor authz.Actor, req CreateAuditExportRequest) (domain.EvidenceExport, error) {
	if !authz.Can(actor, "audit:read", actor.TenantID) {
		return domain.EvidenceExport{}, ErrForbidden
	}
	if (req.IncludeRawPayloads || req.IncludePayloadBodies) && !s.authorized(ctx, actor, "events:raw", "audit_export", "", "") {
		return domain.EvidenceExport{}, ErrForbidden
	}
	if !req.From.IsZero() && !req.To.IsZero() && req.From.After(req.To) {
		return domain.EvidenceExport{}, fmt.Errorf("%w: from must be before to", ErrInvalidInput)
	}
	req.Reason = strings.TrimSpace(req.Reason)
	return s.store.CreateAuditExport(ctx, actor.TenantID, actor.ID, req)
}

func (s *ControlService) CreateTransformation(ctx context.Context, actor authz.Actor, req CreateTransformationRequest) (domain.Transformation, error) {
	if !authz.Can(actor, "routes:write", actor.TenantID) {
		return domain.Transformation{}, ErrForbidden
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return domain.Transformation{}, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if len(req.Operations) != 0 {
		if _, err := transform.ParseOperations(req.Operations); err != nil {
			return domain.Transformation{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
	}
	return s.store.CreateTransformation(ctx, actor.TenantID, actor.ID, req)
}

func (s *ControlService) ListTransformations(ctx context.Context, actor authz.Actor, limit int) ([]domain.Transformation, error) {
	if !authz.Can(actor, "routes:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListTransformations(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetTransformation(ctx context.Context, actor authz.Actor, transformationID string) (domain.Transformation, error) {
	if !authz.Can(actor, "routes:read", actor.TenantID) {
		return domain.Transformation{}, ErrForbidden
	}
	return s.store.GetTransformation(ctx, actor.TenantID, transformationID)
}

func (s *ControlService) CreateTransformationVersion(ctx context.Context, actor authz.Actor, transformationID string, req CreateTransformationVersionRequest) (domain.TransformationVersion, error) {
	if !authz.Can(actor, "routes:write", actor.TenantID) {
		return domain.TransformationVersion{}, ErrForbidden
	}
	if strings.TrimSpace(transformationID) == "" || len(req.Operations) == 0 {
		return domain.TransformationVersion{}, fmt.Errorf("%w: transformation_id and operations are required", ErrInvalidInput)
	}
	if _, err := transform.ParseOperations(req.Operations); err != nil {
		return domain.TransformationVersion{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	return s.store.CreateTransformationVersion(ctx, actor.TenantID, transformationID, actor.ID, req)
}

func (s *ControlService) ListTransformationVersions(ctx context.Context, actor authz.Actor, transformationID string, limit int) ([]domain.TransformationVersion, error) {
	if !authz.Can(actor, "routes:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListTransformationVersions(ctx, actor.TenantID, transformationID, normalizeLimit(limit))
}

func (s *ControlService) ActivateTransformationVersion(ctx context.Context, actor authz.Actor, transformationID, versionID string, req ActivateTransformationVersionRequest) (domain.TransformationVersion, error) {
	if !authz.Can(actor, "routes:write", actor.TenantID) {
		return domain.TransformationVersion{}, ErrForbidden
	}
	if strings.TrimSpace(req.Reason) == "" {
		return domain.TransformationVersion{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	return s.store.ActivateTransformationVersion(ctx, actor.TenantID, transformationID, versionID, actor.ID, req.Reason)
}

func (s *ControlService) ListAuditExports(ctx context.Context, actor authz.Actor, limit int) ([]domain.EvidenceExport, error) {
	if !authz.Can(actor, "audit:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	exports, err := s.store.ListAuditExports(ctx, actor.TenantID, normalizeLimit(limit))
	if err != nil {
		return nil, err
	}
	if !s.authorized(ctx, actor, "events:raw", "audit_export", "", "") {
		filtered := exports[:0]
		for _, export := range exports {
			if !export.IncludeRawPayloads && !export.IncludePayloadBodies {
				filtered = append(filtered, export)
			}
		}
		exports = filtered
	}
	return exports, nil
}

func (s *ControlService) GetAuditExport(ctx context.Context, actor authz.Actor, exportID string) (domain.EvidenceExport, error) {
	if !authz.Can(actor, "audit:read", actor.TenantID) {
		return domain.EvidenceExport{}, ErrForbidden
	}
	export, err := s.store.GetAuditExport(ctx, actor.TenantID, exportID)
	if err != nil {
		return domain.EvidenceExport{}, err
	}
	if (export.IncludeRawPayloads || export.IncludePayloadBodies) && !s.authorized(ctx, actor, "events:raw", "audit_export", exportID, "") {
		return domain.EvidenceExport{}, ErrForbidden
	}
	return export, nil
}

func (s *ControlService) DownloadAuditExport(ctx context.Context, actor authz.Actor, exportID string) (EvidenceExportDownload, error) {
	if !authz.Can(actor, "audit:read", actor.TenantID) {
		return EvidenceExportDownload{}, ErrForbidden
	}
	export, err := s.store.GetAuditExport(ctx, actor.TenantID, exportID)
	if err != nil {
		return EvidenceExportDownload{}, err
	}
	if (export.IncludeRawPayloads || export.IncludePayloadBodies) && !s.authorized(ctx, actor, "events:raw", "audit_export", exportID, "") {
		return EvidenceExportDownload{}, ErrForbidden
	}
	download, err := s.store.DownloadAuditExport(ctx, actor.TenantID, exportID, actor.ID)
	if err != nil {
		return EvidenceExportDownload{}, err
	}
	return download, nil
}

func (s *ControlService) ListDeadLetter(ctx context.Context, actor authz.Actor, limit int) ([]map[string]any, error) {
	if !authz.Can(actor, "deliveries:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListDeadLetter(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) ReleaseDeadLetter(ctx context.Context, actor authz.Actor, entryID string, req DeadLetterReleaseRequest) (ReplayJob, error) {
	if !authz.Can(actor, "deliveries:retry", actor.TenantID) {
		return ReplayJob{}, ErrForbidden
	}
	if req.Reason == "" {
		return ReplayJob{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	return s.store.ReleaseDeadLetter(ctx, actor.TenantID, entryID, actor.ID, req.Reason)
}

func (s *ControlService) BulkReleaseDeadLetter(ctx context.Context, actor authz.Actor, req DeadLetterBulkReleaseRequest) ([]ReplayJob, error) {
	if !authz.Can(actor, "deliveries:retry", actor.TenantID) {
		return nil, ErrForbidden
	}
	if strings.TrimSpace(req.Reason) == "" {
		return nil, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	return s.store.BulkReleaseDeadLetter(ctx, actor.TenantID, req.EntryIDs, actor.ID, req.Reason)
}

func (s *ControlService) ListQuarantine(ctx context.Context, actor authz.Actor, limit int) ([]map[string]any, error) {
	if !authz.Can(actor, "security:read", actor.TenantID) {
		return nil, ErrForbidden
	}
	return s.store.ListQuarantine(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) ApproveQuarantine(ctx context.Context, actor authz.Actor, entryID string, req QuarantineDecisionRequest) (map[string]any, error) {
	if !authz.Can(actor, "security:write", actor.TenantID) {
		return nil, ErrForbidden
	}
	if req.Reason == "" {
		return nil, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	return s.store.ApproveQuarantine(ctx, actor.TenantID, entryID, actor.ID, req.Reason, req.RouteAfterRelease)
}

func (s *ControlService) RejectQuarantine(ctx context.Context, actor authz.Actor, entryID string, req QuarantineDecisionRequest) (map[string]any, error) {
	if !authz.Can(actor, "security:write", actor.TenantID) {
		return nil, ErrForbidden
	}
	if req.Reason == "" {
		return nil, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	return s.store.RejectQuarantine(ctx, actor.TenantID, entryID, actor.ID, req.Reason)
}

func normalizeLimit(limit int) int {
	if limit <= 0 || limit > 100 {
		return 50
	}
	return limit
}

func validMetricName(name string) bool {
	if len(name) > 128 {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func normalizeCreateAlertRule(req *CreateAlertRuleRequest) error {
	req.Name = strings.TrimSpace(req.Name)
	req.RuleType = strings.TrimSpace(req.RuleType)
	req.MetricName = strings.TrimSpace(req.MetricName)
	if req.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if !validAlertRuleType(req.RuleType) {
		return fmt.Errorf("%w: rule_type is invalid", ErrInvalidInput)
	}
	if req.MetricName == "" {
		req.MetricName = defaultAlertMetric(req.RuleType)
	}
	if !validMetricName(req.MetricName) {
		return fmt.Errorf("%w: metric_name is invalid", ErrInvalidInput)
	}
	if req.Comparator == "" {
		req.Comparator = ">="
	}
	if !validComparator(req.Comparator) {
		return fmt.Errorf("%w: comparator is invalid", ErrInvalidInput)
	}
	if req.WindowSeconds == 0 {
		req.WindowSeconds = 300
	}
	if req.WindowSeconds < 60 || req.WindowSeconds > 86400 {
		return fmt.Errorf("%w: window_seconds must be between 60 and 86400", ErrInvalidInput)
	}
	if req.State == "" {
		req.State = domain.StateActive
	}
	if req.State != domain.StateActive && req.State != domain.StateDisabled {
		return fmt.Errorf("%w: alert state must be active or disabled", ErrInvalidInput)
	}
	if req.Dimensions == nil {
		req.Dimensions = map[string]string{}
	}
	if err := validateAlertDimensions(req.Dimensions); err != nil {
		return err
	}
	channelIDs, err := normalizeIDList(req.ChannelIDs, 16, "channel_ids")
	if err != nil {
		return err
	}
	req.ChannelIDs = channelIDs
	return nil
}

func normalizeUpdateAlertRule(req *UpdateAlertRuleRequest) error {
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			return fmt.Errorf("%w: name cannot be empty", ErrInvalidInput)
		}
		req.Name = &name
	}
	if req.Comparator != nil {
		comparator := strings.TrimSpace(*req.Comparator)
		if !validComparator(comparator) {
			return fmt.Errorf("%w: comparator is invalid", ErrInvalidInput)
		}
		req.Comparator = &comparator
	}
	if req.WindowSeconds != nil && (*req.WindowSeconds < 60 || *req.WindowSeconds > 86400) {
		return fmt.Errorf("%w: window_seconds must be between 60 and 86400", ErrInvalidInput)
	}
	if req.State != nil {
		state := strings.TrimSpace(*req.State)
		if state != domain.StateActive && state != domain.StateDisabled {
			return fmt.Errorf("%w: alert state must be active or disabled", ErrInvalidInput)
		}
		req.State = &state
	}
	if req.Dimensions != nil {
		if err := validateAlertDimensions(req.Dimensions); err != nil {
			return err
		}
	}
	if req.ChannelIDs != nil {
		channelIDs, err := normalizeIDList(*req.ChannelIDs, 16, "channel_ids")
		if err != nil {
			return err
		}
		req.ChannelIDs = &channelIDs
	}
	return nil
}

func normalizeCreateNotificationChannel(req *CreateNotificationChannelRequest) error {
	req.Name = strings.TrimSpace(req.Name)
	req.ChannelType = strings.TrimSpace(req.ChannelType)
	req.URL = strings.TrimSpace(req.URL)
	req.SigningSecret = strings.TrimSpace(req.SigningSecret)
	if req.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if req.ChannelType == "" {
		req.ChannelType = domain.NotificationChannelWebhook
	}
	if req.ChannelType != domain.NotificationChannelWebhook {
		return fmt.Errorf("%w: channel_type must be webhook", ErrInvalidInput)
	}
	if req.URL == "" {
		return fmt.Errorf("%w: url is required", ErrInvalidInput)
	}
	if len(req.SigningSecret) < 16 {
		return fmt.Errorf("%w: signing_secret must be at least 16 bytes", ErrInvalidInput)
	}
	return nil
}

func normalizeUpdateNotificationChannel(req *UpdateNotificationChannelRequest) error {
	if req.Name == nil && req.URL == nil && req.SigningSecret == nil && req.State == nil {
		return fmt.Errorf("%w: at least one channel field is required", ErrInvalidInput)
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			return fmt.Errorf("%w: name cannot be empty", ErrInvalidInput)
		}
		req.Name = &name
	}
	if req.URL != nil {
		rawURL := strings.TrimSpace(*req.URL)
		if rawURL == "" {
			return fmt.Errorf("%w: url cannot be empty", ErrInvalidInput)
		}
		req.URL = &rawURL
	}
	if req.SigningSecret != nil {
		secret := strings.TrimSpace(*req.SigningSecret)
		if len(secret) < 16 {
			return fmt.Errorf("%w: signing_secret must be at least 16 bytes", ErrInvalidInput)
		}
		req.SigningSecret = &secret
	}
	if req.State != nil {
		state := strings.TrimSpace(*req.State)
		if state != domain.StateActive && state != domain.StateDisabled {
			return fmt.Errorf("%w: channel state must be active or disabled", ErrInvalidInput)
		}
		req.State = &state
	}
	return nil
}

func normalizeCreateSIEMSink(req *CreateSIEMSinkRequest) error {
	req.Name = strings.TrimSpace(req.Name)
	req.SinkType = strings.TrimSpace(req.SinkType)
	req.URL = strings.TrimSpace(req.URL)
	req.SigningSecret = strings.TrimSpace(req.SigningSecret)
	if req.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if req.SinkType == "" {
		req.SinkType = domain.SIEMSinkWebhook
	}
	if req.SinkType != domain.SIEMSinkWebhook {
		return fmt.Errorf("%w: sink_type must be webhook", ErrInvalidInput)
	}
	if req.URL == "" {
		return fmt.Errorf("%w: url is required", ErrInvalidInput)
	}
	if len(req.SigningSecret) < 16 {
		return fmt.Errorf("%w: signing_secret must be at least 16 bytes", ErrInvalidInput)
	}
	return nil
}

func normalizeUpdateSIEMSink(req *UpdateSIEMSinkRequest) error {
	if req.Name == nil && req.URL == nil && req.SigningSecret == nil && req.State == nil {
		return fmt.Errorf("%w: at least one sink field is required", ErrInvalidInput)
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			return fmt.Errorf("%w: name cannot be empty", ErrInvalidInput)
		}
		req.Name = &name
	}
	if req.URL != nil {
		rawURL := strings.TrimSpace(*req.URL)
		if rawURL == "" {
			return fmt.Errorf("%w: url cannot be empty", ErrInvalidInput)
		}
		req.URL = &rawURL
	}
	if req.SigningSecret != nil {
		secret := strings.TrimSpace(*req.SigningSecret)
		if len(secret) < 16 {
			return fmt.Errorf("%w: signing_secret must be at least 16 bytes", ErrInvalidInput)
		}
		req.SigningSecret = &secret
	}
	if req.State != nil {
		state := strings.TrimSpace(*req.State)
		if state != domain.StateActive && state != domain.StateDisabled {
			return fmt.Errorf("%w: sink state must be active or disabled", ErrInvalidInput)
		}
		req.State = &state
	}
	return nil
}

func normalizeIDList(values []string, max int, field string) ([]string, error) {
	if len(values) > max {
		return nil, fmt.Errorf("%w: %s cannot exceed %d entries", ErrInvalidInput, field, max)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("%w: %s cannot contain empty ids", ErrInvalidInput, field)
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out, nil
}

func validateAlertDimensions(dimensions map[string]string) error {
	if len(dimensions) > 8 {
		return fmt.Errorf("%w: alert dimensions cannot exceed 8 keys", ErrInvalidInput)
	}
	for key, value := range dimensions {
		if strings.TrimSpace(key) == "" || !validMetricName(key) {
			return fmt.Errorf("%w: alert dimension keys are invalid", ErrInvalidInput)
		}
		if len(value) > 128 {
			return fmt.Errorf("%w: alert dimension values cannot exceed 128 bytes", ErrInvalidInput)
		}
	}
	return nil
}

func validAlertRuleType(ruleType string) bool {
	switch ruleType {
	case domain.AlertRuleDeadLetterOpen, domain.AlertRuleQuarantineOpen, domain.AlertRuleEndpointFailureRate24h,
		domain.AlertRuleEndpointCircuitOpen, domain.AlertRuleOldestOutboxAgeSeconds, domain.AlertRuleWorkerLeaseExpired,
		domain.AlertRuleAuditChainVerificationFails, domain.AlertRuleReconciliationFailedItems:
		return true
	default:
		return false
	}
}

func defaultAlertMetric(ruleType string) string {
	switch ruleType {
	case domain.AlertRuleDeadLetterOpen:
		return "dead_letter.open"
	case domain.AlertRuleQuarantineOpen:
		return "quarantine.open"
	case domain.AlertRuleEndpointFailureRate24h:
		return "endpoint.failure_rate_24h"
	case domain.AlertRuleEndpointCircuitOpen:
		return "endpoint.circuit_open"
	case domain.AlertRuleOldestOutboxAgeSeconds:
		return "outbox.oldest_age_seconds"
	case domain.AlertRuleWorkerLeaseExpired:
		return "worker.expired_leases"
	case domain.AlertRuleAuditChainVerificationFails:
		return "audit_chain.verification_failures"
	case domain.AlertRuleReconciliationFailedItems:
		return "reconciliation.failed_items"
	default:
		return ""
	}
}

func validComparator(comparator string) bool {
	switch comparator {
	case ">", ">=", "<", "<=", "==":
		return true
	default:
		return false
	}
}

func validAlertFiringState(state string) bool {
	switch state {
	case domain.AlertFiringOpen, domain.AlertFiringAcknowledged, domain.AlertFiringResolved:
		return true
	default:
		return false
	}
}

func validSignalDeliveryState(state string) bool {
	switch state {
	case domain.SignalDeliveryScheduled, domain.SignalDeliveryRunning, domain.SignalDeliverySucceeded, domain.SignalDeliveryFailed:
		return true
	default:
		return false
	}
}

func validateRetentionPolicyInput(resourceType string, retentionDays int, state string) error {
	switch resourceType {
	case domain.RetentionResourceRawPayload, domain.RetentionResourceAuditEvent, domain.RetentionResourceNormalized, domain.RetentionResourceDeliveryPayload, domain.RetentionResourceProviderAPI:
	default:
		return fmt.Errorf("%w: resource_type must be raw_payload, audit_event, normalized_envelope_data, delivery_payload, or provider_api_evidence", ErrInvalidInput)
	}
	if retentionDays <= 0 || retentionDays > 3650 {
		return fmt.Errorf("%w: retention_days must be between 1 and 3650", ErrInvalidInput)
	}
	if state != domain.StateActive && state != domain.StateDisabled {
		return fmt.Errorf("%w: state must be active or disabled", ErrInvalidInput)
	}
	return nil
}

func validateProviderConnectionRequest(req *CreateProviderConnectionRequest) error {
	req.Name = strings.TrimSpace(req.Name)
	req.Provider = strings.ToLower(strings.TrimSpace(req.Provider))
	req.CredentialType = strings.TrimSpace(req.CredentialType)
	req.Credential = strings.TrimSpace(req.Credential)
	if req.CredentialType == "" {
		req.CredentialType = "api_key"
	}
	if req.Name == "" || req.Provider == "" || req.Credential == "" {
		return fmt.Errorf("%w: name, provider, and credential are required", ErrInvalidInput)
	}
	switch req.Provider {
	case "stripe", "github", "shopify", "slack":
	default:
		return fmt.Errorf("%w: provider must be stripe, github, shopify, or slack", ErrInvalidInput)
	}
	if req.CredentialType != "api_key" && req.CredentialType != "bearer_token" {
		return fmt.Errorf("%w: credential_type must be api_key or bearer_token", ErrInvalidInput)
	}
	if req.Config == nil {
		req.Config = map[string]string{}
	}
	for key, value := range req.Config {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			return fmt.Errorf("%w: config keys must be non-empty", ErrInvalidInput)
		}
		delete(req.Config, key)
		req.Config[trimmedKey] = strings.TrimSpace(value)
	}
	return nil
}

func validateReconciliationJobRequest(req *ReconciliationJobRequest, requireReason bool) error {
	req.ConnectionID = strings.TrimSpace(req.ConnectionID)
	req.ScopeObjectID = strings.TrimSpace(req.ScopeObjectID)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.ConnectionID == "" {
		return fmt.Errorf("%w: connection_id is required", ErrInvalidInput)
	}
	if requireReason && req.Reason == "" {
		return fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	if !req.WindowStart.IsZero() && !req.WindowEnd.IsZero() && req.WindowStart.After(req.WindowEnd) {
		return fmt.Errorf("%w: window_start must be before window_end", ErrInvalidInput)
	}
	if req.RouteRecovered && !req.CaptureMissing {
		return fmt.Errorf("%w: route_recovered requires capture_missing", ErrInvalidInput)
	}
	return nil
}

func validateRetryPolicy(req CreateRetryPolicyRequest) error {
	if req.State != domain.StateActive && req.State != domain.StateDisabled {
		return fmt.Errorf("%w: state must be active or disabled", ErrInvalidInput)
	}
	if req.MaxAttempts <= 0 || req.MaxAttempts > 100 {
		return fmt.Errorf("%w: max_attempts must be between 1 and 100", ErrInvalidInput)
	}
	if req.MaxDurationSeconds <= 0 || req.MaxDurationSeconds > int((30*24*time.Hour)/time.Second) {
		return fmt.Errorf("%w: max_duration_seconds must be between 1 and 2592000", ErrInvalidInput)
	}
	if req.InitialDelaySeconds <= 0 || req.InitialDelaySeconds > req.MaxDelaySeconds {
		return fmt.Errorf("%w: initial_delay_seconds must be positive and no greater than max_delay_seconds", ErrInvalidInput)
	}
	if req.MaxDelaySeconds <= 0 || req.MaxDelaySeconds > int((24*time.Hour)/time.Second) {
		return fmt.Errorf("%w: max_delay_seconds must be between 1 and 86400", ErrInvalidInput)
	}
	if req.RateLimitPerMinute < 0 || req.RateLimitPerMinute > 60000 {
		return fmt.Errorf("%w: rate_limit_per_minute must be between 0 and 60000", ErrInvalidInput)
	}
	return nil
}

func normalizeReplayRequest(req *ReplayRequest, requireScope bool) error {
	req.ConfigMode = strings.TrimSpace(req.ConfigMode)
	if req.ConfigMode == "" {
		req.ConfigMode = ReplayConfigCurrent
	}
	if req.ConfigMode != ReplayConfigCurrent && req.ConfigMode != ReplayConfigOriginal {
		return fmt.Errorf("%w: config_mode must be current or original", ErrInvalidInput)
	}
	if req.RateLimitPerMinute < 0 || req.RateLimitPerMinute > 60000 {
		return fmt.Errorf("%w: rate_limit_per_minute must be between 0 and 60000", ErrInvalidInput)
	}
	if requireScope && strings.TrimSpace(req.EventID) == "" && strings.TrimSpace(req.DeliveryID) == "" {
		return fmt.Errorf("%w: event_id or delivery_id is required", ErrInvalidInput)
	}
	return nil
}

func validateEndpointMTLS(certPEM, keyPEM string) (bool, string, []byte, []byte, error) {
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)
	if certPEM == "" && keyPEM == "" {
		return false, "", nil, nil, nil
	}
	if certPEM == "" || keyPEM == "" {
		return false, "", nil, nil, fmt.Errorf("%w: mtls_client_cert_pem and mtls_client_key_pem are required together", ErrInvalidInput)
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return false, "", nil, nil, fmt.Errorf("%w: invalid mTLS client certificate pair", ErrInvalidInput)
	}
	subject := ""
	if len(pair.Certificate) > 0 {
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return false, "", nil, nil, fmt.Errorf("%w: invalid mTLS client certificate", ErrInvalidInput)
		}
		subject = cert.Subject.String()
	}
	return true, subject, []byte(certPEM), []byte(keyPEM), nil
}

func normalizeState(state string) string {
	state = strings.TrimSpace(state)
	if state == "" {
		return domain.StateActive
	}
	return state
}

func normalizeOptionalState(state string) string {
	return strings.TrimSpace(state)
}

func normalizeEventTypes(eventTypes []string) []string {
	seen := make(map[string]struct{}, len(eventTypes))
	out := make([]string, 0, len(eventTypes))
	for _, eventType := range eventTypes {
		eventType = strings.TrimSpace(eventType)
		if eventType == "" {
			continue
		}
		if _, ok := seen[eventType]; ok {
			continue
		}
		seen[eventType] = struct{}{}
		out = append(out, eventType)
	}
	return out
}

func validRouteState(state string) bool {
	switch state {
	case domain.StateDraft, domain.StateActive, domain.StateInactive:
		return true
	default:
		return false
	}
}

func validSchemaState(state string) bool {
	switch state {
	case domain.StateActive, domain.StateDeprecated, domain.StateRetired:
		return true
	default:
		return false
	}
}

func normalizeScopes(scopes []string) []string {
	seen := make(map[string]struct{}, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	return out
}

func tokenPrefix(token string) string {
	if len(token) <= 8 {
		return token
	}
	return token[:8]
}

func tokenLast4(token string) string {
	if len(token) <= 4 {
		return token
	}
	return token[len(token)-4:]
}

func validRole(role authz.Role) bool {
	switch role {
	case authz.RoleOwner, authz.RoleAdmin, authz.RoleDeveloper, authz.RoleOperator, authz.RoleSecurity, authz.RoleAuditor, authz.RoleSupport:
		return true
	default:
		return false
	}
}
