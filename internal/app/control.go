package app

import (
	"context"
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
	CreateEndpoint(ctx context.Context, endpoint domain.Endpoint) (domain.Endpoint, error)
	ListEndpoints(ctx context.Context, tenantID string, limit int) ([]domain.Endpoint, error)
	TestEndpoint(ctx context.Context, tenantID, endpointID, actorID, reason string) (domain.Delivery, error)
	CreateSubscription(ctx context.Context, subscription domain.Subscription) (domain.Subscription, error)
	ListSubscriptions(ctx context.Context, tenantID string, limit int) ([]domain.Subscription, error)
	CreateRoute(ctx context.Context, route domain.Route) (domain.Route, error)
	ListRoutes(ctx context.Context, tenantID string, limit int) ([]domain.Route, error)
	ListRouteVersions(ctx context.Context, tenantID, routeID string, limit int) ([]domain.RouteVersion, error)
	ActivateRoute(ctx context.Context, tenantID, routeID, actorID, reason string) (domain.Route, error)
	DryRunRoute(ctx context.Context, tenantID, routeID, eventID string) (RouteDryRun, error)
	CreateRetryPolicy(ctx context.Context, tenantID, actorID string, req CreateRetryPolicyRequest) (domain.RetryPolicy, error)
	ListRetryPolicies(ctx context.Context, tenantID string, limit int) ([]domain.RetryPolicy, error)
	CreateEventType(ctx context.Context, eventType domain.EventType) (domain.EventType, error)
	ListEventTypes(ctx context.Context, tenantID string, limit int) ([]domain.EventType, error)
	CreateEventSchema(ctx context.Context, schema domain.EventSchema) (domain.EventSchema, error)
	ListEventSchemas(ctx context.Context, tenantID, eventType string, limit int) ([]domain.EventSchema, error)
	GetEventSchema(ctx context.Context, tenantID, eventType, version string) (domain.EventSchema, error)
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
}

func NewControlService(store ControlStore, validator ssrf.Validator) *ControlService {
	return &ControlService{store: store, ssrfValidator: validator}
}

type CreateSourceRequest struct {
	Name               string `json:"name"`
	Provider           string `json:"provider"`
	Adapter            string `json:"adapter"`
	VerificationSecret string `json:"verification_secret"`
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
	Name          string `json:"name"`
	URL           string `json:"url"`
	RetryPolicyID string `json:"retry_policy_id,omitempty"`
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

type CreateEventSchemaRequest struct {
	Version string `json:"version"`
	Schema  string `json:"schema"`
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
	ID                 string `json:"id"`
	State              string `json:"state"`
	ScopeHash          string `json:"scope_hash"`
	ConfigMode         string `json:"config_mode,omitempty"`
	RateLimitPerMinute int    `json:"rate_limit_per_minute,omitempty"`
	TotalItems         int    `json:"total_items"`
	ProcessedItems     int    `json:"processed_items"`
	FailedItems        int    `json:"failed_items"`
}

type StateChangeRequest struct {
	Reason string `json:"reason"`
}

type CreateRetentionPolicyRequest struct {
	ResourceType  string `json:"resource_type"`
	SourceID      string `json:"source_id,omitempty"`
	RetentionDays int    `json:"retention_days"`
	State         string `json:"state,omitempty"`
}

type UpdateRetentionPolicyRequest struct {
	RetentionDays *int    `json:"retention_days,omitempty"`
	State         string  `json:"state,omitempty"`
	SourceID      *string `json:"source_id,omitempty"`
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
	endpoint, err := s.store.CreateEndpoint(ctx, domain.Endpoint{
		TenantID:      actor.TenantID,
		Name:          req.Name,
		URL:           result.NormalizedURL,
		State:         domain.StateActive,
		RetryPolicyID: strings.TrimSpace(req.RetryPolicyID),
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
	if req.EndpointID == "" || len(req.EventTypes) == 0 {
		return domain.Subscription{}, fmt.Errorf("%w: endpoint_id and event_types are required", ErrInvalidInput)
	}
	payloadFormat := req.PayloadFormat
	if payloadFormat == "" {
		payloadFormat = "canonical_json"
	}
	return s.store.CreateSubscription(ctx, domain.Subscription{
		TenantID:         actor.TenantID,
		EndpointID:       req.EndpointID,
		EventTypes:       req.EventTypes,
		PayloadFormat:    payloadFormat,
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

func (s *ControlService) CreateRoute(ctx context.Context, actor authz.Actor, req CreateRouteRequest) (domain.Route, error) {
	if !authz.Can(actor, "routes:write", actor.TenantID) {
		return domain.Route{}, ErrForbidden
	}
	if req.SourceID == "" || req.EndpointID == "" || len(req.EventTypes) == 0 {
		return domain.Route{}, fmt.Errorf("%w: source_id, endpoint_id, and event_types are required", ErrInvalidInput)
	}
	state := req.State
	if state == "" {
		state = "draft"
	}
	priority := req.Priority
	if priority == 0 {
		priority = 100
	}
	return s.store.CreateRoute(ctx, domain.Route{
		TenantID:         actor.TenantID,
		SourceID:         req.SourceID,
		Name:             req.Name,
		Priority:         priority,
		EventTypes:       req.EventTypes,
		EndpointID:       req.EndpointID,
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
	if reason == "" {
		return domain.Route{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	return s.store.ActivateRoute(ctx, actor.TenantID, routeID, actor.ID, reason)
}

func (s *ControlService) DryRunRoute(ctx context.Context, actor authz.Actor, routeID, eventID string) (RouteDryRun, error) {
	if !authz.Can(actor, "routes:read", actor.TenantID) {
		return RouteDryRun{}, ErrForbidden
	}
	if routeID == "" || eventID == "" {
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

func (s *ControlService) CreateEventType(ctx context.Context, actor authz.Actor, req CreateEventTypeRequest) (domain.EventType, error) {
	if !authz.Can(actor, "schemas:write", actor.TenantID) {
		return domain.EventType{}, ErrForbidden
	}
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
	if !authz.Can(actor, "security:write", actor.TenantID) {
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
	if !authz.Can(actor, "security:write", actor.TenantID) {
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
	if !authz.Can(actor, "events:raw", actor.TenantID) {
		return domain.RawPayload{}, ErrForbidden
	}
	return s.store.GetRawPayload(ctx, actor.TenantID, eventID, actor.ID)
}

func (s *ControlService) GetNormalizedEvent(ctx context.Context, actor authz.Actor, eventID string, includeData bool) (domain.NormalizedEnvelope, error) {
	if !authz.Can(actor, "events:read", actor.TenantID) {
		return domain.NormalizedEnvelope{}, ErrForbidden
	}
	if includeData && !authz.Can(actor, "events:raw", actor.TenantID) {
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
	if !authz.Can(actor, "replay:write", actor.TenantID) {
		return ReplayJob{}, ErrForbidden
	}
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
	if err := validateRetentionPolicyInput(req.ResourceType, req.RetentionDays, req.State); err != nil {
		return domain.RetentionPolicy{}, err
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
	if (req.IncludeRawPayloads || req.IncludePayloadBodies) && !authz.Can(actor, "events:raw", actor.TenantID) {
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
	if !authz.Can(actor, "events:raw", actor.TenantID) {
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
	if (export.IncludeRawPayloads || export.IncludePayloadBodies) && !authz.Can(actor, "events:raw", actor.TenantID) {
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
	if (export.IncludeRawPayloads || export.IncludePayloadBodies) && !authz.Can(actor, "events:raw", actor.TenantID) {
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
