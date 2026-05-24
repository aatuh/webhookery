package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

const (
	StateActive     = "active"
	StateDisabled   = "disabled"
	StateDraft      = "draft"
	StateInactive   = "inactive"
	StateDeprecated = "deprecated"
	StateRetired    = "retired"

	RawStoragePostgres = "postgres"
	RawStorageS3       = "s3"

	StorageStatusStored  = "stored"
	StorageStatusDeleted = "deleted"

	RetentionResourceRawPayload      = "raw_payload"
	RetentionResourceAuditEvent      = "audit_event"
	RetentionResourceNormalized      = "normalized_envelope_data"
	RetentionResourceDeliveryPayload = "delivery_payload"
	RetentionResourceProviderAPI     = "provider_api_evidence"

	RetentionRunStateRunning   = "running"
	RetentionRunStateCompleted = "completed"
	RetentionRunStateFailed    = "failed"

	EvidenceExportStateReady  = "ready"
	EvidenceExportStateFailed = "failed"

	DedupeUnique              = "unique"
	DedupeDuplicateSuppressed = "duplicate_suppressed"
	DedupeCollision           = "collision"

	ConfigResourceSource         = "source"
	ConfigResourceEndpoint       = "endpoint"
	ConfigResourceSubscription   = "subscription"
	ConfigResourceRoute          = "route"
	ConfigResourceRetryPolicy    = "retry_policy"
	ConfigResourceSchema         = "event_schema"
	ConfigResourceTransformation = "transformation"

	SecretStateActive   = "active"
	SecretStatePrevious = "previous"
	SecretStateRevoked  = "revoked"

	ProviderConnectionStateActive  = "active"
	ProviderConnectionStateRevoked = "revoked"

	ReconciliationJobStateScheduled = "scheduled"
	ReconciliationJobStateRunning   = "running"
	ReconciliationJobStateCompleted = "completed"
	ReconciliationJobStateCanceled  = "canceled"
	ReconciliationJobStateFailed    = "failed"

	ReconciliationOutcomeMatched             = "matched"
	ReconciliationOutcomeMissing             = "missing"
	ReconciliationOutcomeCaptured            = "captured"
	ReconciliationOutcomeRedeliveryRequested = "redelivery_requested"
	ReconciliationOutcomeUnrecoverable       = "unrecoverable"
	ReconciliationOutcomeFailed              = "failed"
	VerificationReasonProviderAPIReconcile   = "provider_api_reconciliation"
	ProviderAPIEvidenceStorageStatusStored   = "stored"
	ProviderAPIEvidenceStorageStatusDeleted  = "deleted"
	ProviderAPIEvidenceStorageStatusMetadata = "metadata_only"

	AlertRuleDeadLetterOpen              = "dead_letter_open"
	AlertRuleQuarantineOpen              = "quarantine_open"
	AlertRuleEndpointFailureRate24h      = "endpoint_failure_rate_24h"
	AlertRuleEndpointCircuitOpen         = "endpoint_circuit_open"
	AlertRuleOldestOutboxAgeSeconds      = "oldest_outbox_age_seconds"
	AlertRuleWorkerLeaseExpired          = "worker_lease_expired"
	AlertRuleAuditChainVerificationFails = "audit_chain_verification_failures"
	AlertRuleReconciliationFailedItems   = "reconciliation_failed_items"

	AlertFiringOpen         = "open"
	AlertFiringAcknowledged = "acknowledged"
	AlertFiringResolved     = "resolved"

	NotificationChannelWebhook = "webhook"

	SignalDeliveryScheduled = "scheduled"
	SignalDeliveryRunning   = "in_progress"
	SignalDeliverySucceeded = "succeeded"
	SignalDeliveryFailed    = "failed"

	SIEMSinkWebhook = "webhook"

	AuditChainEntryStateActive    = "active"
	AuditChainEntryStateRetained  = "retained"
	AuditChainEntrySourceLive     = "live"
	AuditChainEntrySourceBackfill = "backfill"

	AdapterKindBuiltin     = "builtin"
	AdapterKindDeclarative = "declarative"
	AdapterKindPlugin      = "plugin"

	AdapterStateDraft           = "draft"
	AdapterStateAutomatedTests  = "automated_tests"
	AdapterStateSecurityReview  = "security_review"
	AdapterStateStagingApproved = "staging_approved"
	AdapterStateActive          = "active"
	AdapterStateDeprecated      = "deprecated"
	AdapterStateRetired         = "retired"
	AdapterRiskCore             = "core"
	AdapterRiskLow              = "low"
	AdapterRiskMedium           = "medium"
	AdapterRiskHigh             = "high"
)

type HeaderPair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func CanonicalHeaders(raw []HeaderPair) map[string][]string {
	headers := make(map[string][]string)
	for _, h := range raw {
		name := strings.ToLower(h.Name)
		headers[name] = append(headers[name], h.Value)
	}
	return headers
}

type Source struct {
	ID                  string
	TenantID            string
	Name                string
	Provider            string
	Adapter             string
	State               string
	CreatedBy           string
	VerificationSecret  []byte
	VerificationSecrets [][]byte
	CreatedAt           time.Time
}

type Endpoint struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	Name              string    `json:"name"`
	URL               string    `json:"url"`
	State             string    `json:"state"`
	RetryPolicyID     string    `json:"retry_policy_id,omitempty"`
	MTLSEnabled       bool      `json:"mtls_enabled"`
	MTLSCertSubject   string    `json:"mtls_cert_subject,omitempty"`
	MTLSClientCertPEM []byte    `json:"-"`
	MTLSClientKeyPEM  []byte    `json:"-"`
	CircuitState      string    `json:"circuit_state,omitempty"`
	FailureCount      int       `json:"failure_count,omitempty"`
	DisabledUntil     time.Time `json:"disabled_until,omitempty"`
	CreatedBy         string    `json:"-"`
	CreatedAt         time.Time `json:"created_at"`
}

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
}

type Membership struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
}

type APIKey struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	Name      string    `json:"name"`
	Prefix    string    `json:"prefix"`
	Last4     string    `json:"last4"`
	Hash      string    `json:"-"`
	Scopes    []string  `json:"scopes"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

type ProducerClient struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	Name            string    `json:"name"`
	SourceID        string    `json:"source_id,omitempty"`
	Scopes          []string  `json:"scopes"`
	TokenTTLSeconds int       `json:"token_ttl_seconds"`
	State           string    `json:"state"`
	CreatedBy       string    `json:"created_by,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	DisabledAt      time.Time `json:"disabled_at,omitempty"`
}

type ProducerClientSecret struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	ClientID   string    `json:"client_id"`
	Hash       string    `json:"-"`
	Prefix     string    `json:"prefix"`
	Last4      string    `json:"last4"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
}

type ProducerAccessToken struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	ClientID   string    `json:"client_id"`
	Hash       string    `json:"-"`
	Prefix     string    `json:"prefix"`
	Last4      string    `json:"last4"`
	Scopes     []string  `json:"scopes"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
}

type ProducerMTLSIdentity struct {
	ID                           string    `json:"id"`
	TenantID                     string    `json:"tenant_id"`
	Name                         string    `json:"name"`
	SourceID                     string    `json:"source_id,omitempty"`
	CertificateFingerprintSHA256 string    `json:"certificate_fingerprint_sha256"`
	CertSubject                  string    `json:"cert_subject"`
	DNSSANs                      []string  `json:"dns_sans,omitempty"`
	URISANs                      []string  `json:"uri_sans,omitempty"`
	EmailSANs                    []string  `json:"email_sans,omitempty"`
	NotBefore                    time.Time `json:"not_before"`
	NotAfter                     time.Time `json:"not_after"`
	State                        string    `json:"state"`
	CreatedBy                    string    `json:"created_by,omitempty"`
	CreatedAt                    time.Time `json:"created_at"`
	UpdatedAt                    time.Time `json:"updated_at"`
	DisabledAt                   time.Time `json:"disabled_at,omitempty"`
}

type IdentityProvider struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	Name                string    `json:"name"`
	ProviderType        string    `json:"provider_type"`
	IssuerURL           string    `json:"issuer_url"`
	AuthorizationURL    string    `json:"authorization_endpoint,omitempty"`
	TokenURL            string    `json:"token_endpoint,omitempty"`
	JWKSURL             string    `json:"jwks_uri,omitempty"`
	ClientID            string    `json:"client_id"`
	ClientSecret        []byte    `json:"-"`
	RedirectURI         string    `json:"redirect_uri,omitempty"`
	AllowedEmailDomains []string  `json:"allowed_email_domains,omitempty"`
	State               string    `json:"state"`
	CreatedBy           string    `json:"created_by,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	DisabledAt          time.Time `json:"disabled_at,omitempty"`
}

type ExternalIdentity struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	UserID             string    `json:"user_id"`
	IdentityProviderID string    `json:"identity_provider_id"`
	ExternalSubject    string    `json:"external_subject"`
	Email              string    `json:"email,omitempty"`
	EmailVerified      bool      `json:"email_verified"`
	DisplayName        string    `json:"display_name,omitempty"`
	State              string    `json:"state"`
	FirstSeenAt        time.Time `json:"first_seen_at"`
	LastSeenAt         time.Time `json:"last_seen_at"`
	DisabledAt         time.Time `json:"disabled_at,omitempty"`
}

type OIDCLoginState struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	IdentityProviderID string    `json:"identity_provider_id"`
	StateHash          string    `json:"-"`
	NonceHash          string    `json:"-"`
	PKCEVerifier       []byte    `json:"-"`
	RedirectAfter      string    `json:"redirect_after,omitempty"`
	ExpiresAt          time.Time `json:"expires_at"`
	ConsumedAt         time.Time `json:"consumed_at,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
}

type AuthSession struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	UserID             string    `json:"user_id"`
	ExternalIdentityID string    `json:"external_identity_id,omitempty"`
	SessionHash        string    `json:"-"`
	State              string    `json:"state"`
	UserAgentHash      string    `json:"-"`
	IPHash             string    `json:"-"`
	CreatedAt          time.Time `json:"created_at"`
	LastSeenAt         time.Time `json:"last_seen_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	RevokedAt          time.Time `json:"revoked_at,omitempty"`
}

type SCIMToken struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Name       string    `json:"name"`
	Prefix     string    `json:"prefix"`
	Last4      string    `json:"last4"`
	Hash       string    `json:"-"`
	State      string    `json:"state"`
	CreatedBy  string    `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
}

type SCIMGroup struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	ExternalID  string    `json:"external_id"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
	State       string    `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type RoleBinding struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	PrincipalType  string    `json:"principal_type"`
	PrincipalID    string    `json:"principal_id"`
	Role           string    `json:"role"`
	ResourceFamily string    `json:"resource_family"`
	ResourceID     string    `json:"resource_id"`
	Environment    string    `json:"environment"`
	State          string    `json:"state"`
	Reason         string    `json:"reason,omitempty"`
	CreatedBy      string    `json:"created_by,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type AccessPolicyRule struct {
	ID             string          `json:"id"`
	TenantID       string          `json:"tenant_id"`
	Name           string          `json:"name"`
	Action         string          `json:"action"`
	Effect         string          `json:"effect"`
	ResourceFamily string          `json:"resource_family"`
	Environment    string          `json:"environment"`
	Conditions     json.RawMessage `json:"conditions,omitempty"`
	State          string          `json:"state"`
	Reason         string          `json:"reason,omitempty"`
	CreatedBy      string          `json:"created_by,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

type AuthzDecisionLog struct {
	ID                   string    `json:"id"`
	TenantID             string    `json:"tenant_id"`
	ActorID              string    `json:"actor_id"`
	Action               string    `json:"action"`
	ResourceFamily       string    `json:"resource_family"`
	ResourceID           string    `json:"resource_id,omitempty"`
	Environment          string    `json:"environment,omitempty"`
	Allowed              bool      `json:"allowed"`
	MatchedRoleBindingID string    `json:"matched_role_binding_id,omitempty"`
	MatchedPolicyRuleID  string    `json:"matched_policy_rule_id,omitempty"`
	Reason               string    `json:"reason"`
	Sampled              bool      `json:"sampled"`
	OccurredAt           time.Time `json:"occurred_at"`
}

type Subscription struct {
	ID                      string    `json:"id"`
	TenantID                string    `json:"tenant_id"`
	EndpointID              string    `json:"endpoint_id"`
	EventTypes              []string  `json:"event_types"`
	PayloadFormat           string    `json:"payload_format"`
	TransformationID        string    `json:"transformation_id,omitempty"`
	TransformationVersionID string    `json:"transformation_version_id,omitempty"`
	State                   string    `json:"state"`
	Version                 int       `json:"version"`
	ActiveVersionID         string    `json:"active_version_id,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
}

type Route struct {
	ID                      string    `json:"id"`
	TenantID                string    `json:"tenant_id"`
	SourceID                string    `json:"source_id"`
	Name                    string    `json:"name"`
	Priority                int       `json:"priority"`
	EventTypes              []string  `json:"event_types"`
	EndpointID              string    `json:"endpoint_id"`
	State                   string    `json:"state"`
	Version                 int       `json:"version"`
	ActiveVersionID         string    `json:"active_version_id,omitempty"`
	RetryPolicyID           string    `json:"retry_policy_id,omitempty"`
	TransformationID        string    `json:"transformation_id,omitempty"`
	TransformationVersionID string    `json:"transformation_version_id,omitempty"`
	CreatedBy               string    `json:"-"`
	CreatedAt               time.Time `json:"created_at"`
}

type ConfigVersion struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Version      int       `json:"version"`
	ConfigHash   string    `json:"config_hash"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

type RouteVersion struct {
	ID                      string    `json:"id"`
	TenantID                string    `json:"tenant_id"`
	RouteID                 string    `json:"route_id"`
	Version                 int       `json:"version"`
	ConfigHash              string    `json:"config_hash"`
	SourceID                string    `json:"source_id"`
	Name                    string    `json:"name"`
	Priority                int       `json:"priority"`
	EventTypes              []string  `json:"event_types"`
	EndpointID              string    `json:"endpoint_id"`
	RetryPolicyID           string    `json:"retry_policy_id,omitempty"`
	TransformationID        string    `json:"transformation_id,omitempty"`
	TransformationVersionID string    `json:"transformation_version_id,omitempty"`
	State                   string    `json:"state"`
	CreatedBy               string    `json:"created_by"`
	CreatedAt               time.Time `json:"created_at"`
}

type SubscriptionVersion struct {
	ID                      string    `json:"id"`
	TenantID                string    `json:"tenant_id"`
	SubscriptionID          string    `json:"subscription_id"`
	Version                 int       `json:"version"`
	ConfigHash              string    `json:"config_hash"`
	EndpointID              string    `json:"endpoint_id"`
	EventTypes              []string  `json:"event_types"`
	PayloadFormat           string    `json:"payload_format"`
	TransformationID        string    `json:"transformation_id,omitempty"`
	TransformationVersionID string    `json:"transformation_version_id,omitempty"`
	State                   string    `json:"state"`
	CreatedBy               string    `json:"created_by"`
	CreatedAt               time.Time `json:"created_at"`
}

type RetryPolicy struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	Name                string    `json:"name"`
	Version             int       `json:"version"`
	State               string    `json:"state"`
	MaxAttempts         int       `json:"max_attempts"`
	MaxDurationSeconds  int       `json:"max_duration_seconds"`
	InitialDelaySeconds int       `json:"initial_delay_seconds"`
	MaxDelaySeconds     int       `json:"max_delay_seconds"`
	RateLimitPerMinute  int       `json:"rate_limit_per_minute,omitempty"`
	CreatedBy           string    `json:"created_by"`
	CreatedAt           time.Time `json:"created_at"`
}

type SourceSecretVersion struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	SourceID  string    `json:"source_id"`
	Version   int       `json:"version"`
	State     string    `json:"state"`
	ActiveAt  time.Time `json:"active_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

type EndpointSecretVersion struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	EndpointID string    `json:"endpoint_id"`
	Version    int       `json:"version"`
	Algorithm  string    `json:"algorithm"`
	State      string    `json:"state"`
	ActiveAt   time.Time `json:"active_at"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
}

type EventType struct {
	Name        string    `json:"name"`
	TenantID    string    `json:"tenant_id"`
	Description string    `json:"description"`
	State       string    `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
}

type EventSchema struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	EventType string    `json:"event_type"`
	Version   string    `json:"version"`
	Schema    string    `json:"schema"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
}

type Event struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	SourceID       string    `json:"source_id"`
	Provider       string    `json:"provider"`
	Type           string    `json:"type"`
	ProviderID     string    `json:"provider_event_id,omitempty"`
	RawPayloadID   string    `json:"raw_payload_id"`
	RawPayloadHash string    `json:"raw_payload_hash"`
	Verified       bool      `json:"signature_verified"`
	VerifyReason   string    `json:"verification_reason"`
	DedupeKey      string    `json:"deduplication_key"`
	DedupeStatus   string    `json:"dedupe_status"`
	ReceivedAt     time.Time `json:"received_at"`
	TraceID        string    `json:"trace_id"`
}

type ProviderAdapter struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id,omitempty"`
	Name          string    `json:"name"`
	Kind          string    `json:"kind"`
	Description   string    `json:"description,omitempty"`
	RiskLevel     string    `json:"risk_level"`
	State         string    `json:"state"`
	ProvenanceURL string    `json:"provenance_url,omitempty"`
	CreatedBy     string    `json:"created_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
	RetiredAt     time.Time `json:"retired_at,omitempty"`
}

type AdapterVersion struct {
	ID               string          `json:"id"`
	TenantID         string          `json:"tenant_id,omitempty"`
	AdapterID        string          `json:"adapter_id"`
	Name             string          `json:"name"`
	Version          string          `json:"version"`
	Kind             string          `json:"kind"`
	ConfigHash       string          `json:"config_hash"`
	Definition       json.RawMessage `json:"definition,omitempty"`
	DefinitionSHA256 string          `json:"definition_sha256,omitempty"`
	PackageSHA256    string          `json:"package_sha256,omitempty"`
	PackageSignature string          `json:"package_signature,omitempty"`
	SBOMSHA256       string          `json:"sbom_sha256,omitempty"`
	ProvenanceURL    string          `json:"provenance_url,omitempty"`
	RiskLevel        string          `json:"risk_level"`
	TestResults      json.RawMessage `json:"test_results,omitempty"`
	ReviewNotes      string          `json:"review_notes,omitempty"`
	State            string          `json:"state"`
	CreatedBy        string          `json:"created_by,omitempty"`
	ReviewedBy       string          `json:"reviewed_by,omitempty"`
	ActivatedBy      string          `json:"activated_by,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	ReviewedAt       time.Time       `json:"reviewed_at,omitempty"`
	ActivatedAt      time.Time       `json:"activated_at,omitempty"`
	DeprecatedAt     time.Time       `json:"deprecated_at,omitempty"`
	RetiredAt        time.Time       `json:"retired_at,omitempty"`
}

type AdapterTestVector struct {
	ID               string          `json:"id"`
	TenantID         string          `json:"tenant_id"`
	AdapterVersionID string          `json:"adapter_version_id"`
	Name             string          `json:"name"`
	Purpose          string          `json:"purpose,omitempty"`
	Request          json.RawMessage `json:"request"`
	Expected         json.RawMessage `json:"expected"`
	RequestSHA256    string          `json:"request_sha256"`
	ExpectedSHA256   string          `json:"expected_sha256"`
	State            string          `json:"state"`
	CreatedBy        string          `json:"created_by,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at,omitempty"`
}

type AdapterVersionReview struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	AdapterVersionID string    `json:"adapter_version_id"`
	Action           string    `json:"action"`
	FromState        string    `json:"from_state"`
	ToState          string    `json:"to_state"`
	ActorID          string    `json:"actor_id"`
	Reason           string    `json:"reason"`
	CreatedAt        time.Time `json:"created_at"`
}

type NormalizedEnvelope struct {
	ID               string          `json:"id"`
	TenantID         string          `json:"tenant_id"`
	EventID          string          `json:"event_id"`
	AdapterVersionID string          `json:"adapter_version_id,omitempty"`
	Provider         string          `json:"provider"`
	ProviderEventID  string          `json:"provider_event_id,omitempty"`
	Type             string          `json:"type"`
	Source           string          `json:"source"`
	Subject          string          `json:"subject,omitempty"`
	Envelope         json.RawMessage `json:"envelope"`
	Data             json.RawMessage `json:"data,omitempty"`
	Metadata         json.RawMessage `json:"metadata"`
	EnvelopeSHA256   string          `json:"envelope_sha256"`
	DataSHA256       string          `json:"data_sha256"`
	MetadataSHA256   string          `json:"metadata_sha256"`
	StorageStatus    string          `json:"storage_status"`
	StorageDeletedAt time.Time       `json:"storage_deleted_at,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
}

type Transformation struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	Name            string    `json:"name"`
	State           string    `json:"state"`
	ActiveVersionID string    `json:"active_version_id,omitempty"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type TransformationVersion struct {
	ID               string          `json:"id"`
	TenantID         string          `json:"tenant_id"`
	TransformationID string          `json:"transformation_id"`
	Version          int             `json:"version"`
	ConfigHash       string          `json:"config_hash"`
	Operations       json.RawMessage `json:"operations"`
	State            string          `json:"state"`
	CreatedBy        string          `json:"created_by"`
	CreatedAt        time.Time       `json:"created_at"`
}

type DeliveryPayload struct {
	ID                      string    `json:"id"`
	TenantID                string    `json:"tenant_id"`
	DeliveryID              string    `json:"delivery_id"`
	EventID                 string    `json:"event_id"`
	NormalizedEnvelopeID    string    `json:"normalized_envelope_id,omitempty"`
	TransformationVersionID string    `json:"transformation_version_id,omitempty"`
	ContentType             string    `json:"content_type"`
	SHA256                  string    `json:"sha256"`
	SizeBytes               int64     `json:"size_bytes"`
	Body                    []byte    `json:"-"`
	StorageStatus           string    `json:"storage_status"`
	StorageDeletedAt        time.Time `json:"storage_deleted_at,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
}

type RawPayload struct {
	ID               string
	TenantID         string
	EventID          string
	SHA256           string
	ContentType      string
	SizeBytes        int64
	Body             []byte
	StorageBackend   string
	ObjectBucket     string
	ObjectKey        string
	StorageStatus    string
	StorageDeletedAt time.Time
	CreatedAt        time.Time
}

type Receipt struct {
	ID           string
	TenantID     string
	SourceID     string
	EventID      string
	RawHeaders   []HeaderPair
	RemoteIP     string
	ReceivedAt   time.Time
	VerifyOK     bool
	VerifyReason string
}

type Delivery struct {
	ID                      string    `json:"id"`
	TenantID                string    `json:"tenant_id"`
	EventID                 string    `json:"event_id"`
	EndpointID              string    `json:"endpoint_id"`
	RouteID                 string    `json:"route_id,omitempty"`
	RouteVersionID          string    `json:"route_version_id,omitempty"`
	SubscriptionID          string    `json:"subscription_id,omitempty"`
	SubscriptionVersionID   string    `json:"subscription_version_id,omitempty"`
	RetryPolicyID           string    `json:"retry_policy_id,omitempty"`
	ReplayJobID             string    `json:"replay_job_id,omitempty"`
	AdapterVersionID        string    `json:"adapter_version_id,omitempty"`
	NormalizedEnvelopeID    string    `json:"normalized_envelope_id,omitempty"`
	TransformationVersionID string    `json:"transformation_version_id,omitempty"`
	DeliveryPayloadID       string    `json:"delivery_payload_id,omitempty"`
	DeliveryPayloadSHA256   string    `json:"delivery_payload_sha256,omitempty"`
	RetrySeed               string    `json:"retry_seed,omitempty"`
	State                   string    `json:"state"`
	AttemptCount            int       `json:"attempt_count"`
	NextAttemptAt           time.Time `json:"next_attempt_at,omitempty"`
}

type EndpointHealth struct {
	EndpointID    string    `json:"endpoint_id"`
	TenantID      string    `json:"tenant_id"`
	URL           string    `json:"url"`
	State         string    `json:"state"`
	CircuitState  string    `json:"circuit_state"`
	FailureCount  int       `json:"failure_count"`
	DisabledUntil time.Time `json:"disabled_until,omitempty"`
	LastAttemptAt time.Time `json:"last_attempt_at,omitempty"`
	LastStatus    int       `json:"last_status,omitempty"`
	LastFailure   string    `json:"last_failure,omitempty"`
	Successes24h  int64     `json:"successes_24h"`
	Failures24h   int64     `json:"failures_24h"`
}

type WorkerStatus struct {
	WorkerID   string    `json:"worker_id"`
	State      string    `json:"state"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type QueueStats struct {
	Name                string    `json:"name"`
	TenantID            string    `json:"tenant_id,omitempty"`
	Pending             int64     `json:"pending"`
	InProgress          int64     `json:"in_progress"`
	Completed           int64     `json:"completed"`
	Terminal            int64     `json:"terminal"`
	DueNow              int64     `json:"due_now"`
	OldestPendingAgeSec int64     `json:"oldest_pending_age_seconds"`
	NextAvailableAt     time.Time `json:"next_available_at,omitempty"`
}

type OpsStorageStatus struct {
	TenantID                    string           `json:"tenant_id,omitempty"`
	RawStorageMode              string           `json:"raw_storage_mode"`
	ObjectStorageConfigured     bool             `json:"object_storage_configured"`
	RawPayloadsByStatus         map[string]int64 `json:"raw_payloads_by_status"`
	RawPayloadsByBackend        map[string]int64 `json:"raw_payloads_by_backend"`
	RawPayloadStoredBytes       int64            `json:"raw_payload_stored_bytes"`
	NormalizedEnvelopesByStatus map[string]int64 `json:"normalized_envelopes_by_status,omitempty"`
	DeliveryPayloadsByStatus    map[string]int64 `json:"delivery_payloads_by_status,omitempty"`
	ProviderAPIEvidenceByStatus map[string]int64 `json:"provider_api_evidence_by_status,omitempty"`
	EvidenceExportsByState      map[string]int64 `json:"evidence_exports_by_state,omitempty"`
	EvidenceExportsByBackend    map[string]int64 `json:"evidence_exports_by_backend,omitempty"`
}

type OpsConfig struct {
	Environment             string `json:"environment"`
	UIEnabled               bool   `json:"ui_enabled"`
	RawStorageMode          string `json:"raw_storage_mode"`
	ObjectStorageConfigured bool   `json:"object_storage_configured"`
	SecretBoxMode           string `json:"secret_box_mode"`
	KeyCustodyConfigured    bool   `json:"key_custody_configured"`
	KeyCustodyKeyRef        string `json:"key_custody_key_ref,omitempty"`
	MaxIngressBodyBytes     int64  `json:"max_ingress_body_bytes"`
	MaxHeaderBytes          int64  `json:"max_header_bytes"`
	MaxHeaderPairs          int    `json:"max_header_pairs"`
	MaxHeaderValueBytes     int64  `json:"max_header_value_bytes"`
}

type DeliveryAttempt struct {
	ID                    string    `json:"id"`
	TenantID              string    `json:"tenant_id"`
	DeliveryID            string    `json:"delivery_id"`
	EventID               string    `json:"event_id"`
	EndpointID            string    `json:"endpoint_id"`
	RequestSHA256         string    `json:"request_sha256,omitempty"`
	ResponseSHA256        string    `json:"response_sha256,omitempty"`
	AttemptNo             int       `json:"attempt_no"`
	State                 string    `json:"state"`
	ResponseStatus        int       `json:"response_status,omitempty"`
	ResponseBodyTruncated string    `json:"response_body_truncated,omitempty"`
	FailureClass          string    `json:"failure_class,omitempty"`
	Retryable             bool      `json:"retryable"`
	RetryDelayMS          int64     `json:"retry_delay_ms,omitempty"`
	NextRetryAt           time.Time `json:"next_retry_at,omitempty"`
	StartedAt             time.Time `json:"started_at"`
	CompletedAt           time.Time `json:"completed_at,omitempty"`
}

type AuditEvent struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	ActorID    string    `json:"actor_id"`
	Action     string    `json:"action"`
	Resource   string    `json:"resource"`
	ResourceID string    `json:"resource_id"`
	Reason     string    `json:"reason,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

type AuditChainHead struct {
	TenantID           string    `json:"tenant_id"`
	Sequence           int64     `json:"sequence"`
	ChainHash          string    `json:"chain_hash"`
	LastAuditEventID   string    `json:"last_audit_event_id,omitempty"`
	UnchainedEvents    int64     `json:"unchained_events"`
	LastAnchoredAt     time.Time `json:"last_anchored_at,omitempty"`
	LastAnchorID       string    `json:"last_anchor_id,omitempty"`
	LastAnchorSequence int64     `json:"last_anchor_sequence,omitempty"`
	UpdatedAt          time.Time `json:"updated_at,omitempty"`
}

type AuditChainEntry struct {
	ID                      string    `json:"id"`
	TenantID                string    `json:"tenant_id"`
	Sequence                int64     `json:"sequence"`
	AuditEventID            string    `json:"audit_event_id"`
	EventHash               string    `json:"event_hash"`
	PreviousChainHash       string    `json:"previous_chain_hash"`
	ChainHash               string    `json:"chain_hash"`
	CanonicalizationVersion string    `json:"canonicalization_version"`
	Source                  string    `json:"source"`
	State                   string    `json:"state"`
	AuditEventDeletedAt     time.Time `json:"audit_event_deleted_at,omitempty"`
	TombstoneReason         string    `json:"tombstone_reason,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
}

type AuditChainVerification struct {
	TenantID        string              `json:"tenant_id"`
	Valid           bool                `json:"valid"`
	FromSequence    int64               `json:"from_sequence"`
	ToSequence      int64               `json:"to_sequence"`
	CheckedEntries  int                 `json:"checked_entries"`
	RetainedEntries int                 `json:"retained_entries"`
	StartChainHash  string              `json:"start_chain_hash,omitempty"`
	EndChainHash    string              `json:"end_chain_hash,omitempty"`
	Failures        []AuditChainFailure `json:"failures"`
	VerifiedAt      time.Time           `json:"verified_at"`
}

type AuditChainFailure struct {
	Sequence     int64  `json:"sequence"`
	AuditEventID string `json:"audit_event_id,omitempty"`
	Kind         string `json:"kind"`
	Detail       string `json:"detail,omitempty"`
}

type AuditChainAnchor struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	FromSequence   int64     `json:"from_sequence"`
	ToSequence     int64     `json:"to_sequence"`
	ChainHash      string    `json:"chain_hash"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	StorageBackend string    `json:"storage_backend"`
	ObjectBucket   string    `json:"object_bucket,omitempty"`
	ObjectKey      string    `json:"object_key,omitempty"`
	CreatedBy      string    `json:"created_by"`
	Reason         string    `json:"reason"`
	CreatedAt      time.Time `json:"created_at"`
}

type RetentionPolicy struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ResourceType  string    `json:"resource_type"`
	SourceID      string    `json:"source_id,omitempty"`
	RetentionDays int       `json:"retention_days"`
	State         string    `json:"state"`
	LegalHold     bool      `json:"legal_hold"`
	HoldReason    string    `json:"hold_reason,omitempty"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type RetentionRun struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	PolicyID       string    `json:"policy_id"`
	ResourceType   string    `json:"resource_type"`
	State          string    `json:"state"`
	MatchedItems   int       `json:"matched_items"`
	ProcessedItems int       `json:"processed_items"`
	Error          string    `json:"error,omitempty"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at,omitempty"`
}

type EvidenceExport struct {
	ID                   string    `json:"id"`
	TenantID             string    `json:"tenant_id"`
	State                string    `json:"state"`
	From                 time.Time `json:"from,omitempty"`
	To                   time.Time `json:"to,omitempty"`
	IncludeRawPayloads   bool      `json:"include_raw_payloads"`
	IncludeTimelines     bool      `json:"include_timelines"`
	IncludePayloadBodies bool      `json:"include_payload_bodies"`
	Format               string    `json:"format"`
	StorageBackend       string    `json:"storage_backend"`
	ObjectBucket         string    `json:"object_bucket,omitempty"`
	ObjectKey            string    `json:"object_key,omitempty"`
	SHA256               string    `json:"sha256"`
	ManifestSHA256       string    `json:"manifest_sha256"`
	SizeBytes            int64     `json:"size_bytes"`
	Error                string    `json:"error,omitempty"`
	CreatedBy            string    `json:"created_by"`
	CreatedAt            time.Time `json:"created_at"`
	CompletedAt          time.Time `json:"completed_at,omitempty"`
}

type OpsMetrics struct {
	EventsTotal                    int64            `json:"events_total"`
	OutboxPending                  int64            `json:"outbox_pending"`
	OldestOutboxAgeSec             int64            `json:"oldest_outbox_age_seconds"`
	DeadLetterOpen                 int64            `json:"dead_letter_open"`
	QuarantineOpen                 int64            `json:"quarantine_open"`
	EndpointCircuitOpen            int64            `json:"endpoint_circuit_open"`
	AuditChainUnchainedEvents      int64            `json:"audit_chain_unchained_events"`
	AuditChainVerificationFailures int64            `json:"audit_chain_verification_failures"`
	AuditChainLastAnchorAgeSec     int64            `json:"audit_chain_last_anchor_age_seconds"`
	DeliveriesByState              map[string]int64 `json:"deliveries_by_state"`
	ReplayJobsByState              map[string]int64 `json:"replay_jobs_by_state"`
	ReconciliationJobsByState      map[string]int64 `json:"reconciliation_jobs_by_state,omitempty"`
	ReconciliationItemsByOutcome   map[string]int64 `json:"reconciliation_items_by_outcome,omitempty"`
}

type MetricRollup struct {
	ID             string            `json:"id"`
	TenantID       string            `json:"tenant_id"`
	MetricName     string            `json:"metric_name"`
	BucketStart    time.Time         `json:"bucket_start"`
	BucketSeconds  int               `json:"bucket_seconds"`
	Dimensions     map[string]string `json:"dimensions,omitempty"`
	DimensionsHash string            `json:"dimensions_hash"`
	Value          float64           `json:"value"`
	Source         string            `json:"source"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at,omitempty"`
}

type AlertRule struct {
	ID            string            `json:"id"`
	TenantID      string            `json:"tenant_id"`
	Name          string            `json:"name"`
	RuleType      string            `json:"rule_type"`
	MetricName    string            `json:"metric_name"`
	Threshold     float64           `json:"threshold"`
	Comparator    string            `json:"comparator"`
	WindowSeconds int               `json:"window_seconds"`
	Dimensions    map[string]string `json:"dimensions,omitempty"`
	State         string            `json:"state"`
	ChannelIDs    []string          `json:"channel_ids,omitempty"`
	CreatedBy     string            `json:"created_by"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

type AlertFiring struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	RuleID          string    `json:"rule_id"`
	State           string    `json:"state"`
	ObservedValue   float64   `json:"observed_value"`
	Threshold       float64   `json:"threshold"`
	Reason          string    `json:"reason,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	LastEvaluatedAt time.Time `json:"last_evaluated_at"`
	AcknowledgedBy  string    `json:"acknowledged_by,omitempty"`
	AcknowledgedAt  time.Time `json:"acknowledged_at,omitempty"`
	ResolvedAt      time.Time `json:"resolved_at,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type NotificationChannel struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	ChannelType string    `json:"channel_type"`
	URL         string    `json:"url"`
	State       string    `json:"state"`
	SecretHint  string    `json:"secret_hint"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type NotificationDelivery struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ChannelID     string    `json:"channel_id"`
	FiringID      string    `json:"firing_id,omitempty"`
	Transition    string    `json:"transition"`
	State         string    `json:"state"`
	BodySHA256    string    `json:"body_sha256"`
	AttemptCount  int       `json:"attempt_count"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitempty"`
	LastAttemptAt time.Time `json:"last_attempt_at,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type NotificationDeliveryAttempt struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	DeliveryID        string    `json:"delivery_id"`
	StatusCode        int       `json:"status_code"`
	FailureClass      string    `json:"failure_class"`
	ResponseBody      string    `json:"response_body,omitempty"`
	ResponseTruncated bool      `json:"response_truncated"`
	Error             string    `json:"error,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

type SIEMSink struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Name           string    `json:"name"`
	SinkType       string    `json:"sink_type"`
	URL            string    `json:"url"`
	State          string    `json:"state"`
	SecretHint     string    `json:"secret_hint"`
	CursorSequence int64     `json:"cursor_sequence"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type SIEMDelivery struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	SinkID        string    `json:"sink_id"`
	FromSequence  int64     `json:"from_sequence"`
	ToSequence    int64     `json:"to_sequence"`
	State         string    `json:"state"`
	BodySHA256    string    `json:"body_sha256"`
	AttemptCount  int       `json:"attempt_count"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitempty"`
	LastAttemptAt time.Time `json:"last_attempt_at,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type SIEMDeliveryAttempt struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	DeliveryID        string    `json:"delivery_id"`
	StatusCode        int       `json:"status_code"`
	FailureClass      string    `json:"failure_class"`
	ResponseBody      string    `json:"response_body,omitempty"`
	ResponseTruncated bool      `json:"response_truncated"`
	Error             string    `json:"error,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

func MetricDimensionsHash(dimensions map[string]string) string {
	if dimensions == nil {
		dimensions = map[string]string{}
	}
	raw, _ := json.Marshal(dimensions)
	return HashSHA256(raw)
}

type ProviderConnection struct {
	ID             string            `json:"id"`
	TenantID       string            `json:"tenant_id"`
	Name           string            `json:"name"`
	Provider       string            `json:"provider"`
	State          string            `json:"state"`
	CredentialType string            `json:"credential_type"`
	CredentialHint string            `json:"credential_hint"`
	Config         map[string]string `json:"config,omitempty"`
	VerifiedAt     time.Time         `json:"verified_at,omitempty"`
	RevokedAt      time.Time         `json:"revoked_at,omitempty"`
	CreatedBy      string            `json:"created_by"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

type ReconciliationJob struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	ConnectionID       string    `json:"connection_id"`
	Provider           string    `json:"provider"`
	State              string    `json:"state"`
	DryRun             bool      `json:"dry_run"`
	CaptureMissing     bool      `json:"capture_missing"`
	RouteRecovered     bool      `json:"route_recovered"`
	RedeliverFailed    bool      `json:"redeliver_failed"`
	ScopeObjectID      string    `json:"scope_object_id,omitempty"`
	WindowStart        time.Time `json:"window_start,omitempty"`
	WindowEnd          time.Time `json:"window_end,omitempty"`
	Cursor             string    `json:"cursor,omitempty"`
	Reason             string    `json:"reason"`
	TotalItems         int       `json:"total_items"`
	MatchedItems       int       `json:"matched_items"`
	MissingItems       int       `json:"missing_items"`
	CapturedItems      int       `json:"captured_items"`
	RedeliveredItems   int       `json:"redelivered_items"`
	UnrecoverableItems int       `json:"unrecoverable_items"`
	FailedItems        int       `json:"failed_items"`
	Error              string    `json:"error,omitempty"`
	CreatedBy          string    `json:"created_by"`
	CreatedAt          time.Time `json:"created_at"`
	StartedAt          time.Time `json:"started_at,omitempty"`
	CompletedAt        time.Time `json:"completed_at,omitempty"`
	CanceledAt         time.Time `json:"canceled_at,omitempty"`
}

type ReconciliationItem struct {
	ID                    string          `json:"id"`
	TenantID              string          `json:"tenant_id"`
	JobID                 string          `json:"job_id"`
	Provider              string          `json:"provider"`
	ProviderObjectID      string          `json:"provider_object_id"`
	ProviderObjectType    string          `json:"provider_object_type"`
	Outcome               string          `json:"outcome"`
	LocalEventID          string          `json:"local_event_id,omitempty"`
	RecoveredEventID      string          `json:"recovered_event_id,omitempty"`
	ProviderAPIEvidenceID string          `json:"provider_api_evidence_id,omitempty"`
	RedeliveryRequested   bool            `json:"redelivery_requested"`
	Error                 string          `json:"error,omitempty"`
	Metadata              json.RawMessage `json:"metadata,omitempty"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
}

type ProviderAPIEvidence struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	JobID             string    `json:"job_id"`
	ItemID            string    `json:"item_id,omitempty"`
	ConnectionID      string    `json:"connection_id"`
	Provider          string    `json:"provider"`
	RequestMethod     string    `json:"request_method"`
	RequestURL        string    `json:"request_url"`
	ResponseStatus    int       `json:"response_status"`
	ResponseSHA256    string    `json:"response_sha256"`
	ResponseSizeBytes int64     `json:"response_size_bytes"`
	StorageStatus     string    `json:"storage_status"`
	StorageDeletedAt  time.Time `json:"storage_deleted_at,omitempty"`
	Error             string    `json:"error,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

func HashSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
