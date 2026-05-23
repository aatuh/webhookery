package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

const (
	StateActive   = "active"
	StateDisabled = "disabled"

	RawStoragePostgres = "postgres"
	RawStorageS3       = "s3"

	StorageStatusStored  = "stored"
	StorageStatusDeleted = "deleted"

	RetentionResourceRawPayload = "raw_payload"
	RetentionResourceAuditEvent = "audit_event"

	RetentionRunStateRunning   = "running"
	RetentionRunStateCompleted = "completed"
	RetentionRunStateFailed    = "failed"

	EvidenceExportStateReady  = "ready"
	EvidenceExportStateFailed = "failed"

	DedupeUnique              = "unique"
	DedupeDuplicateSuppressed = "duplicate_suppressed"
	DedupeCollision           = "collision"

	ConfigResourceSource      = "source"
	ConfigResourceEndpoint    = "endpoint"
	ConfigResourceRoute       = "route"
	ConfigResourceRetryPolicy = "retry_policy"
	ConfigResourceSchema      = "event_schema"

	SecretStateActive   = "active"
	SecretStatePrevious = "previous"
	SecretStateRevoked  = "revoked"
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
	VerificationSecret  []byte
	VerificationSecrets [][]byte
	CreatedAt           time.Time
}

type Endpoint struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	State         string    `json:"state"`
	RetryPolicyID string    `json:"retry_policy_id,omitempty"`
	CircuitState  string    `json:"circuit_state,omitempty"`
	FailureCount  int       `json:"failure_count,omitempty"`
	DisabledUntil time.Time `json:"disabled_until,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
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

type Subscription struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	EndpointID    string    `json:"endpoint_id"`
	EventTypes    []string  `json:"event_types"`
	PayloadFormat string    `json:"payload_format"`
	State         string    `json:"state"`
	CreatedAt     time.Time `json:"created_at"`
}

type Route struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	SourceID        string    `json:"source_id"`
	Name            string    `json:"name"`
	Priority        int       `json:"priority"`
	EventTypes      []string  `json:"event_types"`
	EndpointID      string    `json:"endpoint_id"`
	State           string    `json:"state"`
	Version         int       `json:"version"`
	ActiveVersionID string    `json:"active_version_id,omitempty"`
	RetryPolicyID   string    `json:"retry_policy_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
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
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	RouteID       string    `json:"route_id"`
	Version       int       `json:"version"`
	ConfigHash    string    `json:"config_hash"`
	SourceID      string    `json:"source_id"`
	Name          string    `json:"name"`
	Priority      int       `json:"priority"`
	EventTypes    []string  `json:"event_types"`
	EndpointID    string    `json:"endpoint_id"`
	RetryPolicyID string    `json:"retry_policy_id,omitempty"`
	State         string    `json:"state"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
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
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	EventID        string    `json:"event_id"`
	EndpointID     string    `json:"endpoint_id"`
	RouteID        string    `json:"route_id,omitempty"`
	RouteVersionID string    `json:"route_version_id,omitempty"`
	SubscriptionID string    `json:"subscription_id,omitempty"`
	RetryPolicyID  string    `json:"retry_policy_id,omitempty"`
	State          string    `json:"state"`
	AttemptCount   int       `json:"attempt_count"`
	NextAttemptAt  time.Time `json:"next_attempt_at,omitempty"`
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

type RetentionPolicy struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ResourceType  string    `json:"resource_type"`
	SourceID      string    `json:"source_id,omitempty"`
	RetentionDays int       `json:"retention_days"`
	State         string    `json:"state"`
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
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	State              string    `json:"state"`
	From               time.Time `json:"from,omitempty"`
	To                 time.Time `json:"to,omitempty"`
	IncludeRawPayloads bool      `json:"include_raw_payloads"`
	IncludeTimelines   bool      `json:"include_timelines"`
	Format             string    `json:"format"`
	StorageBackend     string    `json:"storage_backend"`
	ObjectBucket       string    `json:"object_bucket,omitempty"`
	ObjectKey          string    `json:"object_key,omitempty"`
	SHA256             string    `json:"sha256"`
	ManifestSHA256     string    `json:"manifest_sha256"`
	SizeBytes          int64     `json:"size_bytes"`
	Error              string    `json:"error,omitempty"`
	CreatedBy          string    `json:"created_by"`
	CreatedAt          time.Time `json:"created_at"`
	CompletedAt        time.Time `json:"completed_at,omitempty"`
}

type OpsMetrics struct {
	EventsTotal         int64            `json:"events_total"`
	OutboxPending       int64            `json:"outbox_pending"`
	OldestOutboxAgeSec  int64            `json:"oldest_outbox_age_seconds"`
	DeadLetterOpen      int64            `json:"dead_letter_open"`
	QuarantineOpen      int64            `json:"quarantine_open"`
	EndpointCircuitOpen int64            `json:"endpoint_circuit_open"`
	DeliveriesByState   map[string]int64 `json:"deliveries_by_state"`
	ReplayJobsByState   map[string]int64 `json:"replay_jobs_by_state"`
}

func HashSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
