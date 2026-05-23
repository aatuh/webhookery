package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/ssrf"
)

func TestOpenAPIAndRoutes(t *testing.T) {
	server := NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"*"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi route status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestControlRoutesRequireBearer(t *testing.T) {
	server := NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"*"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestProductEventSourceIDExtractionPreservesRawBodyPath(t *testing.T) {
	sourceID := productSourceID([]byte(`{"source_id":"src_internal","id":"evt_1"}`))
	if sourceID != "src_internal" {
		t.Fatalf("unexpected source id %q", sourceID)
	}
	if productSourceID([]byte(`{"id":"evt_1"}`)) != "" {
		t.Fatal("missing source_id must not be accepted")
	}
}

func TestPrometheusMetricsDoesNotRequireBearer(t *testing.T) {
	server := NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"*"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected public metrics, got %d", rec.Code)
	}
}

func TestPrometheusAuditChainMetricsAreAggregate(t *testing.T) {
	body := formatPrometheus(domain.OpsMetrics{
		AuditChainUnchainedEvents:      2,
		AuditChainVerificationFailures: 1,
		AuditChainLastAnchorAgeSec:     3600,
		DeliveriesByState:              map[string]int64{},
		ReplayJobsByState:              map[string]int64{},
	})
	if !strings.Contains(body, "webhookery_audit_chain_unchained_events 2") {
		t.Fatalf("missing unchained audit metric:\n%s", body)
	}
	if !strings.Contains(body, "webhookery_audit_chain_verification_failures 1") {
		t.Fatalf("missing audit chain failure metric:\n%s", body)
	}
	if !strings.Contains(body, "webhookery_audit_chain_last_anchor_age_seconds 3600") {
		t.Fatalf("missing last anchor age metric:\n%s", body)
	}
	if strings.Contains(body, "tenant=") {
		t.Fatalf("public metrics must not expose tenant labels:\n%s", body)
	}
}

func TestSlackChallengeExtraction(t *testing.T) {
	challenge := slackChallenge([]byte(`{"type":"url_verification","challenge":"abc123"}`))
	if challenge != "abc123" {
		t.Fatalf("unexpected challenge %q", challenge)
	}
	if slackChallenge([]byte(`{"type":"event_callback","challenge":"abc123"}`)) != "" {
		t.Fatal("non-url-verification payload must not be treated as challenge")
	}
}

func TestAuditExportWithRawRequiresRawScope(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"audit:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/audit-events:export", bytes.NewBufferString(`{"include_raw_payloads":true}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for raw-inclusive export without events:raw, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRetentionPolicyWriteRequiresSecurityWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAuditor, Scopes: []string{"security:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/retention-policies", bytes.NewBufferString(`{"resource_type":"raw_payload","retention_days":30}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for retention write without security:write, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuditExportDownloadReturnsBundleWithHashHeader(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleOwner, Scopes: []string{"*"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/audit-exports/exp_1:download", nil)
	req.Header.Set("Authorization", "Bearer token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/gzip" {
		t.Fatalf("content type=%q want application/gzip", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("X-Webhookery-Export-SHA256") == "" {
		t.Fatal("expected export hash header")
	}
}

func TestNormalizedEventBodyRequiresRawScope(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"events:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/events/evt_1/normalized?include_data=true", nil)
	req.Header.Set("Authorization", "Bearer token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTransformationWriteRequiresRoutesWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"routes:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/transformations", bytes.NewBufferString(`{"name":"redact","operations":[{"op":"redact","path":"/data/email"}]}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestProviderConnectionCreateRequiresSourcesWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"sources:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/provider-connections", bytes.NewBufferString(`{"name":"Stripe","provider":"stripe","credential":"sk_test_secret"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReconciliationCreateRequiresReplayWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleSupport, Scopes: []string{"replay:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/reconciliation-jobs", bytes.NewBufferString(`{"connection_id":"pcn_1","reason":"recover"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuditChainAnchorRequiresSecurityWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAuditor, Scopes: []string{"audit:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/audit-chain:anchor", bytes.NewBufferString(`{"reason":"daily"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

type fakeIngestStore struct{}

func (fakeIngestStore) FindSource(context.Context, string, string) (domain.Source, error) {
	return domain.Source{}, app.ErrNotFound
}
func (fakeIngestStore) FindSourceByProviderPath(context.Context, string, string) (domain.Source, error) {
	return domain.Source{}, app.ErrNotFound
}
func (fakeIngestStore) CaptureInbound(context.Context, app.CaptureInboundInput) (app.CaptureInboundResult, error) {
	return app.CaptureInboundResult{}, nil
}

func NewNoopControl() *app.ControlService {
	return app.NewControlService(noopControlStore{}, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
}

func testServerWithActor(actor authz.Actor) *Server {
	return NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", actor),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
}

type noopControlStore struct{}

func (noopControlStore) CreateAPIKey(context.Context, app.APIKeyCreateInput) (domain.APIKey, error) {
	return domain.APIKey{}, nil
}
func (noopControlStore) ListAPIKeys(context.Context, string, int) ([]domain.APIKey, error) {
	return nil, nil
}
func (noopControlStore) RevokeAPIKey(context.Context, string, string, string, string) (domain.APIKey, error) {
	return domain.APIKey{}, nil
}
func (noopControlStore) CreateSource(context.Context, domain.Source) (domain.Source, error) {
	return domain.Source{}, nil
}
func (noopControlStore) ListSources(context.Context, string, int) ([]domain.Source, error) {
	return nil, nil
}
func (noopControlStore) RotateSourceSecret(context.Context, string, string, string, app.RotateSourceSecretRequest) (domain.SourceSecretVersion, error) {
	return domain.SourceSecretVersion{}, nil
}
func (noopControlStore) CreateEndpoint(context.Context, domain.Endpoint) (domain.Endpoint, error) {
	return domain.Endpoint{}, nil
}
func (noopControlStore) ListEndpoints(context.Context, string, int) ([]domain.Endpoint, error) {
	return nil, nil
}
func (noopControlStore) TestEndpoint(context.Context, string, string, string, string) (domain.Delivery, error) {
	return domain.Delivery{}, nil
}
func (noopControlStore) RotateEndpointSecret(context.Context, string, string, string, app.RotateEndpointSecretRequest) (domain.EndpointSecretVersion, error) {
	return domain.EndpointSecretVersion{}, nil
}
func (noopControlStore) CreateSubscription(context.Context, domain.Subscription) (domain.Subscription, error) {
	return domain.Subscription{}, nil
}
func (noopControlStore) ListSubscriptions(context.Context, string, int) ([]domain.Subscription, error) {
	return nil, nil
}
func (noopControlStore) CreateRoute(context.Context, domain.Route) (domain.Route, error) {
	return domain.Route{}, nil
}
func (noopControlStore) ListRoutes(context.Context, string, int) ([]domain.Route, error) {
	return nil, nil
}
func (noopControlStore) ListRouteVersions(context.Context, string, string, int) ([]domain.RouteVersion, error) {
	return nil, nil
}
func (noopControlStore) ActivateRoute(context.Context, string, string, string, string) (domain.Route, error) {
	return domain.Route{}, nil
}
func (noopControlStore) DryRunRoute(context.Context, string, string, string) (app.RouteDryRun, error) {
	return app.RouteDryRun{}, nil
}
func (noopControlStore) CreateRetryPolicy(context.Context, string, string, app.CreateRetryPolicyRequest) (domain.RetryPolicy, error) {
	return domain.RetryPolicy{}, nil
}
func (noopControlStore) ListRetryPolicies(context.Context, string, int) ([]domain.RetryPolicy, error) {
	return nil, nil
}
func (noopControlStore) CreateEventType(context.Context, domain.EventType) (domain.EventType, error) {
	return domain.EventType{}, nil
}
func (noopControlStore) ListEventTypes(context.Context, string, int) ([]domain.EventType, error) {
	return nil, nil
}
func (noopControlStore) CreateEventSchema(context.Context, domain.EventSchema) (domain.EventSchema, error) {
	return domain.EventSchema{}, nil
}
func (noopControlStore) ListEventSchemas(context.Context, string, string, int) ([]domain.EventSchema, error) {
	return nil, nil
}
func (noopControlStore) GetEventSchema(context.Context, string, string, string) (domain.EventSchema, error) {
	return domain.EventSchema{}, nil
}
func (noopControlStore) ListEvents(context.Context, string, int) ([]domain.Event, error) {
	return nil, nil
}
func (noopControlStore) GetEvent(context.Context, string, string) (domain.Event, error) {
	return domain.Event{}, nil
}
func (noopControlStore) GetRawPayload(context.Context, string, string, string) (domain.RawPayload, error) {
	return domain.RawPayload{}, nil
}
func (noopControlStore) GetNormalizedEvent(_ context.Context, tenantID, eventID, actorID string, includeData bool) (domain.NormalizedEnvelope, error) {
	return domain.NormalizedEnvelope{ID: "nenv_1", TenantID: tenantID, EventID: eventID, StorageStatus: domain.StorageStatusStored}, nil
}
func (noopControlStore) ListEventTimeline(context.Context, string, string, int) ([]map[string]any, error) {
	return nil, nil
}
func (noopControlStore) ListDeliveries(context.Context, string, int) ([]domain.Delivery, error) {
	return nil, nil
}
func (noopControlStore) ListDeliveryAttempts(context.Context, string, string, int) ([]domain.DeliveryAttempt, error) {
	return nil, nil
}
func (noopControlStore) GetDeliveryAttempt(context.Context, string, string) (domain.DeliveryAttempt, error) {
	return domain.DeliveryAttempt{}, nil
}
func (noopControlStore) RetryDelivery(context.Context, string, string, string, string) (domain.Delivery, error) {
	return domain.Delivery{}, nil
}
func (noopControlStore) CancelDelivery(context.Context, string, string, string, string) (domain.Delivery, error) {
	return domain.Delivery{}, nil
}
func (noopControlStore) ListEndpointHealth(context.Context, string, int) ([]domain.EndpointHealth, error) {
	return nil, nil
}
func (noopControlStore) OpsMetrics(context.Context, string) (domain.OpsMetrics, error) {
	return domain.OpsMetrics{DeliveriesByState: map[string]int64{}, ReplayJobsByState: map[string]int64{}}, nil
}
func (noopControlStore) ListAuditEvents(context.Context, string, int) ([]domain.AuditEvent, error) {
	return nil, nil
}
func (noopControlStore) GetAuditChainHead(context.Context, string) (domain.AuditChainHead, error) {
	return domain.AuditChainHead{}, nil
}
func (noopControlStore) VerifyAuditChain(context.Context, string, app.AuditChainVerifyRequest) (domain.AuditChainVerification, error) {
	return domain.AuditChainVerification{}, nil
}
func (noopControlStore) CreateAuditChainAnchor(context.Context, string, string, app.AuditChainAnchorRequest) (domain.AuditChainAnchor, error) {
	return domain.AuditChainAnchor{}, nil
}
func (noopControlStore) ListAuditChainAnchors(context.Context, string, int) ([]domain.AuditChainAnchor, error) {
	return nil, nil
}
func (noopControlStore) GetAuditChainAnchor(context.Context, string, string) (domain.AuditChainAnchor, error) {
	return domain.AuditChainAnchor{}, nil
}
func (noopControlStore) ListRetentionPolicies(context.Context, string, int) ([]domain.RetentionPolicy, error) {
	return nil, nil
}
func (noopControlStore) CreateRetentionPolicy(_ context.Context, tenantID, actorID string, req app.CreateRetentionPolicyRequest) (domain.RetentionPolicy, error) {
	return domain.RetentionPolicy{ID: "ret_1", TenantID: tenantID, ResourceType: req.ResourceType, RetentionDays: req.RetentionDays, State: domain.StateActive, CreatedBy: actorID}, nil
}
func (noopControlStore) UpdateRetentionPolicy(_ context.Context, tenantID, policyID, actorID string, req app.UpdateRetentionPolicyRequest) (domain.RetentionPolicy, error) {
	days := 30
	if req.RetentionDays != nil {
		days = *req.RetentionDays
	}
	return domain.RetentionPolicy{ID: policyID, TenantID: tenantID, ResourceType: domain.RetentionResourceRawPayload, RetentionDays: days, State: domain.StateActive, CreatedBy: actorID}, nil
}
func (noopControlStore) CreateProviderConnection(_ context.Context, tenantID, actorID string, req app.CreateProviderConnectionRequest) (domain.ProviderConnection, error) {
	return domain.ProviderConnection{ID: "pcn_1", TenantID: tenantID, Name: req.Name, Provider: req.Provider, State: domain.ProviderConnectionStateActive, CredentialType: req.CredentialType, CredentialHint: "***", Config: req.Config, CreatedBy: actorID}, nil
}
func (noopControlStore) ListProviderConnections(context.Context, string, int) ([]domain.ProviderConnection, error) {
	return nil, nil
}
func (noopControlStore) GetProviderConnection(_ context.Context, tenantID, connectionID string) (domain.ProviderConnection, error) {
	return domain.ProviderConnection{ID: connectionID, TenantID: tenantID, State: domain.ProviderConnectionStateActive}, nil
}
func (noopControlStore) VerifyProviderConnection(_ context.Context, tenantID, connectionID, actorID, reason string) (domain.ProviderConnection, error) {
	return domain.ProviderConnection{ID: connectionID, TenantID: tenantID, State: domain.ProviderConnectionStateActive, CreatedBy: actorID}, nil
}
func (noopControlStore) RevokeProviderConnection(_ context.Context, tenantID, connectionID, actorID, reason string) (domain.ProviderConnection, error) {
	return domain.ProviderConnection{ID: connectionID, TenantID: tenantID, State: domain.ProviderConnectionStateRevoked, CreatedBy: actorID}, nil
}
func (noopControlStore) DryRunReconciliation(_ context.Context, tenantID string, req app.ReconciliationJobRequest) (domain.ReconciliationJob, error) {
	return domain.ReconciliationJob{ID: "rec_dry", TenantID: tenantID, ConnectionID: req.ConnectionID, State: domain.ReconciliationJobStateCompleted, DryRun: true}, nil
}
func (noopControlStore) CreateReconciliationJob(_ context.Context, tenantID, actorID string, req app.ReconciliationJobRequest) (domain.ReconciliationJob, error) {
	return domain.ReconciliationJob{ID: "rec_1", TenantID: tenantID, ConnectionID: req.ConnectionID, State: domain.ReconciliationJobStateScheduled, CreatedBy: actorID}, nil
}
func (noopControlStore) ListReconciliationJobs(context.Context, string, int) ([]domain.ReconciliationJob, error) {
	return nil, nil
}
func (noopControlStore) GetReconciliationJob(_ context.Context, tenantID, jobID string) (domain.ReconciliationJob, error) {
	return domain.ReconciliationJob{ID: jobID, TenantID: tenantID}, nil
}
func (noopControlStore) ListReconciliationItems(context.Context, string, string, int) ([]domain.ReconciliationItem, error) {
	return nil, nil
}
func (noopControlStore) CancelReconciliationJob(_ context.Context, tenantID, jobID, actorID, reason string) (domain.ReconciliationJob, error) {
	return domain.ReconciliationJob{ID: jobID, TenantID: tenantID, State: domain.ReconciliationJobStateCanceled}, nil
}
func (noopControlStore) CreateAuditExport(_ context.Context, tenantID, actorID string, req app.CreateAuditExportRequest) (domain.EvidenceExport, error) {
	return domain.EvidenceExport{ID: "exp_1", TenantID: tenantID, State: domain.EvidenceExportStateReady, IncludeRawPayloads: req.IncludeRawPayloads, CreatedBy: actorID}, nil
}
func (noopControlStore) ListAuditExports(context.Context, string, int) ([]domain.EvidenceExport, error) {
	return nil, nil
}
func (noopControlStore) GetAuditExport(_ context.Context, tenantID, exportID string) (domain.EvidenceExport, error) {
	return domain.EvidenceExport{ID: exportID, TenantID: tenantID, State: domain.EvidenceExportStateReady}, nil
}
func (noopControlStore) DownloadAuditExport(_ context.Context, tenantID, exportID, actorID string) (app.EvidenceExportDownload, error) {
	return app.EvidenceExportDownload{Export: domain.EvidenceExport{ID: exportID, TenantID: tenantID, State: domain.EvidenceExportStateReady, SHA256: "sha256:test"}, Filename: exportID + ".tar.gz", ContentType: "application/gzip", Body: []byte("bundle")}, nil
}
func (noopControlStore) ListDeadLetter(context.Context, string, int) ([]map[string]any, error) {
	return nil, nil
}
func (noopControlStore) ReleaseDeadLetter(context.Context, string, string, string, string) (app.ReplayJob, error) {
	return app.ReplayJob{}, nil
}
func (noopControlStore) BulkReleaseDeadLetter(context.Context, string, []string, string, string) ([]app.ReplayJob, error) {
	return nil, nil
}
func (noopControlStore) ListQuarantine(context.Context, string, int) ([]map[string]any, error) {
	return nil, nil
}
func (noopControlStore) ApproveQuarantine(context.Context, string, string, string, string, bool) (map[string]any, error) {
	return nil, nil
}
func (noopControlStore) RejectQuarantine(context.Context, string, string, string, string) (map[string]any, error) {
	return nil, nil
}
func (noopControlStore) DryRunReplay(context.Context, string, app.ReplayRequest) (app.ReplayDryRun, error) {
	return app.ReplayDryRun{}, nil
}
func (noopControlStore) CreateReplay(context.Context, string, string, app.ReplayRequest) (app.ReplayJob, error) {
	return app.ReplayJob{}, nil
}
func (noopControlStore) ListReplayJobs(context.Context, string, int) ([]app.ReplayJob, error) {
	return nil, nil
}
func (noopControlStore) ApproveReplayJob(context.Context, string, string, string, string) (app.ReplayJob, error) {
	return app.ReplayJob{}, nil
}
func (noopControlStore) PauseReplayJob(context.Context, string, string, string, string) (app.ReplayJob, error) {
	return app.ReplayJob{}, nil
}
func (noopControlStore) ResumeReplayJob(context.Context, string, string, string, string) (app.ReplayJob, error) {
	return app.ReplayJob{}, nil
}
func (noopControlStore) CancelReplayJob(context.Context, string, string, string, string) (app.ReplayJob, error) {
	return app.ReplayJob{}, nil
}
func (noopControlStore) CreateTransformation(_ context.Context, tenantID, actorID string, req app.CreateTransformationRequest) (domain.Transformation, error) {
	return domain.Transformation{ID: "trn_1", TenantID: tenantID, Name: req.Name, CreatedBy: actorID}, nil
}
func (noopControlStore) ListTransformations(context.Context, string, int) ([]domain.Transformation, error) {
	return nil, nil
}
func (noopControlStore) GetTransformation(context.Context, string, string) (domain.Transformation, error) {
	return domain.Transformation{}, nil
}
func (noopControlStore) CreateTransformationVersion(context.Context, string, string, string, app.CreateTransformationVersionRequest) (domain.TransformationVersion, error) {
	return domain.TransformationVersion{}, nil
}
func (noopControlStore) ListTransformationVersions(context.Context, string, string, int) ([]domain.TransformationVersion, error) {
	return nil, nil
}
func (noopControlStore) ActivateTransformationVersion(context.Context, string, string, string, string, string) (domain.TransformationVersion, error) {
	return domain.TransformationVersion{}, nil
}
