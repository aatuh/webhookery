package app

import (
	"context"
	"errors"
	"testing"

	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/ssrf"
)

func TestControlServiceScopesEventReadsToActorTenant(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"events:read"}}

	_, err := svc.GetEvent(context.Background(), actor, "evt_123")
	if err != nil {
		t.Fatal(err)
	}
	if store.eventTenantID != "ten_a" {
		t.Fatalf("expected tenant-scoped event read, got %q", store.eventTenantID)
	}
}

func TestControlServiceRequiresRawPayloadScope(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"events:read"}}

	_, err := svc.GetRawPayload(context.Background(), actor, "evt_123")
	if err != ErrForbidden {
		t.Fatalf("expected forbidden raw payload access, got %v", err)
	}
}

func TestControlServiceForbidsRawInclusiveAuditExportWithoutRawScope(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"audit:read"}}

	_, err := svc.CreateAuditExport(context.Background(), actor, CreateAuditExportRequest{IncludeRawPayloads: true})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden raw-inclusive export, got %v", err)
	}
}

func TestControlServiceScopesAuditExportDownloadToActorTenant(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAuditor, Scopes: []string{"audit:read"}}

	_, err := svc.DownloadAuditExport(context.Background(), actor, "exp_123")
	if err != nil {
		t.Fatal(err)
	}
	if store.auditExportTenantID != "ten_a" {
		t.Fatalf("expected tenant-scoped audit export download, got %q", store.auditExportTenantID)
	}
}

func TestControlServiceForbidsRawInclusiveDownloadBeforeBundleRead(t *testing.T) {
	store := &fakeControlStore{auditExport: domain.EvidenceExport{ID: "exp_raw", TenantID: "ten_a", IncludeRawPayloads: true}}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"audit:read"}}

	_, err := svc.DownloadAuditExport(context.Background(), actor, "exp_raw")
	if err != ErrForbidden {
		t.Fatalf("expected forbidden raw-inclusive download, got %v", err)
	}
	if store.auditExportDownloaded {
		t.Fatal("raw-inclusive export bundle was read before authorization")
	}
}

func TestControlServiceHidesRawInclusiveAuditExportsWithoutRawScope(t *testing.T) {
	store := &fakeControlStore{
		auditExports: []domain.EvidenceExport{
			{ID: "exp_public", TenantID: "ten_a"},
			{ID: "exp_raw", TenantID: "ten_a", IncludeRawPayloads: true},
		},
	}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"audit:read"}}

	exports, err := svc.ListAuditExports(context.Background(), actor, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(exports) != 1 || exports[0].ID != "exp_public" {
		t.Fatalf("unexpected exports: %+v", exports)
	}
}

func TestControlServiceRetentionPolicyRequiresSecurityWrite(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAuditor, Scopes: []string{"security:read"}}

	_, err := svc.CreateRetentionPolicy(context.Background(), actor, CreateRetentionPolicyRequest{ResourceType: domain.RetentionResourceRawPayload, RetentionDays: 30})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden retention write, got %v", err)
	}
}

func TestControlServiceTestEndpointRequiresReason(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"endpoints:write"}}

	_, err := svc.TestEndpoint(context.Background(), actor, "end_123", TestEndpointRequest{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid input, got %v", err)
	}
}

func TestControlServiceValidatesPayloadAgainstStoredSchema(t *testing.T) {
	store := &fakeControlStore{
		eventSchema: domain.EventSchema{
			TenantID:  "ten_a",
			EventType: "invoice.paid",
			Version:   "2026-05-01",
			Schema:    `{"type":"object","required":["id","amount"],"properties":{"id":{"type":"string"},"amount":{"type":"integer"}}}`,
		},
	}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"schemas:read"}}

	res, err := svc.ValidateEventSchema(context.Background(), actor, "invoice.paid", "2026-05-01", ValidateSchemaRequest{Payload: `{"id":"evt_1","amount":42}`})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid || len(res.Errors) != 0 {
		t.Fatalf("expected valid payload, got %+v", res)
	}

	res, err = svc.ValidateEventSchema(context.Background(), actor, "invoice.paid", "2026-05-01", ValidateSchemaRequest{Payload: `{"id":"evt_1","amount":"42"}`})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || len(res.Errors) == 0 {
		t.Fatalf("expected validation errors, got %+v", res)
	}
	if store.schemaTenantID != "ten_a" {
		t.Fatalf("schema lookup was not tenant scoped: %q", store.schemaTenantID)
	}
}

func TestControlServiceChecksConservativeSchemaCompatibility(t *testing.T) {
	store := &fakeControlStore{
		eventSchema: domain.EventSchema{
			TenantID:  "ten_a",
			EventType: "invoice.paid",
			Version:   "v1",
			Schema:    `{"type":"object","required":["id"],"properties":{"id":{"type":"string"},"amount":{"type":"integer"}}}`,
		},
	}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"schemas:read"}}

	res, err := svc.CheckEventSchemaCompatibility(context.Background(), actor, "invoice.paid", "v1", CheckSchemaCompatibilityRequest{
		NewSchema: `{"type":"object","required":["id","currency"],"properties":{"id":{"type":"string"},"amount":{"type":"integer"},"currency":{"type":"string"}}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Compatible || len(res.Errors) == 0 {
		t.Fatalf("expected compatibility rejection, got %+v", res)
	}
}

func TestControlServiceReplayValidatesConfigModeAndRate(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"replay:write", "replay:read"}}

	_, err := svc.CreateReplay(context.Background(), actor, ReplayRequest{EventID: "evt_1", Reason: "repair", ConfigMode: "future"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid config mode, got %v", err)
	}
	_, err = svc.CreateReplay(context.Background(), actor, ReplayRequest{EventID: "evt_1", Reason: "repair", ConfigMode: ReplayConfigOriginal, RateLimitPerMinute: -1})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid rate limit, got %v", err)
	}
}

func TestControlServiceSecretRotationRequiresSecurityWrite(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAuditor, Scopes: []string{"security:read"}}

	_, err := svc.RotateSourceSecret(context.Background(), actor, "src_1", RotateSourceSecretRequest{NewSecret: "next", Reason: "rotate"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden source secret rotation, got %v", err)
	}
	_, err = svc.RotateEndpointSecret(context.Background(), actor, "end_1", RotateEndpointSecretRequest{Reason: "rotate"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden endpoint secret rotation, got %v", err)
	}
}

func TestControlServiceRetryPolicyValidation(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"routes:write"}}

	_, err := svc.CreateRetryPolicy(context.Background(), actor, CreateRetryPolicyRequest{Name: "fast", MaxAttempts: 0, InitialDelaySeconds: 1, MaxDelaySeconds: 10})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid max attempts, got %v", err)
	}
	_, err = svc.CreateRetryPolicy(context.Background(), actor, CreateRetryPolicyRequest{Name: "fast", MaxAttempts: 3, MaxDurationSeconds: 60, InitialDelaySeconds: 1, MaxDelaySeconds: 10})
	if err != nil {
		t.Fatalf("expected valid retry policy, got %v", err)
	}
	if store.retryPolicyTenantID != "ten_a" {
		t.Fatalf("retry policy was not tenant scoped: %q", store.retryPolicyTenantID)
	}
}

type fakeControlStore struct {
	eventTenantID         string
	auditExportTenantID   string
	auditExport           domain.EvidenceExport
	auditExportDownloaded bool
	auditExports          []domain.EvidenceExport
	apiKeyInput           APIKeyCreateInput
	eventSchema           domain.EventSchema
	schemaTenantID        string
	retryPolicyTenantID   string
}

func (f *fakeControlStore) CreateAPIKey(_ context.Context, input APIKeyCreateInput) (domain.APIKey, error) {
	f.apiKeyInput = input
	input.Key.ID = "key_1"
	return input.Key, nil
}
func (f *fakeControlStore) ListAPIKeys(context.Context, string, int) ([]domain.APIKey, error) {
	return nil, nil
}
func (f *fakeControlStore) RevokeAPIKey(context.Context, string, string, string, string) (domain.APIKey, error) {
	return domain.APIKey{}, nil
}
func (f *fakeControlStore) CreateSource(context.Context, domain.Source) (domain.Source, error) {
	return domain.Source{}, nil
}
func (f *fakeControlStore) ListSources(context.Context, string, int) ([]domain.Source, error) {
	return nil, nil
}
func (f *fakeControlStore) CreateEndpoint(context.Context, domain.Endpoint) (domain.Endpoint, error) {
	return domain.Endpoint{}, nil
}
func (f *fakeControlStore) TestEndpoint(context.Context, string, string, string, string) (domain.Delivery, error) {
	return domain.Delivery{}, nil
}
func (f *fakeControlStore) ListEndpoints(context.Context, string, int) ([]domain.Endpoint, error) {
	return nil, nil
}
func (f *fakeControlStore) CreateSubscription(context.Context, domain.Subscription) (domain.Subscription, error) {
	return domain.Subscription{}, nil
}
func (f *fakeControlStore) ListSubscriptions(context.Context, string, int) ([]domain.Subscription, error) {
	return nil, nil
}
func (f *fakeControlStore) CreateRoute(context.Context, domain.Route) (domain.Route, error) {
	return domain.Route{}, nil
}
func (f *fakeControlStore) ListRoutes(context.Context, string, int) ([]domain.Route, error) {
	return nil, nil
}
func (f *fakeControlStore) ListRouteVersions(context.Context, string, string, int) ([]domain.RouteVersion, error) {
	return nil, nil
}
func (f *fakeControlStore) ActivateRoute(context.Context, string, string, string, string) (domain.Route, error) {
	return domain.Route{}, nil
}
func (f *fakeControlStore) DryRunRoute(context.Context, string, string, string) (RouteDryRun, error) {
	return RouteDryRun{}, nil
}
func (f *fakeControlStore) CreateRetryPolicy(_ context.Context, tenantID, actorID string, req CreateRetryPolicyRequest) (domain.RetryPolicy, error) {
	f.retryPolicyTenantID = tenantID
	return domain.RetryPolicy{ID: "rtp_1", TenantID: tenantID, Name: req.Name, Version: 1, State: domain.StateActive, MaxAttempts: req.MaxAttempts, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) ListRetryPolicies(context.Context, string, int) ([]domain.RetryPolicy, error) {
	return nil, nil
}
func (f *fakeControlStore) CreateEventType(context.Context, domain.EventType) (domain.EventType, error) {
	return domain.EventType{}, nil
}
func (f *fakeControlStore) ListEventTypes(context.Context, string, int) ([]domain.EventType, error) {
	return nil, nil
}
func (f *fakeControlStore) CreateEventSchema(context.Context, domain.EventSchema) (domain.EventSchema, error) {
	return domain.EventSchema{}, nil
}
func (f *fakeControlStore) ListEventSchemas(context.Context, string, string, int) ([]domain.EventSchema, error) {
	return nil, nil
}
func (f *fakeControlStore) GetEventSchema(_ context.Context, tenantID, eventType, version string) (domain.EventSchema, error) {
	f.schemaTenantID = tenantID
	if f.eventSchema.ID == "" {
		f.eventSchema.ID = "sch_1"
	}
	f.eventSchema.TenantID = tenantID
	f.eventSchema.EventType = eventType
	f.eventSchema.Version = version
	return f.eventSchema, nil
}
func (f *fakeControlStore) RotateSourceSecret(context.Context, string, string, string, RotateSourceSecretRequest) (domain.SourceSecretVersion, error) {
	return domain.SourceSecretVersion{}, nil
}
func (f *fakeControlStore) RotateEndpointSecret(context.Context, string, string, string, RotateEndpointSecretRequest) (domain.EndpointSecretVersion, error) {
	return domain.EndpointSecretVersion{}, nil
}
func (f *fakeControlStore) ListEvents(context.Context, string, int) ([]domain.Event, error) {
	return nil, nil
}
func (f *fakeControlStore) GetEvent(_ context.Context, tenantID, eventID string) (domain.Event, error) {
	f.eventTenantID = tenantID
	return domain.Event{ID: eventID, TenantID: tenantID}, nil
}
func (f *fakeControlStore) GetRawPayload(context.Context, string, string, string) (domain.RawPayload, error) {
	return domain.RawPayload{}, nil
}
func (f *fakeControlStore) ListEventTimeline(context.Context, string, string, int) ([]map[string]any, error) {
	return nil, nil
}
func (f *fakeControlStore) ListDeliveries(context.Context, string, int) ([]domain.Delivery, error) {
	return nil, nil
}
func (f *fakeControlStore) ListDeliveryAttempts(context.Context, string, string, int) ([]domain.DeliveryAttempt, error) {
	return nil, nil
}
func (f *fakeControlStore) GetDeliveryAttempt(context.Context, string, string) (domain.DeliveryAttempt, error) {
	return domain.DeliveryAttempt{}, nil
}
func (f *fakeControlStore) RetryDelivery(context.Context, string, string, string, string) (domain.Delivery, error) {
	return domain.Delivery{}, nil
}
func (f *fakeControlStore) CancelDelivery(context.Context, string, string, string, string) (domain.Delivery, error) {
	return domain.Delivery{}, nil
}
func (f *fakeControlStore) ListEndpointHealth(context.Context, string, int) ([]domain.EndpointHealth, error) {
	return nil, nil
}
func (f *fakeControlStore) OpsMetrics(context.Context, string) (domain.OpsMetrics, error) {
	return domain.OpsMetrics{}, nil
}
func (f *fakeControlStore) ListAuditEvents(context.Context, string, int) ([]domain.AuditEvent, error) {
	return nil, nil
}
func (f *fakeControlStore) ListRetentionPolicies(context.Context, string, int) ([]domain.RetentionPolicy, error) {
	return nil, nil
}
func (f *fakeControlStore) CreateRetentionPolicy(_ context.Context, tenantID, actorID string, req CreateRetentionPolicyRequest) (domain.RetentionPolicy, error) {
	return domain.RetentionPolicy{ID: "ret_1", TenantID: tenantID, ResourceType: req.ResourceType, RetentionDays: req.RetentionDays, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) UpdateRetentionPolicy(_ context.Context, tenantID, policyID, actorID string, req UpdateRetentionPolicyRequest) (domain.RetentionPolicy, error) {
	days := 30
	if req.RetentionDays != nil {
		days = *req.RetentionDays
	}
	return domain.RetentionPolicy{ID: policyID, TenantID: tenantID, RetentionDays: days, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) CreateAuditExport(_ context.Context, tenantID, actorID string, req CreateAuditExportRequest) (domain.EvidenceExport, error) {
	return domain.EvidenceExport{ID: "exp_1", TenantID: tenantID, IncludeRawPayloads: req.IncludeRawPayloads, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) ListAuditExports(context.Context, string, int) ([]domain.EvidenceExport, error) {
	return f.auditExports, nil
}
func (f *fakeControlStore) GetAuditExport(_ context.Context, tenantID, exportID string) (domain.EvidenceExport, error) {
	if f.auditExport.ID != "" {
		f.auditExport.TenantID = tenantID
		return f.auditExport, nil
	}
	return domain.EvidenceExport{ID: exportID, TenantID: tenantID}, nil
}
func (f *fakeControlStore) DownloadAuditExport(_ context.Context, tenantID, exportID, actorID string) (EvidenceExportDownload, error) {
	f.auditExportTenantID = tenantID
	f.auditExportDownloaded = true
	return EvidenceExportDownload{Export: domain.EvidenceExport{ID: exportID, TenantID: tenantID}, Filename: exportID + ".tar.gz", ContentType: "application/gzip", Body: []byte("bundle")}, nil
}
func (f *fakeControlStore) ListDeadLetter(context.Context, string, int) ([]map[string]any, error) {
	return nil, nil
}
func (f *fakeControlStore) ReleaseDeadLetter(context.Context, string, string, string, string) (ReplayJob, error) {
	return ReplayJob{}, nil
}
func (f *fakeControlStore) BulkReleaseDeadLetter(context.Context, string, []string, string, string) ([]ReplayJob, error) {
	return nil, nil
}
func (f *fakeControlStore) ListQuarantine(context.Context, string, int) ([]map[string]any, error) {
	return nil, nil
}
func (f *fakeControlStore) ApproveQuarantine(context.Context, string, string, string, string, bool) (map[string]any, error) {
	return nil, nil
}
func (f *fakeControlStore) RejectQuarantine(context.Context, string, string, string, string) (map[string]any, error) {
	return nil, nil
}
func (f *fakeControlStore) DryRunReplay(context.Context, string, ReplayRequest) (ReplayDryRun, error) {
	return ReplayDryRun{}, nil
}
func (f *fakeControlStore) CreateReplay(context.Context, string, string, ReplayRequest) (ReplayJob, error) {
	return ReplayJob{}, nil
}
func (f *fakeControlStore) ListReplayJobs(context.Context, string, int) ([]ReplayJob, error) {
	return nil, nil
}
func (f *fakeControlStore) PauseReplayJob(context.Context, string, string, string, string) (ReplayJob, error) {
	return ReplayJob{}, nil
}
func (f *fakeControlStore) ResumeReplayJob(context.Context, string, string, string, string) (ReplayJob, error) {
	return ReplayJob{}, nil
}
func (f *fakeControlStore) CancelReplayJob(context.Context, string, string, string, string) (ReplayJob, error) {
	return ReplayJob{}, nil
}
