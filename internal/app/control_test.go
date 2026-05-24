package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"strings"
	"testing"
	"time"

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

func TestControlServiceScopesEventSchemaReadsToActorTenant(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"schemas:read"}}

	_, err := svc.GetEventSchema(context.Background(), actor, "invoice.paid", "2026-05-01")
	if err != nil {
		t.Fatal(err)
	}
	if store.schemaTenantID != "ten_a" {
		t.Fatalf("expected tenant-scoped schema read, got %q", store.schemaTenantID)
	}
}

func TestControlServiceScopesEventTypeReadsToActorTenant(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"schemas:read"}}

	_, err := svc.GetEventType(context.Background(), actor, "invoice.paid")
	if err != nil {
		t.Fatal(err)
	}
	if store.schemaTenantID != "ten_a" {
		t.Fatalf("expected tenant-scoped event type read, got %q", store.schemaTenantID)
	}
}

func TestControlServiceSchemaLifecycleRequiresSchemasWrite(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"schemas:read"}}
	state := domain.StateDeprecated

	_, err := svc.UpdateEventType(context.Background(), actor, "invoice.paid", UpdateEventTypeRequest{Description: ptrString("Invoice paid"), Reason: "describe"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden event type update, got %v", err)
	}
	_, err = svc.UpdateEventSchema(context.Background(), actor, "invoice.paid", "2026-05-01", UpdateEventSchemaRequest{State: &state, Reason: "deprecate"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden schema update, got %v", err)
	}
}

func TestControlServiceSchemaLifecycleValidatesReasonAndState(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"schemas:write"}}
	state := "bad"

	_, err := svc.UpdateEventSchema(context.Background(), actor, "invoice.paid", "2026-05-01", UpdateEventSchemaRequest{State: &state, Reason: "bad state"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid state, got %v", err)
	}

	state = domain.StateDeprecated
	_, err = svc.UpdateEventSchema(context.Background(), actor, "invoice.paid", "2026-05-01", UpdateEventSchemaRequest{State: &state, Reason: "replace with 2026-06-01"})
	if err != nil {
		t.Fatal(err)
	}
	if store.schemaTenantID != "ten_a" || store.schemaReason != "replace with 2026-06-01" {
		t.Fatalf("expected tenant-scoped schema update with reason, tenant=%q reason=%q", store.schemaTenantID, store.schemaReason)
	}
}

func TestControlServiceScopesSourceReadsToActorTenant(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"sources:read"}}

	_, err := svc.GetSource(context.Background(), actor, "src_123")
	if err != nil {
		t.Fatal(err)
	}
	if store.sourceTenantID != "ten_a" || store.sourceID != "src_123" {
		t.Fatalf("expected tenant-scoped source read, got tenant=%q source=%q", store.sourceTenantID, store.sourceID)
	}
}

func TestControlServiceSourceMutationRequiresSourcesWrite(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"sources:read"}}
	name := "renamed"

	_, err := svc.UpdateSource(context.Background(), actor, "src_123", UpdateSourceRequest{Name: &name, Reason: "rename"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden source update, got %v", err)
	}
	_, err = svc.DeleteSource(context.Background(), actor, "src_123", StateChangeRequest{Reason: "retire"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden source delete, got %v", err)
	}
	if store.sourceTenantID != "" {
		t.Fatal("source store must not be called before authorization")
	}
}

func TestControlServiceUpdateSourceRequiresReasonAndValidState(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"sources:write"}}
	state := "deleted"

	_, err := svc.UpdateSource(context.Background(), actor, "src_123", UpdateSourceRequest{State: &state, Reason: "retire"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid source state, got %v", err)
	}
	state = domain.StateDisabled
	_, err = svc.UpdateSource(context.Background(), actor, "src_123", UpdateSourceRequest{State: &state})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected missing reason error, got %v", err)
	}
}

func TestControlServiceDeleteSourceDisablesWithReason(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"sources:write"}}

	_, err := svc.DeleteSource(context.Background(), actor, "src_123", StateChangeRequest{Reason: "retire old webhook"})
	if err != nil {
		t.Fatal(err)
	}
	if store.sourceTenantID != "ten_a" || store.sourceID != "src_123" || store.sourceReason != "retire old webhook" {
		t.Fatalf("expected tenant-scoped source delete, tenant=%q source=%q reason=%q", store.sourceTenantID, store.sourceID, store.sourceReason)
	}
}

func TestControlServiceScopesEndpointReadsToActorTenant(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"endpoints:read"}}

	_, err := svc.GetEndpoint(context.Background(), actor, "end_123")
	if err != nil {
		t.Fatal(err)
	}
	if store.endpointTenantID != "ten_a" || store.endpointID != "end_123" {
		t.Fatalf("expected tenant-scoped endpoint read, got tenant=%q endpoint=%q", store.endpointTenantID, store.endpointID)
	}
}

func TestControlServiceEndpointMutationRequiresEndpointsWrite(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"endpoints:read"}}
	name := "receiver"

	_, _, err := svc.UpdateEndpoint(context.Background(), actor, "end_123", UpdateEndpointRequest{Name: &name, Reason: "rename"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden endpoint update, got %v", err)
	}
	_, err = svc.DeleteEndpoint(context.Background(), actor, "end_123", StateChangeRequest{Reason: "retire"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden endpoint delete, got %v", err)
	}
	if store.endpointTenantID != "" {
		t.Fatal("endpoint store must not be called before authorization")
	}
}

func TestControlServiceUpdateEndpointValidatesURL(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{"receiver.example": []netip.Addr{netip.MustParseAddr("93.184.216.34")}}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"endpoints:write"}}
	rawURL := "https://receiver.example/webhook"

	_, ssrfResult, err := svc.UpdateEndpoint(context.Background(), actor, "end_123", UpdateEndpointRequest{URL: &rawURL, Reason: "move receiver"})
	if err != nil {
		t.Fatal(err)
	}
	if !ssrfResult.Allowed {
		t.Fatalf("expected URL validation result to allow update, got %+v", ssrfResult)
	}
	if store.endpoint.URL != rawURL || store.endpointTenantID != "ten_a" {
		t.Fatalf("expected endpoint update to reach store, endpoint=%+v tenant=%q", store.endpoint, store.endpointTenantID)
	}
}

func TestControlServiceDeleteEndpointDisablesWithReason(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"endpoints:write"}}

	_, err := svc.DeleteEndpoint(context.Background(), actor, "end_123", StateChangeRequest{Reason: "retire old receiver"})
	if err != nil {
		t.Fatal(err)
	}
	if store.endpointTenantID != "ten_a" || store.endpointID != "end_123" || store.endpointReason != "retire old receiver" {
		t.Fatalf("expected tenant-scoped endpoint delete, tenant=%q endpoint=%q reason=%q", store.endpointTenantID, store.endpointID, store.endpointReason)
	}
}

func TestControlServiceScopesSubscriptionReadsToActorTenant(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"subscriptions:read"}}

	_, err := svc.GetSubscription(context.Background(), actor, "sub_123")
	if err != nil {
		t.Fatal(err)
	}
	if store.subscriptionTenantID != "ten_a" || store.subscriptionID != "sub_123" {
		t.Fatalf("expected tenant-scoped subscription read, got tenant=%q subscription=%q", store.subscriptionTenantID, store.subscriptionID)
	}
}

func TestControlServiceSubscriptionMutationRequiresSubscriptionsWrite(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"subscriptions:read"}}
	state := domain.StateDisabled

	_, err := svc.UpdateSubscription(context.Background(), actor, "sub_123", UpdateSubscriptionRequest{State: &state, Reason: "pause fanout"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden subscription update, got %v", err)
	}
	_, err = svc.DeleteSubscription(context.Background(), actor, "sub_123", StateChangeRequest{Reason: "retire fanout"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden subscription delete, got %v", err)
	}
	if store.subscriptionTenantID != "" {
		t.Fatal("subscription store must not be called before authorization")
	}
}

func TestControlServiceUpdateSubscriptionValidatesFields(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"subscriptions:write"}}

	_, err := svc.UpdateSubscription(context.Background(), actor, "sub_123", UpdateSubscriptionRequest{Reason: "noop"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected missing field validation, got %v", err)
	}

	eventTypes := []string{"invoice.paid", "invoice.updated"}
	_, err = svc.UpdateSubscription(context.Background(), actor, "sub_123", UpdateSubscriptionRequest{EventTypes: eventTypes, Reason: "narrow fanout"})
	if err != nil {
		t.Fatal(err)
	}
	if store.subscriptionTenantID != "ten_a" || len(store.subscription.EventTypes) != 2 {
		t.Fatalf("expected subscription update to reach tenant store, tenant=%q subscription=%+v", store.subscriptionTenantID, store.subscription)
	}

	state := "paused"
	_, err = svc.UpdateSubscription(context.Background(), actor, "sub_123", UpdateSubscriptionRequest{State: &state, Reason: "bad state"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected state validation, got %v", err)
	}
}

func TestControlServiceDeleteSubscriptionDisablesWithReason(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"subscriptions:write"}}

	_, err := svc.DeleteSubscription(context.Background(), actor, "sub_123", StateChangeRequest{Reason: "retire fanout"})
	if err != nil {
		t.Fatal(err)
	}
	if store.subscriptionTenantID != "ten_a" || store.subscriptionID != "sub_123" || store.subscriptionReason != "retire fanout" {
		t.Fatalf("expected tenant-scoped subscription delete, tenant=%q subscription=%q reason=%q", store.subscriptionTenantID, store.subscriptionID, store.subscriptionReason)
	}
}

func TestControlServiceScopesRouteReadsToActorTenant(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"routes:read"}}

	_, err := svc.GetRoute(context.Background(), actor, "rte_123")
	if err != nil {
		t.Fatal(err)
	}
	if store.routeTenantID != "ten_a" || store.routeID != "rte_123" {
		t.Fatalf("expected tenant-scoped route read, got tenant=%q route=%q", store.routeTenantID, store.routeID)
	}
}

func TestControlServiceRouteMutationRequiresRoutesWrite(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"routes:read"}}
	state := "inactive"

	_, err := svc.UpdateRoute(context.Background(), actor, "rte_123", UpdateRouteRequest{State: &state, Reason: "pause route"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden route update, got %v", err)
	}
	_, err = svc.DeleteRoute(context.Background(), actor, "rte_123", StateChangeRequest{Reason: "retire route"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden route delete, got %v", err)
	}
	if store.routeTenantID != "" {
		t.Fatal("route store must not be called before authorization")
	}
}

func TestControlServiceUpdateRouteValidatesFields(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"routes:write"}}

	_, err := svc.UpdateRoute(context.Background(), actor, "rte_123", UpdateRouteRequest{Reason: "noop"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected missing field validation, got %v", err)
	}

	priority := 25
	eventTypes := []string{"invoice.paid", "invoice.updated"}
	_, err = svc.UpdateRoute(context.Background(), actor, "rte_123", UpdateRouteRequest{Priority: &priority, EventTypes: eventTypes, Reason: "reprioritize"})
	if err != nil {
		t.Fatal(err)
	}
	if store.routeTenantID != "ten_a" || store.route.Priority != 25 || len(store.route.EventTypes) != 2 {
		t.Fatalf("expected route update to reach tenant store, tenant=%q route=%+v", store.routeTenantID, store.route)
	}

	state := "paused"
	_, err = svc.UpdateRoute(context.Background(), actor, "rte_123", UpdateRouteRequest{State: &state, Reason: "bad state"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected state validation, got %v", err)
	}
}

func TestControlServiceDeleteRouteInactivatesWithReason(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"routes:write"}}

	_, err := svc.DeleteRoute(context.Background(), actor, "rte_123", StateChangeRequest{Reason: "retire route"})
	if err != nil {
		t.Fatal(err)
	}
	if store.routeTenantID != "ten_a" || store.routeID != "rte_123" || store.routeReason != "retire route" {
		t.Fatalf("expected tenant-scoped route delete, tenant=%q route=%q reason=%q", store.routeTenantID, store.routeID, store.routeReason)
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

func TestControlServiceNormalizedEventDataRequiresRawScope(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"events:read"}}

	_, err := svc.GetNormalizedEvent(context.Background(), actor, "evt_123", true)
	if err != ErrForbidden {
		t.Fatalf("expected forbidden normalized data access, got %v", err)
	}
	if store.normalizedTenantID != "" {
		t.Fatal("normalized body lookup should not happen before authorization")
	}
}

func TestControlServiceScopesNormalizedMetadataRead(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"events:read"}}

	_, err := svc.GetNormalizedEvent(context.Background(), actor, "evt_123", false)
	if err != nil {
		t.Fatal(err)
	}
	if store.normalizedTenantID != "ten_a" || !store.normalizedMetadataOnly {
		t.Fatalf("expected tenant-scoped metadata-only read, got tenant=%q metadataOnly=%v", store.normalizedTenantID, store.normalizedMetadataOnly)
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

func TestControlServiceForbidsPayloadInclusiveAuditExportWithoutRawScope(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"audit:read"}}

	_, err := svc.CreateAuditExport(context.Background(), actor, CreateAuditExportRequest{IncludePayloadBodies: true})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden payload-inclusive export, got %v", err)
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

func TestControlServiceForbidsPayloadInclusiveDownloadBeforeBundleRead(t *testing.T) {
	store := &fakeControlStore{auditExport: domain.EvidenceExport{ID: "exp_payload", TenantID: "ten_a", IncludePayloadBodies: true}}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"audit:read"}}

	_, err := svc.DownloadAuditExport(context.Background(), actor, "exp_payload")
	if err != ErrForbidden {
		t.Fatalf("expected forbidden payload-inclusive download, got %v", err)
	}
	if store.auditExportDownloaded {
		t.Fatal("payload-inclusive export bundle was read before authorization")
	}
}

func TestControlServiceHidesRawInclusiveAuditExportsWithoutRawScope(t *testing.T) {
	store := &fakeControlStore{
		auditExports: []domain.EvidenceExport{
			{ID: "exp_public", TenantID: "ten_a"},
			{ID: "exp_raw", TenantID: "ten_a", IncludeRawPayloads: true},
			{ID: "exp_payload", TenantID: "ten_a", IncludePayloadBodies: true},
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

func TestControlServiceRetentionLegalHoldRequiresReason(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleOwner, Scopes: []string{"security:write"}}

	_, err := svc.CreateRetentionPolicy(context.Background(), actor, CreateRetentionPolicyRequest{ResourceType: domain.RetentionResourceRawPayload, RetentionDays: 30, LegalHold: true})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid input for legal hold without reason, got %v", err)
	}
	hold := true
	_, err = svc.UpdateRetentionPolicy(context.Background(), actor, "ret_1", UpdateRetentionPolicyRequest{LegalHold: &hold})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid input for legal hold update without reason, got %v", err)
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

func TestControlServiceEndpointMTLSValidation(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{
		"receiver.example": {netip.MustParseAddr("93.184.216.34")},
	}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"endpoints:write"}}

	_, _, err := svc.CreateEndpoint(context.Background(), actor, CreateEndpointRequest{
		Name:              "receiver",
		URL:               "https://receiver.example/webhook",
		MTLSClientCertPEM: "not a cert",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected client key requirement, got %v", err)
	}

	certPEM, keyPEM := testClientCertificatePEM(t, "Webhookery Test Client")
	endpoint, _, err := svc.CreateEndpoint(context.Background(), actor, CreateEndpointRequest{
		Name:              "receiver",
		URL:               "https://receiver.example/webhook",
		MTLSClientCertPEM: certPEM,
		MTLSClientKeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("expected valid mTLS endpoint config, got %v", err)
	}
	if !store.endpoint.MTLSEnabled || len(store.endpoint.MTLSClientKeyPEM) == 0 || !endpoint.MTLSEnabled {
		t.Fatalf("expected mTLS endpoint material to use the store path, stored=%+v returned=%+v", store.endpoint, endpoint)
	}
	if !strings.Contains(endpoint.MTLSCertSubject, "Webhookery Test Client") {
		t.Fatalf("expected certificate subject metadata, got %q", endpoint.MTLSCertSubject)
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

func TestControlServiceReplayApprovalValidationAndTenantScope(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"replay:write", "replay:read"}}

	job, err := svc.CreateReplay(context.Background(), actor, ReplayRequest{EventID: "evt_1", Reason: "repair", RequireApproval: true})
	if err != nil {
		t.Fatalf("expected replay creation to succeed, got %v", err)
	}
	if !store.replayReq.RequireApproval || !job.ApprovalRequired {
		t.Fatalf("expected approval requirement to propagate, req=%+v job=%+v", store.replayReq, job)
	}

	_, err = svc.ApproveReplayJob(context.Background(), actor, "rpl_1", StateChangeRequest{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected approval reason validation, got %v", err)
	}

	readOnly := authz.Actor{ID: "usr_2", TenantID: "ten_a", Role: authz.RoleSupport, Scopes: []string{"replay:read"}}
	_, err = svc.ApproveReplayJob(context.Background(), readOnly, "rpl_1", StateChangeRequest{Reason: "approved"})
	if err != ErrForbidden {
		t.Fatalf("expected replay write permission requirement, got %v", err)
	}

	_, err = svc.ApproveReplayJob(context.Background(), actor, "rpl_1", StateChangeRequest{Reason: "approved"})
	if err != nil {
		t.Fatalf("expected approval to succeed, got %v", err)
	}
	if store.approveReplayTenantID != "ten_a" || store.approveReplayActorID != "usr_1" || store.approveReplayReason != "approved" {
		t.Fatalf("approval was not tenant-scoped with reason: tenant=%q actor=%q reason=%q", store.approveReplayTenantID, store.approveReplayActorID, store.approveReplayReason)
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

func TestControlServiceScopesRetryPolicyReadsToActorTenant(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"routes:read"}}

	_, err := svc.GetRetryPolicy(context.Background(), actor, "rtp_123")
	if err != nil {
		t.Fatal(err)
	}
	if store.retryPolicyTenantID != "ten_a" || store.retryPolicyID != "rtp_123" {
		t.Fatalf("expected tenant-scoped retry policy read, got tenant=%q policy=%q", store.retryPolicyTenantID, store.retryPolicyID)
	}
}

func TestControlServiceRetryPolicyMutationRequiresRoutesWrite(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"routes:read"}}
	maxAttempts := 6

	_, err := svc.UpdateRetryPolicy(context.Background(), actor, "rtp_123", UpdateRetryPolicyRequest{MaxAttempts: &maxAttempts, Reason: "tune retry"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden retry policy update, got %v", err)
	}
	_, err = svc.DeleteRetryPolicy(context.Background(), actor, "rtp_123", StateChangeRequest{Reason: "retire policy"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden retry policy delete, got %v", err)
	}
	if store.retryPolicyID != "" {
		t.Fatal("retry policy store must not be called before authorization")
	}
}

func TestControlServiceUpdateRetryPolicyValidatesFields(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"routes:write"}}

	_, err := svc.UpdateRetryPolicy(context.Background(), actor, "rtp_123", UpdateRetryPolicyRequest{Reason: "noop"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected missing field validation, got %v", err)
	}

	maxAttempts := 6
	_, err = svc.UpdateRetryPolicy(context.Background(), actor, "rtp_123", UpdateRetryPolicyRequest{MaxAttempts: &maxAttempts, Reason: "tune retry"})
	if err != nil {
		t.Fatal(err)
	}
	if store.retryPolicyTenantID != "ten_a" || store.retryPolicyID != "rtp_123" || store.retryPolicyReq.MaxAttempts == nil || *store.retryPolicyReq.MaxAttempts != 6 {
		t.Fatalf("expected retry policy update to reach tenant store, tenant=%q policy=%q req=%+v", store.retryPolicyTenantID, store.retryPolicyID, store.retryPolicyReq)
	}
}

func TestControlServiceDeleteRetryPolicyRequiresReason(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAdmin, Scopes: []string{"routes:write"}}

	_, err := svc.DeleteRetryPolicy(context.Background(), actor, "rtp_123", StateChangeRequest{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected missing reason validation, got %v", err)
	}
}

func TestControlServiceTransformationRequiresRoutesWrite(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"routes:read"}}

	_, err := svc.CreateTransformation(context.Background(), actor, CreateTransformationRequest{Name: "redact", Operations: json.RawMessage(`[{"op":"redact","path":"/data/email"}]`)})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden transformation write, got %v", err)
	}
}

func TestControlServiceValidatesTransformationOperations(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"routes:write"}}

	_, err := svc.CreateTransformation(context.Background(), actor, CreateTransformationRequest{Name: "bad", Operations: json.RawMessage(`[{"op":"drop","path":"/raw_payload_hash"}]`)})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid protected path, got %v", err)
	}
	_, err = svc.CreateTransformation(context.Background(), actor, CreateTransformationRequest{Name: "redact", Operations: json.RawMessage(`[{"op":"redact","path":"/data/email"}]`)})
	if err != nil {
		t.Fatalf("expected valid transformation, got %v", err)
	}
	if store.transformationTenantID != "ten_a" {
		t.Fatalf("transformation create was not tenant scoped: %q", store.transformationTenantID)
	}
}

func TestControlServiceProviderConnectionsScopeAndRedactCredentials(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"sources:write", "sources:read"}}

	conn, err := svc.CreateProviderConnection(context.Background(), actor, CreateProviderConnectionRequest{
		Name:       "Stripe prod",
		Provider:   "stripe",
		Credential: "sk_test_secret",
		Config:     map[string]string{" source_id ": " src_1 "},
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.providerConnectionTenantID != "ten_a" {
		t.Fatalf("connection create was not tenant-scoped: %q", store.providerConnectionTenantID)
	}
	if store.providerConnectionReq.Credential != "sk_test_secret" {
		t.Fatal("credential did not reach persistence boundary for encryption")
	}
	if conn.CredentialHint == "" || conn.CredentialHint == "sk_test_secret" {
		t.Fatalf("credential metadata was not redacted: %+v", conn)
	}
}

func TestControlServiceProviderConnectionMutationRequiresSourcesWrite(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"sources:read"}}

	_, err := svc.CreateProviderConnection(context.Background(), actor, CreateProviderConnectionRequest{Name: "GitHub", Provider: "github", Credential: "token"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden create, got %v", err)
	}
	_, err = svc.RevokeProviderConnection(context.Background(), actor, "pcn_1", ProviderConnectionStateRequest{Reason: "offboard"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden revoke, got %v", err)
	}
}

func TestControlServiceReconciliationRequiresReasonAndScopesTenant(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"replay:write", "replay:read"}}

	_, err := svc.CreateReconciliationJob(context.Background(), actor, ReconciliationJobRequest{ConnectionID: "pcn_1", CaptureMissing: true})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected missing reason validation, got %v", err)
	}
	_, err = svc.CreateReconciliationJob(context.Background(), actor, ReconciliationJobRequest{ConnectionID: "pcn_1", RouteRecovered: true, Reason: "recover"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected route_recovered validation, got %v", err)
	}
	job, err := svc.CreateReconciliationJob(context.Background(), actor, ReconciliationJobRequest{ConnectionID: "pcn_1", CaptureMissing: true, RouteRecovered: true, Reason: "recover"})
	if err != nil {
		t.Fatal(err)
	}
	if store.reconciliationTenantID != "ten_a" || job.TenantID != "ten_a" {
		t.Fatalf("reconciliation job was not tenant scoped: store=%q job=%q", store.reconciliationTenantID, job.TenantID)
	}
}

func TestControlServiceReconciliationReadRequiresReplayRead(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleSupport, Scopes: []string{"events:read"}}

	_, err := svc.ListReconciliationJobs(context.Background(), actor, 50)
	if err != ErrForbidden {
		t.Fatalf("expected forbidden reconciliation list, got %v", err)
	}
}

func TestControlServiceAuditChainVerifyRequiresAuditRead(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleSupport, Scopes: []string{"events:read"}}

	_, err := svc.VerifyAuditChain(context.Background(), actor, AuditChainVerifyRequest{})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden audit chain verify, got %v", err)
	}
}

func TestControlServiceAuditChainAnchorRequiresSecurityWriteAndReason(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	auditor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAuditor, Scopes: []string{"audit:read"}}
	_, err := svc.CreateAuditChainAnchor(context.Background(), auditor, AuditChainAnchorRequest{Reason: "anchor"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden audit chain anchor, got %v", err)
	}

	security := authz.Actor{ID: "usr_2", TenantID: "ten_a", Role: authz.RoleSecurity, Scopes: []string{"security:write"}}
	_, err = svc.CreateAuditChainAnchor(context.Background(), security, AuditChainAnchorRequest{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected missing reason validation, got %v", err)
	}
}

func TestControlServiceOpsVisibilityRequiresOpsRead(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlServiceWithRuntimeConfig(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}}, domain.OpsConfig{
		Environment:             "production",
		UIEnabled:               true,
		RawStorageMode:          domain.RawStorageS3,
		ObjectStorageConfigured: true,
		SecretBoxMode:           "vault-transit",
		MaxIngressBodyBytes:     2 << 20,
	})
	support := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleSupport, Scopes: []string{"events:read"}}
	operator := authz.Actor{ID: "usr_2", TenantID: "ten_a", Role: authz.RoleOperator, Scopes: []string{"ops:read"}}

	_, err := svc.ListWorkers(context.Background(), support, 10)
	if err != ErrForbidden {
		t.Fatalf("expected forbidden worker list, got %v", err)
	}
	_, err = svc.ListQueues(context.Background(), support)
	if err != ErrForbidden {
		t.Fatalf("expected forbidden queue list, got %v", err)
	}
	_, err = svc.ListQueues(context.Background(), operator)
	if err != nil {
		t.Fatal(err)
	}
	if store.opsTenantID != "ten_a" {
		t.Fatalf("expected tenant-scoped queue stats, got %q", store.opsTenantID)
	}
	_, err = svc.OpsStorage(context.Background(), support)
	if err != ErrForbidden {
		t.Fatalf("expected forbidden storage status, got %v", err)
	}
	storage, err := svc.OpsStorage(context.Background(), operator)
	if err != nil {
		t.Fatal(err)
	}
	if storage.TenantID != "ten_a" || store.opsTenantID != "ten_a" {
		t.Fatalf("expected tenant-scoped storage status, got item=%q store=%q", storage.TenantID, store.opsTenantID)
	}
	cfg, err := svc.OpsConfig(context.Background(), operator)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"DATABASE_URL", "MASTER_KEY", "VAULT_TOKEN", "postgres://user:pass", "raw-secret-value"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("ops config exposed sensitive token %q in %s", forbidden, raw)
		}
	}
	if cfg.Environment != "production" || cfg.RawStorageMode != domain.RawStorageS3 || !cfg.ObjectStorageConfigured {
		t.Fatalf("unexpected safe ops config: %+v", cfg)
	}
}

func TestControlServiceMetricRollupsRequireOpsReadAndValidateFilter(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	support := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleSupport, Scopes: []string{"events:read"}}
	operator := authz.Actor{ID: "usr_2", TenantID: "ten_a", Role: authz.RoleOperator, Scopes: []string{"ops:read"}}

	_, err := svc.ListMetricRollups(context.Background(), support, "", 10)
	if err != ErrForbidden {
		t.Fatalf("expected forbidden rollup list, got %v", err)
	}
	_, err = svc.ListMetricRollups(context.Background(), operator, "bad metric", 10)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid metric filter, got %v", err)
	}
	items, err := svc.ListMetricRollups(context.Background(), operator, "deliveries.by_state", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].TenantID != "ten_a" || store.opsTenantID != "ten_a" || store.metricName != "deliveries.by_state" {
		t.Fatalf("expected tenant-scoped metric rollups, items=%+v tenant=%q metric=%q", items, store.opsTenantID, store.metricName)
	}
}

func TestControlServiceAlertRulesRequireOpsWriteAndReason(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	reader := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleOperator, Scopes: []string{"ops:read"}}
	operator := authz.Actor{ID: "usr_2", TenantID: "ten_a", Role: authz.RoleOperator, Scopes: []string{"ops:write", "ops:read"}}

	_, err := svc.CreateAlertRule(context.Background(), reader, CreateAlertRuleRequest{Name: "DLQ", RuleType: domain.AlertRuleDeadLetterOpen, Threshold: 1})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden alert create, got %v", err)
	}
	_, err = svc.CreateAlertRule(context.Background(), operator, CreateAlertRuleRequest{Name: "bad", RuleType: "unknown", Threshold: 1})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid rule type, got %v", err)
	}
	rule, err := svc.CreateAlertRule(context.Background(), operator, CreateAlertRuleRequest{Name: "DLQ", RuleType: domain.AlertRuleDeadLetterOpen, Threshold: 1})
	if err != nil {
		t.Fatal(err)
	}
	if rule.TenantID != "ten_a" || store.alertTenantID != "ten_a" || store.alertActorID != "usr_2" {
		t.Fatalf("expected tenant-scoped alert create, rule=%+v tenant=%q actor=%q", rule, store.alertTenantID, store.alertActorID)
	}
	_, err = svc.DeleteAlertRule(context.Background(), operator, "alr_1", StateChangeRequest{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected delete reason validation, got %v", err)
	}
}

func TestControlServiceAlertFiringAckRequiresOpsWriteAndReason(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	reader := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleOperator, Scopes: []string{"ops:read"}}
	operator := authz.Actor{ID: "usr_2", TenantID: "ten_a", Role: authz.RoleOperator, Scopes: []string{"ops:write"}}

	_, err := svc.AcknowledgeAlertFiring(context.Background(), reader, "alf_1", StateChangeRequest{Reason: "seen"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden alert ack, got %v", err)
	}
	_, err = svc.AcknowledgeAlertFiring(context.Background(), operator, "alf_1", StateChangeRequest{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ack reason validation, got %v", err)
	}
	item, err := svc.AcknowledgeAlertFiring(context.Background(), operator, "alf_1", StateChangeRequest{Reason: "seen"})
	if err != nil {
		t.Fatal(err)
	}
	if item.TenantID != "ten_a" || store.alertTenantID != "ten_a" || store.alertActorID != "usr_2" {
		t.Fatalf("expected tenant-scoped alert ack, item=%+v tenant=%q actor=%q", item, store.alertTenantID, store.alertActorID)
	}
}

func testClientCertificatePEM(t *testing.T, commonName string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM)
}

type fakeControlStore struct {
	eventTenantID              string
	auditExportTenantID        string
	auditExport                domain.EvidenceExport
	auditExportDownloaded      bool
	auditExports               []domain.EvidenceExport
	apiKeyInput                APIKeyCreateInput
	eventSchema                domain.EventSchema
	schemaTenantID             string
	schemaReason               string
	retryPolicyTenantID        string
	retryPolicyID              string
	retryPolicyReq             UpdateRetryPolicyRequest
	normalizedTenantID         string
	normalizedMetadataOnly     bool
	sourceTenantID             string
	sourceID                   string
	sourceReason               string
	endpointTenantID           string
	endpointID                 string
	endpointReason             string
	subscriptionTenantID       string
	subscriptionID             string
	subscriptionReason         string
	subscription               domain.Subscription
	routeTenantID              string
	routeID                    string
	routeReason                string
	route                      domain.Route
	transformationTenantID     string
	providerConnectionTenantID string
	providerConnectionReq      CreateProviderConnectionRequest
	reconciliationTenantID     string
	opsTenantID                string
	metricName                 string
	alertTenantID              string
	alertActorID               string
	replayReq                  ReplayRequest
	approveReplayTenantID      string
	approveReplayActorID       string
	approveReplayReason        string
	endpoint                   domain.Endpoint
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
func (f *fakeControlStore) GetSource(_ context.Context, tenantID, sourceID string) (domain.Source, error) {
	f.sourceTenantID = tenantID
	f.sourceID = sourceID
	return domain.Source{ID: sourceID, TenantID: tenantID, Name: "Source", Provider: "github", Adapter: "github", State: domain.StateActive}, nil
}
func (f *fakeControlStore) UpdateSource(_ context.Context, tenantID, sourceID, actorID string, req UpdateSourceRequest) (domain.Source, error) {
	f.sourceTenantID = tenantID
	f.sourceID = sourceID
	f.sourceReason = req.Reason
	state := domain.StateActive
	if req.State != nil {
		state = *req.State
	}
	name := "Source"
	if req.Name != nil {
		name = *req.Name
	}
	return domain.Source{ID: sourceID, TenantID: tenantID, Name: name, Provider: "github", Adapter: "github", State: state}, nil
}
func (f *fakeControlStore) DeleteSource(_ context.Context, tenantID, sourceID, actorID, reason string) (domain.Source, error) {
	f.sourceTenantID = tenantID
	f.sourceID = sourceID
	f.sourceReason = reason
	return domain.Source{ID: sourceID, TenantID: tenantID, Name: "Source", Provider: "github", Adapter: "github", State: domain.StateDisabled}, nil
}
func (f *fakeControlStore) CreateEndpoint(_ context.Context, endpoint domain.Endpoint) (domain.Endpoint, error) {
	f.endpoint = endpoint
	endpoint.ID = "end_1"
	return endpoint, nil
}
func (f *fakeControlStore) TestEndpoint(context.Context, string, string, string, string) (domain.Delivery, error) {
	return domain.Delivery{}, nil
}
func (f *fakeControlStore) ListEndpoints(context.Context, string, int) ([]domain.Endpoint, error) {
	return nil, nil
}
func (f *fakeControlStore) GetEndpoint(_ context.Context, tenantID, endpointID string) (domain.Endpoint, error) {
	f.endpointTenantID = tenantID
	f.endpointID = endpointID
	return domain.Endpoint{ID: endpointID, TenantID: tenantID, Name: "Receiver", URL: "https://receiver.example/webhook", State: domain.StateActive}, nil
}
func (f *fakeControlStore) UpdateEndpoint(_ context.Context, tenantID, endpointID, actorID string, req UpdateEndpointRequest) (domain.Endpoint, error) {
	f.endpointTenantID = tenantID
	f.endpointID = endpointID
	f.endpointReason = req.Reason
	if f.endpoint.ID == "" {
		f.endpoint = domain.Endpoint{ID: endpointID, TenantID: tenantID, Name: "Receiver", URL: "https://receiver.example/webhook", State: domain.StateActive}
	}
	if req.Name != nil {
		f.endpoint.Name = *req.Name
	}
	if req.URL != nil {
		f.endpoint.URL = *req.URL
	}
	if req.State != nil {
		f.endpoint.State = *req.State
	}
	if req.RetryPolicyID != nil {
		f.endpoint.RetryPolicyID = *req.RetryPolicyID
	}
	return f.endpoint, nil
}
func (f *fakeControlStore) DeleteEndpoint(_ context.Context, tenantID, endpointID, actorID, reason string) (domain.Endpoint, error) {
	f.endpointTenantID = tenantID
	f.endpointID = endpointID
	f.endpointReason = reason
	return domain.Endpoint{ID: endpointID, TenantID: tenantID, Name: "Receiver", URL: "https://receiver.example/webhook", State: domain.StateDisabled}, nil
}
func (f *fakeControlStore) CreateSubscription(context.Context, domain.Subscription) (domain.Subscription, error) {
	return domain.Subscription{}, nil
}
func (f *fakeControlStore) ListSubscriptions(context.Context, string, int) ([]domain.Subscription, error) {
	return nil, nil
}
func (f *fakeControlStore) GetSubscription(_ context.Context, tenantID, subscriptionID string) (domain.Subscription, error) {
	f.subscriptionTenantID = tenantID
	f.subscriptionID = subscriptionID
	return domain.Subscription{ID: subscriptionID, TenantID: tenantID, EndpointID: "end_1", EventTypes: []string{"invoice.paid"}, PayloadFormat: "canonical_json", State: domain.StateActive, Version: 1}, nil
}
func (f *fakeControlStore) UpdateSubscription(_ context.Context, tenantID, subscriptionID, actorID string, req UpdateSubscriptionRequest) (domain.Subscription, error) {
	f.subscriptionTenantID = tenantID
	f.subscriptionID = subscriptionID
	f.subscriptionReason = req.Reason
	if f.subscription.ID == "" {
		f.subscription = domain.Subscription{ID: subscriptionID, TenantID: tenantID, EndpointID: "end_1", EventTypes: []string{"invoice.paid"}, PayloadFormat: "canonical_json", State: domain.StateActive, Version: 1}
	}
	if req.EndpointID != nil {
		f.subscription.EndpointID = *req.EndpointID
	}
	if req.EventTypes != nil {
		f.subscription.EventTypes = req.EventTypes
	}
	if req.PayloadFormat != nil {
		f.subscription.PayloadFormat = *req.PayloadFormat
	}
	if req.TransformationID != nil {
		f.subscription.TransformationID = *req.TransformationID
	}
	if req.State != nil {
		f.subscription.State = *req.State
	}
	return f.subscription, nil
}
func (f *fakeControlStore) DeleteSubscription(_ context.Context, tenantID, subscriptionID, actorID, reason string) (domain.Subscription, error) {
	f.subscriptionTenantID = tenantID
	f.subscriptionID = subscriptionID
	f.subscriptionReason = reason
	return domain.Subscription{ID: subscriptionID, TenantID: tenantID, EndpointID: "end_1", EventTypes: []string{"invoice.paid"}, PayloadFormat: "canonical_json", State: domain.StateDisabled, Version: 2}, nil
}
func (f *fakeControlStore) CreateRoute(context.Context, domain.Route) (domain.Route, error) {
	return domain.Route{}, nil
}
func (f *fakeControlStore) ListRoutes(context.Context, string, int) ([]domain.Route, error) {
	return nil, nil
}
func (f *fakeControlStore) GetRoute(_ context.Context, tenantID, routeID string) (domain.Route, error) {
	f.routeTenantID = tenantID
	f.routeID = routeID
	return domain.Route{ID: routeID, TenantID: tenantID, SourceID: "src_1", Name: "Route", Priority: 100, EventTypes: []string{"invoice.paid"}, EndpointID: "end_1", State: domain.StateActive, Version: 1}, nil
}
func (f *fakeControlStore) UpdateRoute(_ context.Context, tenantID, routeID, actorID string, req UpdateRouteRequest) (domain.Route, error) {
	f.routeTenantID = tenantID
	f.routeID = routeID
	f.routeReason = req.Reason
	if f.route.ID == "" {
		f.route = domain.Route{ID: routeID, TenantID: tenantID, SourceID: "src_1", Name: "Route", Priority: 100, EventTypes: []string{"invoice.paid"}, EndpointID: "end_1", State: domain.StateActive, Version: 1}
	}
	if req.SourceID != nil {
		f.route.SourceID = *req.SourceID
	}
	if req.Name != nil {
		f.route.Name = *req.Name
	}
	if req.Priority != nil {
		f.route.Priority = *req.Priority
	}
	if req.EventTypes != nil {
		f.route.EventTypes = req.EventTypes
	}
	if req.EndpointID != nil {
		f.route.EndpointID = *req.EndpointID
	}
	if req.RetryPolicyID != nil {
		f.route.RetryPolicyID = *req.RetryPolicyID
	}
	if req.TransformationID != nil {
		f.route.TransformationID = *req.TransformationID
	}
	if req.State != nil {
		f.route.State = *req.State
	}
	return f.route, nil
}
func (f *fakeControlStore) DeleteRoute(_ context.Context, tenantID, routeID, actorID, reason string) (domain.Route, error) {
	f.routeTenantID = tenantID
	f.routeID = routeID
	f.routeReason = reason
	return domain.Route{ID: routeID, TenantID: tenantID, SourceID: "src_1", Name: "Route", Priority: 100, EventTypes: []string{"invoice.paid"}, EndpointID: "end_1", State: domain.StateInactive, Version: 2}, nil
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
func (f *fakeControlStore) GetRetryPolicy(_ context.Context, tenantID, retryPolicyID string) (domain.RetryPolicy, error) {
	f.retryPolicyTenantID = tenantID
	f.retryPolicyID = retryPolicyID
	return domain.RetryPolicy{ID: retryPolicyID, TenantID: tenantID, Name: "standard", Version: 1, State: domain.StateActive, MaxAttempts: 3, MaxDurationSeconds: 60, InitialDelaySeconds: 1, MaxDelaySeconds: 10}, nil
}
func (f *fakeControlStore) UpdateRetryPolicy(_ context.Context, tenantID, retryPolicyID, actorID string, req UpdateRetryPolicyRequest) (domain.RetryPolicy, error) {
	f.retryPolicyTenantID = tenantID
	f.retryPolicyID = retryPolicyID
	f.retryPolicyReq = req
	maxAttempts := 3
	if req.MaxAttempts != nil {
		maxAttempts = *req.MaxAttempts
	}
	return domain.RetryPolicy{ID: "rtp_2", TenantID: tenantID, Name: "standard", Version: 2, State: domain.StateActive, MaxAttempts: maxAttempts, MaxDurationSeconds: 60, InitialDelaySeconds: 1, MaxDelaySeconds: 10, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) DeleteRetryPolicy(_ context.Context, tenantID, retryPolicyID, actorID, reason string) (domain.RetryPolicy, error) {
	f.retryPolicyTenantID = tenantID
	f.retryPolicyID = retryPolicyID
	return domain.RetryPolicy{ID: retryPolicyID, TenantID: tenantID, Name: "standard", Version: 2, State: domain.StateDisabled, MaxAttempts: 3, MaxDurationSeconds: 60, InitialDelaySeconds: 1, MaxDelaySeconds: 10, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) CreateEventType(context.Context, domain.EventType) (domain.EventType, error) {
	return domain.EventType{}, nil
}
func (f *fakeControlStore) ListEventTypes(context.Context, string, int) ([]domain.EventType, error) {
	return nil, nil
}
func (f *fakeControlStore) GetEventType(_ context.Context, tenantID, eventType string) (domain.EventType, error) {
	f.schemaTenantID = tenantID
	return domain.EventType{TenantID: tenantID, Name: eventType, Description: "Invoice paid", State: domain.StateActive}, nil
}
func (f *fakeControlStore) UpdateEventType(_ context.Context, tenantID, eventType, actorID string, req UpdateEventTypeRequest) (domain.EventType, error) {
	f.schemaTenantID = tenantID
	f.schemaReason = req.Reason
	description := "Invoice paid"
	if req.Description != nil {
		description = *req.Description
	}
	state := domain.StateActive
	if req.State != nil {
		state = *req.State
	}
	return domain.EventType{TenantID: tenantID, Name: eventType, Description: description, State: state}, nil
}
func (f *fakeControlStore) DeleteEventType(_ context.Context, tenantID, eventType, actorID, reason string) (domain.EventType, error) {
	f.schemaTenantID = tenantID
	f.schemaReason = reason
	return domain.EventType{TenantID: tenantID, Name: eventType, Description: "Invoice paid", State: domain.StateDisabled}, nil
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
func (f *fakeControlStore) UpdateEventSchema(_ context.Context, tenantID, eventType, version, actorID string, req UpdateEventSchemaRequest) (domain.EventSchema, error) {
	f.schemaTenantID = tenantID
	f.schemaReason = req.Reason
	state := domain.StateActive
	if req.State != nil {
		state = *req.State
	}
	return domain.EventSchema{ID: "sch_1", TenantID: tenantID, EventType: eventType, Version: version, Schema: `{"type":"object"}`, State: state}, nil
}
func (f *fakeControlStore) DeleteEventSchema(_ context.Context, tenantID, eventType, version, actorID, reason string) (domain.EventSchema, error) {
	f.schemaTenantID = tenantID
	f.schemaReason = reason
	return domain.EventSchema{ID: "sch_1", TenantID: tenantID, EventType: eventType, Version: version, Schema: `{"type":"object"}`, State: domain.StateRetired}, nil
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
func (f *fakeControlStore) GetNormalizedEvent(_ context.Context, tenantID, eventID, actorID string, includeData bool) (domain.NormalizedEnvelope, error) {
	f.normalizedTenantID = tenantID
	f.normalizedMetadataOnly = !includeData
	return domain.NormalizedEnvelope{ID: "nenv_1", TenantID: tenantID, EventID: eventID}, nil
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
func (f *fakeControlStore) ListWorkers(context.Context, string, int) ([]domain.WorkerStatus, error) {
	return nil, nil
}
func (f *fakeControlStore) GetWorker(context.Context, string, string) (domain.WorkerStatus, error) {
	return domain.WorkerStatus{}, nil
}
func (f *fakeControlStore) ListQueues(_ context.Context, tenantID string) ([]domain.QueueStats, error) {
	f.opsTenantID = tenantID
	return nil, nil
}
func (f *fakeControlStore) OpsStorage(_ context.Context, tenantID string) (domain.OpsStorageStatus, error) {
	f.opsTenantID = tenantID
	return domain.OpsStorageStatus{
		TenantID:                tenantID,
		RawStorageMode:          domain.RawStorageS3,
		ObjectStorageConfigured: true,
		RawPayloadsByStatus:     map[string]int64{domain.StorageStatusStored: 2},
		RawPayloadsByBackend:    map[string]int64{domain.RawStorageS3: 2},
	}, nil
}
func (f *fakeControlStore) ListMetricRollups(_ context.Context, tenantID, metricName string, limit int) ([]domain.MetricRollup, error) {
	f.opsTenantID = tenantID
	f.metricName = metricName
	return []domain.MetricRollup{{
		ID:            "mru_1",
		TenantID:      tenantID,
		MetricName:    metricName,
		BucketSeconds: 60,
		Dimensions:    map[string]string{"state": "scheduled"},
		Value:         3,
	}}, nil
}
func (f *fakeControlStore) CreateAlertRule(_ context.Context, tenantID, actorID string, req CreateAlertRuleRequest) (domain.AlertRule, error) {
	f.alertTenantID = tenantID
	f.alertActorID = actorID
	return domain.AlertRule{ID: "alr_1", TenantID: tenantID, Name: req.Name, RuleType: req.RuleType, MetricName: req.MetricName, Threshold: req.Threshold, Comparator: req.Comparator, WindowSeconds: req.WindowSeconds, State: req.State, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) ListAlertRules(context.Context, string, int) ([]domain.AlertRule, error) {
	return nil, nil
}
func (f *fakeControlStore) GetAlertRule(context.Context, string, string) (domain.AlertRule, error) {
	return domain.AlertRule{}, nil
}
func (f *fakeControlStore) UpdateAlertRule(context.Context, string, string, string, UpdateAlertRuleRequest) (domain.AlertRule, error) {
	return domain.AlertRule{}, nil
}
func (f *fakeControlStore) DeleteAlertRule(_ context.Context, tenantID, alertID, actorID, reason string) (domain.AlertRule, error) {
	f.alertTenantID = tenantID
	f.alertActorID = actorID
	return domain.AlertRule{ID: alertID, TenantID: tenantID, State: domain.StateDisabled}, nil
}
func (f *fakeControlStore) ListAlertFirings(context.Context, string, string, int) ([]domain.AlertFiring, error) {
	return nil, nil
}
func (f *fakeControlStore) GetAlertFiring(context.Context, string, string) (domain.AlertFiring, error) {
	return domain.AlertFiring{}, nil
}
func (f *fakeControlStore) AcknowledgeAlertFiring(_ context.Context, tenantID, firingID, actorID, reason string) (domain.AlertFiring, error) {
	f.alertTenantID = tenantID
	f.alertActorID = actorID
	return domain.AlertFiring{ID: firingID, TenantID: tenantID, State: domain.AlertFiringAcknowledged, AcknowledgedBy: actorID, Reason: reason}, nil
}
func (f *fakeControlStore) ListAuditEvents(context.Context, string, int) ([]domain.AuditEvent, error) {
	return nil, nil
}
func (f *fakeControlStore) GetAuditChainHead(context.Context, string) (domain.AuditChainHead, error) {
	return domain.AuditChainHead{}, nil
}
func (f *fakeControlStore) VerifyAuditChain(context.Context, string, AuditChainVerifyRequest) (domain.AuditChainVerification, error) {
	return domain.AuditChainVerification{Valid: true}, nil
}
func (f *fakeControlStore) CreateAuditChainAnchor(context.Context, string, string, AuditChainAnchorRequest) (domain.AuditChainAnchor, error) {
	return domain.AuditChainAnchor{}, nil
}
func (f *fakeControlStore) ListAuditChainAnchors(context.Context, string, int) ([]domain.AuditChainAnchor, error) {
	return nil, nil
}
func (f *fakeControlStore) GetAuditChainAnchor(context.Context, string, string) (domain.AuditChainAnchor, error) {
	return domain.AuditChainAnchor{}, nil
}
func (f *fakeControlStore) ListRetentionPolicies(context.Context, string, int) ([]domain.RetentionPolicy, error) {
	return nil, nil
}
func (f *fakeControlStore) CreateRetentionPolicy(_ context.Context, tenantID, actorID string, req CreateRetentionPolicyRequest) (domain.RetentionPolicy, error) {
	return domain.RetentionPolicy{ID: "ret_1", TenantID: tenantID, ResourceType: req.ResourceType, RetentionDays: req.RetentionDays, LegalHold: req.LegalHold, HoldReason: req.HoldReason, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) UpdateRetentionPolicy(_ context.Context, tenantID, policyID, actorID string, req UpdateRetentionPolicyRequest) (domain.RetentionPolicy, error) {
	days := 30
	if req.RetentionDays != nil {
		days = *req.RetentionDays
	}
	item := domain.RetentionPolicy{ID: policyID, TenantID: tenantID, RetentionDays: days, CreatedBy: actorID}
	if req.LegalHold != nil {
		item.LegalHold = *req.LegalHold
	}
	if req.HoldReason != nil {
		item.HoldReason = *req.HoldReason
	}
	return item, nil
}
func (f *fakeControlStore) CreateProviderConnection(_ context.Context, tenantID, actorID string, req CreateProviderConnectionRequest) (domain.ProviderConnection, error) {
	f.providerConnectionTenantID = tenantID
	f.providerConnectionReq = req
	return domain.ProviderConnection{ID: "pcn_1", TenantID: tenantID, Name: req.Name, Provider: req.Provider, State: domain.ProviderConnectionStateActive, CredentialType: req.CredentialType, CredentialHint: "sk_...cret", Config: req.Config, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) ListProviderConnections(context.Context, string, int) ([]domain.ProviderConnection, error) {
	return nil, nil
}
func (f *fakeControlStore) GetProviderConnection(context.Context, string, string) (domain.ProviderConnection, error) {
	return domain.ProviderConnection{}, nil
}
func (f *fakeControlStore) VerifyProviderConnection(context.Context, string, string, string, string) (domain.ProviderConnection, error) {
	return domain.ProviderConnection{}, nil
}
func (f *fakeControlStore) RevokeProviderConnection(context.Context, string, string, string, string) (domain.ProviderConnection, error) {
	return domain.ProviderConnection{}, nil
}
func (f *fakeControlStore) DryRunReconciliation(_ context.Context, tenantID string, req ReconciliationJobRequest) (domain.ReconciliationJob, error) {
	f.reconciliationTenantID = tenantID
	return domain.ReconciliationJob{ID: "rec_dry", TenantID: tenantID, ConnectionID: req.ConnectionID, DryRun: true}, nil
}
func (f *fakeControlStore) CreateReconciliationJob(_ context.Context, tenantID, actorID string, req ReconciliationJobRequest) (domain.ReconciliationJob, error) {
	f.reconciliationTenantID = tenantID
	return domain.ReconciliationJob{ID: "rec_1", TenantID: tenantID, ConnectionID: req.ConnectionID, State: domain.ReconciliationJobStateScheduled, CaptureMissing: req.CaptureMissing, RouteRecovered: req.RouteRecovered, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) ListReconciliationJobs(context.Context, string, int) ([]domain.ReconciliationJob, error) {
	return nil, nil
}
func (f *fakeControlStore) GetReconciliationJob(context.Context, string, string) (domain.ReconciliationJob, error) {
	return domain.ReconciliationJob{}, nil
}
func (f *fakeControlStore) ListReconciliationItems(context.Context, string, string, int) ([]domain.ReconciliationItem, error) {
	return nil, nil
}
func (f *fakeControlStore) CancelReconciliationJob(context.Context, string, string, string, string) (domain.ReconciliationJob, error) {
	return domain.ReconciliationJob{}, nil
}
func (f *fakeControlStore) CreateAuditExport(_ context.Context, tenantID, actorID string, req CreateAuditExportRequest) (domain.EvidenceExport, error) {
	return domain.EvidenceExport{ID: "exp_1", TenantID: tenantID, IncludeRawPayloads: req.IncludeRawPayloads, IncludePayloadBodies: req.IncludePayloadBodies, CreatedBy: actorID}, nil
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
func (f *fakeControlStore) CreateReplay(_ context.Context, tenantID, actorID string, req ReplayRequest) (ReplayJob, error) {
	f.replayReq = req
	return ReplayJob{ID: "rpl_1", State: "pending_approval", ScopeHash: "sha256:abc", TotalItems: 1, ApprovalRequired: req.RequireApproval}, nil
}
func (f *fakeControlStore) ListReplayJobs(context.Context, string, int) ([]ReplayJob, error) {
	return nil, nil
}
func (f *fakeControlStore) ApproveReplayJob(_ context.Context, tenantID, replayJobID, actorID, reason string) (ReplayJob, error) {
	f.approveReplayTenantID = tenantID
	f.approveReplayActorID = actorID
	f.approveReplayReason = reason
	return ReplayJob{ID: replayJobID, State: "scheduled", ApprovalRequired: true, ApprovedBy: actorID}, nil
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
func (f *fakeControlStore) CreateTransformation(_ context.Context, tenantID, actorID string, req CreateTransformationRequest) (domain.Transformation, error) {
	f.transformationTenantID = tenantID
	return domain.Transformation{ID: "trn_1", TenantID: tenantID, Name: req.Name, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) ListTransformations(context.Context, string, int) ([]domain.Transformation, error) {
	return nil, nil
}
func (f *fakeControlStore) GetTransformation(context.Context, string, string) (domain.Transformation, error) {
	return domain.Transformation{}, nil
}
func (f *fakeControlStore) CreateTransformationVersion(context.Context, string, string, string, CreateTransformationVersionRequest) (domain.TransformationVersion, error) {
	return domain.TransformationVersion{}, nil
}
func (f *fakeControlStore) ListTransformationVersions(context.Context, string, string, int) ([]domain.TransformationVersion, error) {
	return nil, nil
}
func (f *fakeControlStore) ActivateTransformationVersion(context.Context, string, string, string, string, string) (domain.TransformationVersion, error) {
	return domain.TransformationVersion{}, nil
}

func ptrString(v string) *string {
	return &v
}
