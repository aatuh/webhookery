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
	store := &fakeControlStore{eventSchema: domain.EventSchema{Schema: `{"type":"object"}`}}
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

func TestControlServiceSearchEventsNormalizesFiltersAndScopesTenant(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"events:read"}}

	receivedAfter := time.Date(2026, 6, 4, 12, 0, 0, 0, time.FixedZone("UTC+2", 2*60*60))
	if _, err := svc.SearchEvents(context.Background(), actor, EventSearchRequest{
		Provider:      " stripe ",
		ExternalID:    " evt_external ",
		Status:        "DLQ",
		Verification:  "INVALID",
		ReceivedAfter: receivedAfter,
		Limit:         250,
	}); err != nil {
		t.Fatal(err)
	}
	if store.eventSearchTenantID != "ten_a" {
		t.Fatalf("expected tenant-scoped event search, got %q", store.eventSearchTenantID)
	}
	if store.eventSearchReq.Provider != "stripe" || store.eventSearchReq.ExternalID != "evt_external" || store.eventSearchReq.Status != "dlq" || store.eventSearchReq.Verification != "invalid" {
		t.Fatalf("filters were not normalized: %+v", store.eventSearchReq)
	}
	if store.eventSearchReq.Limit != 50 {
		t.Fatalf("limit should be bounded to default, got %d", store.eventSearchReq.Limit)
	}
	if store.eventSearchReq.ReceivedAfter.Location() != time.UTC {
		t.Fatalf("received_after should be UTC-normalized: %s", store.eventSearchReq.ReceivedAfter)
	}
	if _, err := svc.SearchEvents(context.Background(), actor, EventSearchRequest{Verification: "maybe"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid verification to be rejected, got %v", err)
	}
}

func TestControlServiceListEventTimelineReturnsVersionedEntries(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"events:read"}}

	items, err := svc.ListEventTimeline(context.Background(), actor, "evt_1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatal("expected timeline entries")
	}
	if items[0].SchemaVersion != EventTimelineSchemaV1 || items[0].Sequence != 1 || items[0].OccurredAt.Location() != time.UTC {
		t.Fatalf("timeline entry was not normalized: %+v", items[0])
	}
}

func TestControlServiceIncidentLifecycleScopesAndRedactsReports(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleOperator, Scopes: []string{"incidents:read", "incidents:write", "events:read"}}
	reader := authz.Actor{ID: "usr_2", TenantID: "ten_a", Role: authz.RoleSupport, Scopes: []string{"incidents:read"}}

	if _, err := svc.CreateIncident(context.Background(), reader, CreateIncidentRequest{Title: "Stripe payment failed", Reason: "support case"}); err != ErrForbidden {
		t.Fatalf("expected incident create to require incidents:write, got %v", err)
	}
	if _, err := svc.CreateIncident(context.Background(), actor, CreateIncidentRequest{Title: " ", Reason: "support case"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected incident title validation, got %v", err)
	}

	incident, err := svc.CreateIncident(context.Background(), actor, CreateIncidentRequest{Title: "Stripe payment failed", Reason: "support case"})
	if err != nil {
		t.Fatal(err)
	}
	if incident.TenantID != "ten_a" || incident.CreatedBy != "usr_1" || store.incidentTenantID != "ten_a" || store.incidentActorID != "usr_1" {
		t.Fatalf("incident was not tenant-scoped: incident=%+v tenant=%q actor=%q", incident, store.incidentTenantID, store.incidentActorID)
	}

	if _, err := svc.AddIncidentEvent(context.Background(), actor, incident.ID, AddIncidentEventRequest{EventID: "evt_1", Reason: "investigate"}); err != nil {
		t.Fatal(err)
	}
	if store.incidentID != incident.ID || store.incidentEventID != "evt_1" || store.incidentReason != "investigate" {
		t.Fatalf("incident event link was not scoped with reason: incident=%q event=%q reason=%q", store.incidentID, store.incidentEventID, store.incidentReason)
	}

	snapshot, err := svc.GenerateIncidentReport(context.Background(), actor, incident.ID, IncidentReportRequest{Reason: "support handoff"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"raw-body-secret", "whsec_test", "sk_test_secret", "Stripe-Signature", "v1=secret", "Bearer secret-token", "private-key-secret"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("incident report leaked sensitive value %q in %s", forbidden, raw)
		}
	}
	if !strings.Contains(snapshot.Markdown, "Inbound capture does not prove downstream business success") {
		t.Fatalf("incident report must include non-claims, got markdown:\n%s", snapshot.Markdown)
	}
	if !strings.Contains(snapshot.Markdown, "reason_code=incident_recovery") || !strings.Contains(snapshot.Markdown, "receiver restored after DLQ") {
		t.Fatalf("incident report must include replay reason code and reason, got markdown:\n%s", snapshot.Markdown)
	}

	if _, err := svc.GetIncidentReport(context.Background(), reader, incident.ID); err != nil {
		t.Fatal(err)
	}
	if store.incidentTenantID != "ten_a" {
		t.Fatalf("incident report read was not tenant-scoped: %q", store.incidentTenantID)
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

func TestControlServiceOwnerHappyPathSurface(t *testing.T) {
	store := &fakeControlStore{eventSchema: domain.EventSchema{Schema: `{"type":"object"}`}}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{
		"receiver.example": {netip.MustParseAddr("93.184.216.34")},
		"signals.example":  {netip.MustParseAddr("93.184.216.34")},
		"siem.example":     {netip.MustParseAddr("93.184.216.34")},
	}})
	actor := authz.Actor{ID: "usr_owner", TenantID: "ten_owner", Role: authz.RoleOwner, Scopes: []string{"*"}}
	active := domain.StateActive
	disabled := domain.StateDisabled
	tests := []struct {
		name string
		run  func(context.Context) error
	}{
		{name: "api keys", run: func(ctx context.Context) error {
			if _, err := svc.ListAPIKeys(ctx, actor, 10); err != nil {
				return err
			}
			_, err := svc.RevokeAPIKey(ctx, actor, "key_1", RevokeAPIKeyRequest{Reason: "rotate"})
			return err
		}},
		{name: "sources", run: func(ctx context.Context) error {
			if _, err := svc.CreateSource(ctx, actor, CreateSourceRequest{Name: "stripe", Provider: "stripe", Adapter: "stripe", VerificationSecret: "whsec_test"}); err != nil {
				return err
			}
			if _, err := svc.ListSources(ctx, actor, 10); err != nil {
				return err
			}
			_, err := svc.RotateSourceSecret(ctx, actor, "src_1", RotateSourceSecretRequest{NewSecret: "next", GracePeriodHours: 1, Reason: "rotate"})
			return err
		}},
		{name: "endpoints", run: func(ctx context.Context) error {
			if _, _, err := svc.CreateEndpoint(ctx, actor, CreateEndpointRequest{Name: "receiver", URL: "https://receiver.example/hook"}); err != nil {
				return err
			}
			if _, err := svc.ListEndpoints(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.TestEndpoint(ctx, actor, "end_1", TestEndpointRequest{Reason: "smoke"}); err != nil {
				return err
			}
			_, err := svc.RotateEndpointSecret(ctx, actor, "end_1", RotateEndpointSecretRequest{GracePeriodHours: 1, Reason: "rotate"})
			return err
		}},
		{name: "subscriptions and routes", run: func(ctx context.Context) error {
			if _, err := svc.CreateSubscription(ctx, actor, CreateSubscriptionRequest{EndpointID: "end_1", EventTypes: []string{"invoice.paid"}}); err != nil {
				return err
			}
			if _, err := svc.ListSubscriptions(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.CreateRoute(ctx, actor, CreateRouteRequest{Name: "route", SourceID: "src_1", EndpointID: "end_1", EventTypes: []string{"invoice.paid"}}); err != nil {
				return err
			}
			if _, err := svc.ListRoutes(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.ListRouteVersions(ctx, actor, "rte_1", 10); err != nil {
				return err
			}
			if _, err := svc.ActivateRoute(ctx, actor, "rte_1", "publish"); err != nil {
				return err
			}
			_, err := svc.DryRunRoute(ctx, actor, "rte_1", "evt_1")
			return err
		}},
		{name: "retry policies", run: func(ctx context.Context) error {
			if _, err := svc.CreateRetryPolicy(ctx, actor, CreateRetryPolicyRequest{Name: "standard", MaxAttempts: 3, MaxDurationSeconds: 3600, InitialDelaySeconds: 1, MaxDelaySeconds: 60}); err != nil {
				return err
			}
			if _, err := svc.ListRetryPolicies(ctx, actor, 10); err != nil {
				return err
			}
			_, err := svc.DeleteRetryPolicy(ctx, actor, "rtp_1", StateChangeRequest{Reason: "retire"})
			return err
		}},
		{name: "event schemas", run: func(ctx context.Context) error {
			if _, err := svc.CreateEventType(ctx, actor, CreateEventTypeRequest{Name: "invoice.paid", Description: "Invoice paid"}); err != nil {
				return err
			}
			if _, err := svc.ListEventTypes(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.CreateEventSchema(ctx, actor, "invoice.paid", CreateEventSchemaRequest{Version: "2026-05-01", Schema: `{"type":"object"}`}); err != nil {
				return err
			}
			if _, err := svc.ListEventSchemas(ctx, actor, "invoice.paid", 10); err != nil {
				return err
			}
			if _, err := svc.ValidateEventSchema(ctx, actor, "invoice.paid", "2026-05-01", ValidateSchemaRequest{Payload: `{"id":"evt_1"}`}); err != nil {
				return err
			}
			if _, err := svc.CheckEventSchemaCompatibility(ctx, actor, "invoice.paid", "2026-05-01", CheckSchemaCompatibilityRequest{NewSchema: `{"type":"object"}`}); err != nil {
				return err
			}
			_, err := svc.DeleteEventSchema(ctx, actor, "invoice.paid", "2026-05-01", StateChangeRequest{Reason: "retire"})
			return err
		}},
		{name: "events and deliveries", run: func(ctx context.Context) error {
			if _, err := svc.ListEvents(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.ListEventTimeline(ctx, actor, "evt_1", 10); err != nil {
				return err
			}
			if _, err := svc.ListDeliveries(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.ListDeliveryAttempts(ctx, actor, "del_1", 10); err != nil {
				return err
			}
			if _, err := svc.GetDeliveryAttempt(ctx, actor, "att_1"); err != nil {
				return err
			}
			if _, err := svc.RetryDelivery(ctx, actor, "del_1", "retry"); err != nil {
				return err
			}
			_, err := svc.CancelDelivery(ctx, actor, "del_1", StateChangeRequest{Reason: "cancel"})
			return err
		}},
		{name: "ops and signals", run: func(ctx context.Context) error {
			if _, err := svc.ListEndpointHealth(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.OpsMetrics(ctx, actor); err != nil {
				return err
			}
			if _, err := svc.PublicOpsMetrics(ctx); err != nil {
				return err
			}
			if _, err := svc.ListQueues(ctx, actor); err != nil {
				return err
			}
			if _, err := svc.OpsStorage(ctx, actor); err != nil {
				return err
			}
			if _, err := svc.OpsConfig(ctx, actor); err != nil {
				return err
			}
			if _, err := svc.ListMetricRollups(ctx, actor, "deliveries.scheduled", 10); err != nil {
				return err
			}
			if _, err := svc.ListWorkers(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.GetWorker(ctx, actor, "wrk_1"); err != nil {
				return err
			}
			if _, err := svc.CreateAlertRule(ctx, actor, CreateAlertRuleRequest{Name: "delivery backlog", RuleType: domain.AlertRuleDeadLetterOpen, Threshold: 10}); err != nil {
				return err
			}
			if _, err := svc.ListAlertRules(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.GetAlertRule(ctx, actor, "alr_1"); err != nil {
				return err
			}
			if _, err := svc.UpdateAlertRule(ctx, actor, "alr_1", UpdateAlertRuleRequest{Name: ptrString("latency"), State: &active, Reason: "tune"}); err != nil {
				return err
			}
			if _, err := svc.DeleteAlertRule(ctx, actor, "alr_1", StateChangeRequest{Reason: "retire"}); err != nil {
				return err
			}
			if _, err := svc.ListAlertFirings(ctx, actor, domain.AlertFiringOpen, 10); err != nil {
				return err
			}
			if _, err := svc.GetAlertFiring(ctx, actor, "afr_1"); err != nil {
				return err
			}
			if _, err := svc.AcknowledgeAlertFiring(ctx, actor, "afr_1", StateChangeRequest{Reason: "investigating"}); err != nil {
				return err
			}
			if _, _, err := svc.CreateNotificationChannel(ctx, actor, CreateNotificationChannelRequest{Name: "pager", ChannelType: domain.NotificationChannelWebhook, URL: "https://signals.example/hook", SigningSecret: "0123456789abcdef"}); err != nil {
				return err
			}
			if _, err := svc.ListNotificationChannels(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.GetNotificationChannel(ctx, actor, "nch_1"); err != nil {
				return err
			}
			if _, _, err := svc.UpdateNotificationChannel(ctx, actor, "nch_1", UpdateNotificationChannelRequest{State: &disabled, Reason: "pause"}); err != nil {
				return err
			}
			if _, err := svc.TestNotificationChannel(ctx, actor, "nch_1", StateChangeRequest{Reason: "verify route"}); err != nil {
				return err
			}
			if _, err := svc.ListNotificationDeliveries(ctx, actor, domain.SignalDeliveryScheduled, 10); err != nil {
				return err
			}
			if _, err := svc.ListNotificationDeliveryAttempts(ctx, actor, "ndel_1", 10); err != nil {
				return err
			}
			if _, err := svc.RetryNotificationDelivery(ctx, actor, "ndel_1", StateChangeRequest{Reason: "retry"}); err != nil {
				return err
			}
			if _, err := svc.DeleteNotificationChannel(ctx, actor, "nch_1", StateChangeRequest{Reason: "retire"}); err != nil {
				return err
			}
			if _, _, err := svc.CreateSIEMSink(ctx, actor, CreateSIEMSinkRequest{Name: "siem", SinkType: domain.SIEMSinkWebhook, URL: "https://siem.example/ingest", SigningSecret: "0123456789abcdef"}); err != nil {
				return err
			}
			if _, err := svc.ListSIEMSinks(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.GetSIEMSink(ctx, actor, "snk_1"); err != nil {
				return err
			}
			if _, _, err := svc.UpdateSIEMSink(ctx, actor, "snk_1", UpdateSIEMSinkRequest{State: &disabled, Reason: "pause"}); err != nil {
				return err
			}
			if _, err := svc.TestSIEMSink(ctx, actor, "snk_1", StateChangeRequest{Reason: "verify route"}); err != nil {
				return err
			}
			if _, err := svc.ListSIEMDeliveries(ctx, actor, domain.SignalDeliveryScheduled, 10); err != nil {
				return err
			}
			if _, err := svc.ListSIEMDeliveryAttempts(ctx, actor, "sdel_1", 10); err != nil {
				return err
			}
			if _, err := svc.RetrySIEMDelivery(ctx, actor, "sdel_1", StateChangeRequest{Reason: "retry"}); err != nil {
				return err
			}
			_, err := svc.DeleteSIEMSink(ctx, actor, "snk_1", StateChangeRequest{Reason: "retire"})
			return err
		}},
		{name: "audit and replay", run: func(ctx context.Context) error {
			if _, err := svc.ListAuditEvents(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.GetAuditChainHead(ctx, actor); err != nil {
				return err
			}
			if _, err := svc.VerifyAuditChain(ctx, actor, AuditChainVerifyRequest{}); err != nil {
				return err
			}
			if _, err := svc.CreateAuditChainAnchor(ctx, actor, AuditChainAnchorRequest{Reason: "publish checkpoint"}); err != nil {
				return err
			}
			if _, err := svc.ListAuditChainAnchors(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.GetAuditChainAnchor(ctx, actor, "anc_1"); err != nil {
				return err
			}
			if _, err := svc.ListRetentionPolicies(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.CreateRetentionPolicy(ctx, actor, CreateRetentionPolicyRequest{ResourceType: domain.RetentionResourceRawPayload, RetentionDays: 30}); err != nil {
				return err
			}
			if _, err := svc.UpdateRetentionPolicy(ctx, actor, "ret_1", UpdateRetentionPolicyRequest{RetentionDays: ptrInt(45)}); err != nil {
				return err
			}
			if _, err := svc.ListReplayJobs(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.DryRunReplay(ctx, actor, ReplayRequest{EventID: "evt_1", ReasonCode: ReplayReasonOperatorRequested, Reason: "investigate"}); err != nil {
				return err
			}
			if _, err := svc.PauseReplayJob(ctx, actor, "rpl_1", StateChangeRequest{Reason: "pause"}); err != nil {
				return err
			}
			if _, err := svc.ResumeReplayJob(ctx, actor, "rpl_1", StateChangeRequest{Reason: "resume"}); err != nil {
				return err
			}
			_, err := svc.CancelReplayJob(ctx, actor, "rpl_1", StateChangeRequest{Reason: "cancel"})
			return err
		}},
		{name: "provider reconciliation and recovery controls", run: func(ctx context.Context) error {
			if _, err := svc.CreateProviderConnection(ctx, actor, CreateProviderConnectionRequest{Name: "Stripe", Provider: "stripe", Credential: "sk_test_secret"}); err != nil {
				return err
			}
			if _, err := svc.ListProviderConnections(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.GetProviderConnection(ctx, actor, "pcn_1"); err != nil {
				return err
			}
			if _, err := svc.VerifyProviderConnection(ctx, actor, "pcn_1", ProviderConnectionStateRequest{Reason: "validated"}); err != nil {
				return err
			}
			if _, err := svc.RevokeProviderConnection(ctx, actor, "pcn_1", ProviderConnectionStateRequest{Reason: "rotate"}); err != nil {
				return err
			}
			if _, err := svc.DryRunReconciliation(ctx, actor, ReconciliationJobRequest{ConnectionID: "pcn_1", Reason: "inspect window"}); err != nil {
				return err
			}
			if _, err := svc.CreateReconciliationJob(ctx, actor, ReconciliationJobRequest{ConnectionID: "pcn_1", CaptureMissing: true, RouteRecovered: true, Reason: "recover"}); err != nil {
				return err
			}
			if _, err := svc.ListReconciliationJobs(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.GetReconciliationJob(ctx, actor, "rec_1"); err != nil {
				return err
			}
			if _, err := svc.ListReconciliationItems(ctx, actor, "rec_1", 10); err != nil {
				return err
			}
			_, err := svc.CancelReconciliationJob(ctx, actor, "rec_1", ProviderConnectionStateRequest{Reason: "stop"})
			return err
		}},
		{name: "transformations dead letter and quarantine", run: func(ctx context.Context) error {
			if _, err := svc.CreateTransformation(ctx, actor, CreateTransformationRequest{Name: "redact", Operations: json.RawMessage(`[{"op":"redact","path":"/data/email"}]`)}); err != nil {
				return err
			}
			if _, err := svc.ListTransformations(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.GetTransformation(ctx, actor, "trn_1"); err != nil {
				return err
			}
			if _, err := svc.CreateTransformationVersion(ctx, actor, "trn_1", CreateTransformationVersionRequest{Operations: json.RawMessage(`[{"op":"set","path":"/data/source","value":"webhookery"}]`)}); err != nil {
				return err
			}
			if _, err := svc.ListTransformationVersions(ctx, actor, "trn_1", 10); err != nil {
				return err
			}
			if _, err := svc.ActivateTransformationVersion(ctx, actor, "trn_1", "trv_1", ActivateTransformationVersionRequest{Reason: "publish"}); err != nil {
				return err
			}
			if _, err := svc.ListDeadLetter(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.ReleaseDeadLetter(ctx, actor, "dlq_1", DeadLetterReleaseRequest{ReasonCode: ReplayReasonReceiverFixed, Reason: "receiver fixed"}); err != nil {
				return err
			}
			if _, err := svc.BulkReleaseDeadLetter(ctx, actor, DeadLetterBulkReleaseRequest{EntryIDs: []string{"dlq_1", "dlq_2"}, ReasonCode: ReplayReasonIncidentRecovery, Reason: "incident recovery"}); err != nil {
				return err
			}
			if _, err := svc.ListQuarantine(ctx, actor, 10); err != nil {
				return err
			}
			if _, err := svc.ApproveQuarantine(ctx, actor, "qua_1", QuarantineDecisionRequest{Reason: "trusted after review", RouteAfterRelease: true}); err != nil {
				return err
			}
			_, err := svc.RejectQuarantine(ctx, actor, "qua_2", QuarantineDecisionRequest{Reason: "unsafe"})
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestControlServiceSchemaLifecycleRequiresSchemasWrite(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"schemas:read"}}
	state := domain.StateDeprecated

	_, err := svc.UpdateEventType(context.Background(), actor, "invoice.paid", UpdateEventTypeRequest{Description: ptrString("Invoice paid"), Reason: "describe"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden event type update, got %v", err)
	}
	_, err = svc.UpdateEventSchema(context.Background(), actor, "invoice.paid", "2026-05-01", UpdateEventSchemaRequest{State: &state, Reason: "deprecate"})
	if !errors.Is(err, ErrForbidden) {
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

func TestControlServiceUsesCentralAuthorizationForSourceRead(t *testing.T) {
	store := &policyDecisionStore{decision: authz.Decision{Allowed: false, Reason: "denied by access policy"}}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleOwner, Scopes: []string{"*"}}

	_, err := svc.GetSource(context.Background(), actor, "src_123")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected policy deny to forbid source read, got %v", err)
	}
	if store.sourceTenantID != "" {
		t.Fatal("source store must not be called after policy deny")
	}
	if store.lastTenantID != "ten_a" || store.lastActorID != "usr_1" || store.lastReq.Action != "sources:read" || store.lastReq.ResourceFamily != "source" || store.lastReq.ResourceID != "src_123" {
		t.Fatalf("unexpected authorization request: tenant=%q actor=%q req=%+v", store.lastTenantID, store.lastActorID, store.lastReq)
	}
}

func TestControlServiceSourceMutationRequiresSourcesWrite(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"sources:read"}}
	name := "renamed"

	_, err := svc.UpdateSource(context.Background(), actor, "src_123", UpdateSourceRequest{Name: &name, Reason: "rename"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden source update, got %v", err)
	}
	_, err = svc.DeleteSource(context.Background(), actor, "src_123", StateChangeRequest{Reason: "retire"})
	if !errors.Is(err, ErrForbidden) {
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
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden endpoint update, got %v", err)
	}
	_, err = svc.DeleteEndpoint(context.Background(), actor, "end_123", StateChangeRequest{Reason: "retire"})
	if !errors.Is(err, ErrForbidden) {
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

	_, err := svc.GetRawPayload(context.Background(), actor, "evt_123", "support investigation")
	if err != ErrForbidden {
		t.Fatalf("expected forbidden raw payload access, got %v", err)
	}
}

func TestControlServiceRequiresRawPayloadReason(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleOwner, Scopes: []string{"events:raw"}}

	_, err := svc.GetRawPayload(context.Background(), actor, "evt_123", "  ")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid input for missing raw payload reason, got %v", err)
	}
	if store.rawPayloadTenantID != "" {
		t.Fatalf("raw payload store called before reason validation: %+v", store)
	}
}

func TestControlServicePassesRawPayloadReasonToStore(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleOwner, Scopes: []string{"events:raw"}}

	_, err := svc.GetRawPayload(context.Background(), actor, " evt_123 ", " support case review ")
	if err != nil {
		t.Fatal(err)
	}
	if store.rawPayloadTenantID != "ten_a" || store.rawPayloadEventID != "evt_123" || store.rawPayloadActorID != "usr_1" || store.rawPayloadReason != "support case review" {
		t.Fatalf("raw payload store context mismatch: %+v", store)
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

	_, err := svc.CreateReplay(context.Background(), actor, ReplayRequest{EventID: "evt_1", ReasonCode: ReplayReasonReceiverFixed, Reason: "repair", ConfigMode: "future"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid config mode, got %v", err)
	}
	_, err = svc.CreateReplay(context.Background(), actor, ReplayRequest{EventID: "evt_1", ReasonCode: ReplayReasonReceiverFixed, Reason: "repair", ConfigMode: ReplayConfigOriginal, RateLimitPerMinute: -1})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid rate limit, got %v", err)
	}
	_, err = svc.CreateReplay(context.Background(), actor, ReplayRequest{EventID: "evt_1", Reason: "repair", ConfigMode: ReplayConfigOriginal})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected missing reason code rejection, got %v", err)
	}
	_, err = svc.CreateReplay(context.Background(), actor, ReplayRequest{EventID: "evt_1", ReasonCode: "because", Reason: "repair", ConfigMode: ReplayConfigOriginal})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid reason code rejection, got %v", err)
	}
	approvalExpiresAt := time.Now().UTC().Add(time.Hour)
	_, err = svc.CreateReplay(context.Background(), actor, ReplayRequest{EventID: "evt_1", ReasonCode: ReplayReasonReceiverFixed, Reason: "repair", ApprovalExpiresAt: &approvalExpiresAt})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected approval expiry without approval rejection, got %v", err)
	}
	expiredApproval := time.Now().UTC().Add(-time.Hour)
	_, err = svc.CreateReplay(context.Background(), actor, ReplayRequest{EventID: "evt_1", ReasonCode: ReplayReasonReceiverFixed, Reason: "repair", RequireApproval: true, ApprovalExpiresAt: &expiredApproval})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected expired approval window rejection, got %v", err)
	}
	_, err = svc.DryRunReplay(context.Background(), actor, ReplayRequest{EventID: "evt_1", Reason: "repair", ConfigMode: ReplayConfigOriginal})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected dry-run missing reason code rejection, got %v", err)
	}
}

func TestControlServiceReplayApprovalValidationAndTenantScope(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"replay:write", "replay:read"}}

	job, err := svc.CreateReplay(context.Background(), actor, ReplayRequest{EventID: "evt_1", ReasonCode: ReplayReasonIncidentRecovery, Reason: "repair", RequireApproval: true})
	if err != nil {
		t.Fatalf("expected replay creation to succeed, got %v", err)
	}
	if !store.replayReq.RequireApproval || !job.ApprovalRequired {
		t.Fatalf("expected approval requirement to propagate, req=%+v job=%+v", store.replayReq, job)
	}
	if store.replayReq.ApprovalExpiresAt == nil || job.ApprovalExpiresAt == nil {
		t.Fatalf("expected approval expiry to default and propagate, req=%+v job=%+v", store.replayReq, job)
	}
	if store.replayReq.ReasonCode != ReplayReasonIncidentRecovery || job.ReasonCode != ReplayReasonIncidentRecovery || job.Reason != "repair" {
		t.Fatalf("expected reason code and reason to propagate, req=%+v job=%+v", store.replayReq, job)
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

	approver := authz.Actor{ID: "usr_3", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"replay:write", "replay:read"}}
	_, err = svc.ApproveReplayJob(context.Background(), approver, "rpl_1", StateChangeRequest{Reason: "approved"})
	if err != nil {
		t.Fatalf("expected approval to succeed, got %v", err)
	}
	if store.approveReplayTenantID != "ten_a" || store.approveReplayActorID != "usr_3" || store.approveReplayReason != "approved" {
		t.Fatalf("approval was not tenant-scoped with reason: tenant=%q actor=%q reason=%q", store.approveReplayTenantID, store.approveReplayActorID, store.approveReplayReason)
	}
}

func TestControlServiceReplayApprovalPoliciesValidateAndScope(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	admin := authz.Actor{ID: "usr_sec", TenantID: "ten_a", Role: authz.RoleSecurity, Scopes: []string{"security:write", "security:read"}}

	policy, err := svc.CreateReplayApprovalPolicy(context.Background(), admin, CreateReplayApprovalPolicyRequest{ScopeType: ReplayApprovalScopeRoute, ScopeID: "rte_1", Reason: "sensitive route"})
	if err != nil {
		t.Fatalf("expected policy creation to succeed, got %v", err)
	}
	if policy.TenantID != "ten_a" || policy.ScopeType != ReplayApprovalScopeRoute || policy.ScopeID != "rte_1" || !policy.RequireApproval || policy.DefaultExpirySeconds != int(ReplayApprovalDefaultExpiry/time.Second) {
		t.Fatalf("policy was not normalized or tenant-scoped: %+v", policy)
	}
	if store.replayApprovalPolicyReq.ScopeType != ReplayApprovalScopeRoute || store.replayApprovalPolicyReq.ScopeID != "rte_1" || store.replayApprovalPolicyActorID != "usr_sec" {
		t.Fatalf("policy request was not propagated: %+v actor=%q", store.replayApprovalPolicyReq, store.replayApprovalPolicyActorID)
	}

	_, err = svc.CreateReplayApprovalPolicy(context.Background(), admin, CreateReplayApprovalPolicyRequest{ScopeType: ReplayApprovalScopeSource, Reason: "missing source"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected source scope_id validation, got %v", err)
	}
	_, err = svc.CreateReplayApprovalPolicy(context.Background(), admin, CreateReplayApprovalPolicyRequest{ScopeType: ReplayApprovalScopeTenant, DefaultExpirySeconds: 60, Reason: "too short"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected default expiry bounds validation, got %v", err)
	}

	readOnly := authz.Actor{ID: "usr_read", TenantID: "ten_a", Role: authz.RoleAuditor, Scopes: []string{"security:read"}}
	_, err = svc.CreateReplayApprovalPolicy(context.Background(), readOnly, CreateReplayApprovalPolicyRequest{ScopeType: ReplayApprovalScopeTenant, Reason: "no write"})
	if err != ErrForbidden {
		t.Fatalf("expected security write requirement, got %v", err)
	}

	if _, err := svc.ListReplayApprovalPolicies(context.Background(), readOnly, 10); err != nil {
		t.Fatalf("expected security read list to succeed, got %v", err)
	}
	if store.replayApprovalPolicyTenantID != "ten_a" {
		t.Fatalf("policy list was not tenant-scoped: %q", store.replayApprovalPolicyTenantID)
	}

	disabled, err := svc.DisableReplayApprovalPolicy(context.Background(), admin, "rap_1", StateChangeRequest{Reason: "route is no longer sensitive"})
	if err != nil {
		t.Fatalf("expected policy disable to succeed, got %v", err)
	}
	if disabled.State != domain.StateDisabled || store.replayApprovalPolicyID != "rap_1" || store.replayApprovalPolicyReason != "route is no longer sensitive" {
		t.Fatalf("policy disable was not propagated: policy=%+v store=%+v", disabled, store)
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

func TestControlServiceProducerClientsRequireSecurityWriteAndRedactSecrets(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	reader := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAuditor, Scopes: []string{"security:read"}}
	security := authz.Actor{ID: "usr_2", TenantID: "ten_a", Role: authz.RoleSecurity, Scopes: []string{"security:write", "security:read"}}

	_, err := svc.CreateProducerClient(context.Background(), reader, CreateProducerClientRequest{Name: "billing", Scopes: []string{"events:write"}})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden producer client create, got %v", err)
	}
	created, err := svc.CreateProducerClient(context.Background(), security, CreateProducerClientRequest{Name: "billing", SourceID: "src_1", Scopes: []string{"events:write"}, TokenTTLSeconds: 900})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(created.Client)
	if err != nil {
		t.Fatal(err)
	}
	if created.ClientSecret == "" || created.Client.TenantID != "ten_a" || store.producerClientTenantID != "ten_a" || store.producerClientActorID != "usr_2" {
		t.Fatalf("expected tenant-scoped producer client with one-time secret, created=%+v tenant=%q actor=%q", created, store.producerClientTenantID, store.producerClientActorID)
	}
	if store.producerClientInput.Secret.Hash == "" || strings.Contains(string(raw), store.producerClientInput.Secret.Hash) || strings.Contains(string(raw), created.ClientSecret) {
		t.Fatalf("producer client response exposed credential material: json=%s input=%+v", raw, store.producerClientInput)
	}
	rotated, err := svc.RotateProducerClientSecret(context.Background(), security, "pcl_1", RotateProducerClientSecretRequest{Reason: "rotation"})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ClientSecret == "" || rotated.Secret.Hash != "" || store.producerClientReason != "rotation" {
		t.Fatalf("expected secret rotation metadata without hash, rotated=%+v reason=%q", rotated, store.producerClientReason)
	}
}

func TestControlServiceProducerClientManagementScopesTenantAndRequiresReasons(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	reader := authz.Actor{ID: "usr_reader", TenantID: "ten_a", Role: authz.RoleAuditor, Scopes: []string{"security:read"}}
	security := authz.Actor{ID: "usr_sec", TenantID: "ten_a", Role: authz.RoleSecurity, Scopes: []string{"security:write", "security:read"}}

	clients, err := svc.ListProducerClients(context.Background(), reader, 250)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].TenantID != "ten_a" || store.producerClientTenantID != "ten_a" {
		t.Fatalf("producer client list was not tenant scoped: clients=%+v tenant=%q", clients, store.producerClientTenantID)
	}
	client, err := svc.GetProducerClient(context.Background(), reader, "pcl_1")
	if err != nil {
		t.Fatal(err)
	}
	if client.ID != "pcl_1" || client.TenantID != "ten_a" {
		t.Fatalf("producer client get did not round trip tenant/id: %+v", client)
	}
	if _, err := svc.GetProducerClient(context.Background(), reader, " "); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected blank producer client id to be invalid, got %v", err)
	}
	if _, err := svc.UpdateProducerClient(context.Background(), security, "pcl_1", UpdateProducerClientRequest{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected update without reason/fields to be invalid, got %v", err)
	}
	name := "billing producer"
	ttl := 1200
	updated, err := svc.UpdateProducerClient(context.Background(), security, "pcl_1", UpdateProducerClientRequest{Name: &name, TokenTTLSeconds: &ttl, Scopes: []string{"events:write"}, Reason: "rotate owner"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != "pcl_1" || store.producerClientActorID != "usr_sec" || store.producerClientReason != "rotate owner" {
		t.Fatalf("producer client update was not scoped with reason: updated=%+v actor=%q reason=%q", updated, store.producerClientActorID, store.producerClientReason)
	}
	if _, err := svc.UpdateProducerClient(context.Background(), security, "pcl_1", UpdateProducerClientRequest{Scopes: []string{"events:read"}, Reason: "bad scope"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected unsupported producer scope to be invalid, got %v", err)
	}
	disabled, err := svc.DeleteProducerClient(context.Background(), security, "pcl_1", StateChangeRequest{Reason: "offboard producer"})
	if err != nil {
		t.Fatal(err)
	}
	if disabled.State != domain.StateDisabled || store.producerClientReason != "offboard producer" {
		t.Fatalf("producer client delete was not scoped with reason: disabled=%+v reason=%q", disabled, store.producerClientReason)
	}
}

func TestControlServiceUsesCentralAuthorizationForProducerSecretRotation(t *testing.T) {
	store := &policyDecisionStore{decision: authz.Decision{Allowed: false, Reason: "denied by access policy"}}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleOwner, Scopes: []string{"*"}}

	_, err := svc.RotateProducerClientSecret(context.Background(), actor, "pcl_1", RotateProducerClientSecretRequest{Reason: "rotate compromised secret"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected policy deny to forbid producer secret rotation, got %v", err)
	}
	if store.producerClientTenantID != "" || store.producerClientReason != "" {
		t.Fatal("producer client store must not be called after policy deny")
	}
	if store.lastReq.Action != "security:write" || store.lastReq.ResourceFamily != "producer_client" || store.lastReq.ResourceID != "pcl_1" {
		t.Fatalf("unexpected authorization request: %+v", store.lastReq)
	}
}

func TestControlServiceResourcePoliciesDenySensitiveOperations(t *testing.T) {
	cases := []struct {
		name       string
		run        func(*ControlService, authz.Actor) error
		wantAction string
		wantFamily string
		wantID     string
		wantEnv    string
	}{
		{
			name: "raw payload read", wantAction: "events:raw", wantFamily: "event", wantID: "evt_raw",
			run: func(svc *ControlService, actor authz.Actor) error {
				_, err := svc.GetRawPayload(context.Background(), actor, "evt_raw", "support investigation")
				return err
			},
		},
		{
			name: "replay creation", wantAction: "replay:write", wantFamily: "replay", wantID: "evt_replay",
			run: func(svc *ControlService, actor authz.Actor) error {
				_, err := svc.CreateReplay(context.Background(), actor, ReplayRequest{EventID: "evt_replay", ReasonCode: ReplayReasonSupportInvestigation, Reason: "investigate"})
				return err
			},
		},
		{
			name: "audit export payload inclusion", wantAction: "events:raw", wantFamily: "audit_export",
			run: func(svc *ControlService, actor authz.Actor) error {
				_, err := svc.CreateAuditExport(context.Background(), actor, CreateAuditExportRequest{IncludePayloadBodies: true, Reason: "export evidence"})
				return err
			},
		},
		{
			name: "endpoint production change", wantAction: "endpoints:write", wantFamily: "endpoint", wantID: "end_prod", wantEnv: "production",
			run: func(svc *ControlService, actor authz.Actor) error {
				_, _, err := svc.UpdateEndpoint(context.Background(), actor, "end_prod", UpdateEndpointRequest{Name: ptrString("prod receiver"), Reason: "rename"})
				return err
			},
		},
		{
			name: "notification mutation", wantAction: "ops:write", wantFamily: "notification_channel", wantID: "nch_1",
			run: func(svc *ControlService, actor authz.Actor) error {
				_, _, err := svc.UpdateNotificationChannel(context.Background(), actor, "nch_1", UpdateNotificationChannelRequest{Name: ptrString("ops"), Reason: "rename"})
				return err
			},
		},
		{
			name: "siem mutation", wantAction: "security:write", wantFamily: "siem_sink", wantID: "snk_1",
			run: func(svc *ControlService, actor authz.Actor) error {
				_, _, err := svc.UpdateSIEMSink(context.Background(), actor, "snk_1", UpdateSIEMSinkRequest{Name: ptrString("siem"), Reason: "rename"})
				return err
			},
		},
		{
			name: "secret rotation", wantAction: "security:write", wantFamily: "producer_client", wantID: "pcl_1",
			run: func(svc *ControlService, actor authz.Actor) error {
				_, err := svc.RotateProducerClientSecret(context.Background(), actor, "pcl_1", RotateProducerClientSecretRequest{Reason: "rotate"})
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &policyDecisionStore{
				decide: func(tenantID, _ string, req AuthzExplainRequest) (authz.Decision, error) {
					return testAuthorizationDecision(tenantID, req, req.Action == "audit:read"), nil
				},
			}
			svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{"receiver.example": {netip.MustParseAddr("93.184.216.34")}}})
			actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleOwner, Scopes: []string{"*"}}

			err := tc.run(svc, actor)
			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("expected forbidden from policy deny, got %v", err)
			}
			if store.lastReq.Action != tc.wantAction || store.lastReq.ResourceFamily != tc.wantFamily || store.lastReq.ResourceID != tc.wantID || store.lastReq.Environment != tc.wantEnv {
				t.Fatalf("unexpected authorization request: got %+v want action=%q family=%q id=%q env=%q", store.lastReq, tc.wantAction, tc.wantFamily, tc.wantID, tc.wantEnv)
			}
		})
	}
}

func TestControlServiceResourcePolicyAllowsBindingAndPreservesScopeLimit(t *testing.T) {
	store := &policyDecisionStore{
		decide: func(tenantID, _ string, req AuthzExplainRequest) (authz.Decision, error) {
			return testAuthorizationDecision(tenantID, req, true), nil
		},
	}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{"receiver.example": {netip.MustParseAddr("93.184.216.34")}}})
	boundActor := authz.Actor{ID: "usr_binding", TenantID: "ten_a", Role: authz.RoleSupport, Scopes: []string{"endpoints:write"}}
	rawURL := "https://receiver.example/hook"

	_, result, err := svc.UpdateEndpoint(context.Background(), boundActor, "end_1", UpdateEndpointRequest{URL: &rawURL, Reason: "resource binding allows endpoint change"})
	if err != nil {
		t.Fatalf("expected resource binding allow, got %v", err)
	}
	if !result.Allowed || store.endpointTenantID != "ten_a" || store.endpointID != "end_1" {
		t.Fatalf("expected tenant-scoped endpoint update after binding allow, result=%+v tenant=%q endpoint=%q", result, store.endpointTenantID, store.endpointID)
	}

	scopeLimited := authz.Actor{ID: "usr_limited", TenantID: "ten_a", Role: authz.RoleOwner, Scopes: []string{"events:read"}}
	_, err = svc.GetRawPayload(context.Background(), scopeLimited, "evt_1", "support investigation")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected actor scope to limit enterprise allow, got %v", err)
	}
}

func TestControlServiceExplainAuthorizationOmitsSensitiveAttributes(t *testing.T) {
	store := &policyDecisionStore{
		decide: func(tenantID, _ string, req AuthzExplainRequest) (authz.Decision, error) {
			decision := testAuthorizationDecision(tenantID, req, true)
			decision.Resource.Attributes = req.Attributes
			return decision, nil
		},
	}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleSecurity, Scopes: []string{"security:read"}}
	decision, err := svc.ExplainAuthorization(context.Background(), actor, AuthzExplainRequest{
		Action:         "events:raw",
		ResourceFamily: "event",
		ResourceID:     "evt_1",
		Attributes: map[string]string{
			"payload_body":   `{"token":"payload-secret-value"}`,
			"session_token":  "sess_secret_value",
			"provider_token": "ghp_secret_value",
			"webhook_secret": "whsec_secret_value",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.Resource.Attributes) != 0 {
		t.Fatalf("expected explain response attributes to be omitted, got %+v", decision.Resource.Attributes)
	}
	raw, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"payload-secret-value", "sess_secret_value", "ghp_secret_value", "whsec_secret_value"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("explain output leaked sensitive value %q: %s", secret, raw)
		}
	}
}

func TestControlServiceProducerMTLSIdentitiesValidateCertAndScopeTenant(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	reader := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAuditor, Scopes: []string{"security:read"}}
	security := authz.Actor{ID: "usr_2", TenantID: "ten_a", Role: authz.RoleSecurity, Scopes: []string{"security:write", "security:read"}}
	certPEM, _ := testClientCertificatePEM(t, "Webhookery Producer Client")

	_, err := svc.CreateProducerMTLSIdentity(context.Background(), reader, CreateProducerMTLSIdentityRequest{Name: "billing", CertificatePEM: certPEM})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden producer mTLS create, got %v", err)
	}
	_, err = svc.CreateProducerMTLSIdentity(context.Background(), security, CreateProducerMTLSIdentityRequest{Name: "billing", CertificatePEM: "not a cert"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid certificate error, got %v", err)
	}
	identity, err := svc.CreateProducerMTLSIdentity(context.Background(), security, CreateProducerMTLSIdentityRequest{Name: "billing", SourceID: "src_1", CertificatePEM: certPEM})
	if err != nil {
		t.Fatal(err)
	}
	if identity.TenantID != "ten_a" || identity.CertificateFingerprintSHA256 == "" || store.producerMTLSTenantID != "ten_a" || store.producerMTLSActorID != "usr_2" {
		t.Fatalf("expected tenant-scoped producer mTLS identity, identity=%+v tenant=%q actor=%q", identity, store.producerMTLSTenantID, store.producerMTLSActorID)
	}
	verified, err := svc.VerifyProducerMTLSIdentity(context.Background(), security, identity.ID, VerifyProducerMTLSIdentityRequest{CertificatePEM: certPEM})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Matched {
		t.Fatalf("expected certificate verification to match stored fingerprint: %+v", verified)
	}
}

func TestControlServiceProducerMTLSManagementScopesTenantAndRequiresReasons(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	reader := authz.Actor{ID: "usr_reader", TenantID: "ten_a", Role: authz.RoleAuditor, Scopes: []string{"security:read"}}
	security := authz.Actor{ID: "usr_sec", TenantID: "ten_a", Role: authz.RoleSecurity, Scopes: []string{"security:write", "security:read"}}

	identities, err := svc.ListProducerMTLSIdentities(context.Background(), reader, 250)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 1 || identities[0].TenantID != "ten_a" || store.producerMTLSTenantID != "ten_a" {
		t.Fatalf("producer mTLS list was not tenant scoped: identities=%+v tenant=%q", identities, store.producerMTLSTenantID)
	}
	identity, err := svc.GetProducerMTLSIdentity(context.Background(), reader, "pmi_1")
	if err != nil {
		t.Fatal(err)
	}
	if identity.ID != "pmi_1" || identity.TenantID != "ten_a" {
		t.Fatalf("producer mTLS get did not round trip tenant/id: %+v", identity)
	}
	if _, err := svc.GetProducerMTLSIdentity(context.Background(), reader, " "); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected blank mTLS identity id to be invalid, got %v", err)
	}
	if _, err := svc.UpdateProducerMTLSIdentity(context.Background(), security, "pmi_1", UpdateProducerMTLSIdentityRequest{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected update without reason/fields to be invalid, got %v", err)
	}
	name := "renamed certificate"
	updated, err := svc.UpdateProducerMTLSIdentity(context.Background(), security, "pmi_1", UpdateProducerMTLSIdentityRequest{Name: &name, Reason: "certificate owner changed"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != "pmi_1" || store.producerMTLSActorID != "usr_sec" || store.producerMTLSReason != "certificate owner changed" {
		t.Fatalf("producer mTLS update was not scoped with reason: updated=%+v actor=%q reason=%q", updated, store.producerMTLSActorID, store.producerMTLSReason)
	}
	disabled, err := svc.DeleteProducerMTLSIdentity(context.Background(), security, "pmi_1", StateChangeRequest{Reason: "certificate retired"})
	if err != nil {
		t.Fatal(err)
	}
	if disabled.State != domain.StateDisabled || store.producerMTLSReason != "certificate retired" {
		t.Fatalf("producer mTLS delete was not scoped with reason: disabled=%+v reason=%q", disabled, store.producerMTLSReason)
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

func TestControlServiceAdapterRegistryRequiresSecurityWriteAndScopesTenant(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	reader := authz.Actor{ID: "usr_reader", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"sources:read"}}
	security := authz.Actor{ID: "usr_sec", TenantID: "ten_a", Role: authz.RoleSecurity, Scopes: []string{"security:write", "sources:read"}}

	_, err := svc.CreateProviderAdapter(context.Background(), reader, CreateProviderAdapterRequest{Name: "acme", Kind: domain.AdapterKindDeclarative})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden adapter create, got %v", err)
	}
	adapter, err := svc.CreateProviderAdapter(context.Background(), security, CreateProviderAdapterRequest{Name: "Acme-HMAC", Kind: domain.AdapterKindDeclarative})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.Name != "acme-hmac" || store.adapterTenantID != "ten_a" || store.adapterActorID != "usr_sec" {
		t.Fatalf("adapter create was not normalized and tenant scoped: adapter=%+v tenant=%q actor=%q", adapter, store.adapterTenantID, store.adapterActorID)
	}
}

func TestControlServiceAdapterVersionRejectsSecretFields(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	security := authz.Actor{ID: "usr_sec", TenantID: "ten_a", Role: authz.RoleSecurity, Scopes: []string{"security:write"}}

	_, err := svc.CreateAdapterVersion(context.Background(), security, "pad_1", CreateAdapterVersionRequest{
		Version:    "2026-05-01",
		Definition: json.RawMessage(`{"verification":{"type":"hmac_sha256","client_secret":"leak"}}`),
		Reason:     "upload",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected secret field rejection, got %v", err)
	}
	_, err = svc.CreateAdapterVersion(context.Background(), security, "pad_1", CreateAdapterVersionRequest{
		Version:    "2026-05-01",
		Definition: json.RawMessage(`{"verification":{"type":"hmac_sha256","signature_header":"X-Acme-Signature"}}`),
		Reason:     "upload",
	})
	if err != nil {
		t.Fatalf("expected adapter version create, got %v", err)
	}
	if store.adapterVersionReq.Version != "2026-05-01" || store.adapterTenantID != "ten_a" {
		t.Fatalf("adapter version not passed through tenant boundary: req=%+v tenant=%q", store.adapterVersionReq, store.adapterTenantID)
	}
}

func TestControlServiceAdapterRegistryReadVectorsAndTransitions(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	reader := authz.Actor{ID: "usr_reader", TenantID: "ten_a", Role: authz.RoleDeveloper, Scopes: []string{"sources:read"}}
	security := authz.Actor{ID: "usr_sec", TenantID: "ten_a", Role: authz.RoleSecurity, Scopes: []string{"security:write", "sources:read"}}

	adapters, err := svc.ListProviderAdapters(context.Background(), reader, 250)
	if err != nil {
		t.Fatal(err)
	}
	if len(adapters) != 1 || adapters[0].TenantID != "ten_a" || store.adapterTenantID != "ten_a" {
		t.Fatalf("adapter list was not tenant scoped: adapters=%+v tenant=%q", adapters, store.adapterTenantID)
	}
	adapter, err := svc.GetProviderAdapter(context.Background(), reader, "pad_1")
	if err != nil {
		t.Fatal(err)
	}
	if adapter.ID != "pad_1" || adapter.TenantID != "ten_a" {
		t.Fatalf("adapter get did not round trip tenant/id: %+v", adapter)
	}
	if _, err := svc.GetProviderAdapter(context.Background(), reader, " "); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected blank adapter id to be invalid, got %v", err)
	}
	versions, err := svc.ListAdapterVersions(context.Background(), reader, "pad_1", 250)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || versions[0].AdapterID != "pad_1" {
		t.Fatalf("adapter version list did not scope by adapter: %+v", versions)
	}
	if _, err := svc.ListAdapterVersions(context.Background(), reader, "", 10); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected blank adapter id to be invalid for versions, got %v", err)
	}

	vectorReq := CreateAdapterTestVectorRequest{
		Name:     " valid vector ",
		Request:  json.RawMessage(`{"headers":{"x-acme-signature":"sig"},"body":"{}"}`),
		Expected: json.RawMessage(`{"type":"invoice.created"}`),
	}
	vector, err := svc.CreateAdapterTestVector(context.Background(), security, "pad_1", "adv_1", vectorReq)
	if err != nil {
		t.Fatal(err)
	}
	if vector.Name != "valid vector" || vector.TenantID != "ten_a" || vector.CreatedBy != "usr_sec" {
		t.Fatalf("adapter test vector was not normalized/scoped: %+v", vector)
	}
	if _, err := svc.CreateAdapterTestVector(context.Background(), reader, "pad_1", "adv_1", vectorReq); err != ErrForbidden {
		t.Fatalf("expected non-security writer to be forbidden, got %v", err)
	}
	if _, err := svc.CreateAdapterTestVector(context.Background(), security, "", "adv_1", vectorReq); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected missing adapter id to be invalid, got %v", err)
	}
	if _, err := svc.CreateAdapterTestVector(context.Background(), security, "pad_1", "adv_1", CreateAdapterTestVectorRequest{Name: "bad", Request: json.RawMessage(`{"token":"leak"}`), Expected: json.RawMessage(`{"ok":true}`)}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected secret-bearing vector to be invalid, got %v", err)
	}
	if _, err := svc.CreateAdapterTestVector(context.Background(), security, "pad_1", "adv_1", CreateAdapterTestVectorRequest{Name: "bad", Request: json.RawMessage(`{`), Expected: json.RawMessage(`{"ok":true}`)}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected malformed vector JSON to be invalid, got %v", err)
	}

	if _, err := svc.TransitionAdapterVersion(context.Background(), security, "pad_1", "adv_1", AdapterVersionTransitionRequest{Action: "activate"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected missing transition reason to be invalid, got %v", err)
	}
	if _, err := svc.TransitionAdapterVersion(context.Background(), security, "pad_1", "adv_1", AdapterVersionTransitionRequest{Action: "ship", Reason: "release"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected unsupported transition to be invalid, got %v", err)
	}
	if _, err := svc.TransitionAdapterVersion(context.Background(), security, "pad_1", "adv_1", AdapterVersionTransitionRequest{Action: "submit_tests", Reason: "tests", TestResults: json.RawMessage(`{`)}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected malformed test results to be invalid, got %v", err)
	}
	transitioned, err := svc.TransitionAdapterVersion(context.Background(), security, "pad_1", "adv_1", AdapterVersionTransitionRequest{Action: "activate", Reason: "approved for production", TestResults: json.RawMessage(`{"passed":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if transitioned.ID != "adv_1" || transitioned.TenantID != "ten_a" || store.adapterActorID != "usr_sec" {
		t.Fatalf("adapter transition was not tenant/actor scoped: version=%+v actor=%q", transitioned, store.adapterActorID)
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

func TestControlServiceNotificationChannelsRequireOpsWriteSSRFAndRedactSecrets(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{
		"signals.example": {netip.MustParseAddr("93.184.216.34")},
	}})
	reader := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleOperator, Scopes: []string{"ops:read"}}
	operator := authz.Actor{ID: "usr_2", TenantID: "ten_a", Role: authz.RoleOperator, Scopes: []string{"ops:write", "ops:read"}}

	_, _, err := svc.CreateNotificationChannel(context.Background(), reader, CreateNotificationChannelRequest{Name: "pager", URL: "https://signals.example/hook", SigningSecret: "0123456789abcdef"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden notification channel create, got %v", err)
	}
	_, result, err := svc.CreateNotificationChannel(context.Background(), operator, CreateNotificationChannelRequest{Name: "bad", URL: "http://169.254.169.254/latest", SigningSecret: "0123456789abcdef"})
	if !errors.Is(err, ErrInvalidInput) || result.Allowed {
		t.Fatalf("expected SSRF rejection, result=%+v err=%v", result, err)
	}
	channel, result, err := svc.CreateNotificationChannel(context.Background(), operator, CreateNotificationChannelRequest{Name: "pager", URL: "https://signals.example/hook", SigningSecret: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(channel)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed || channel.TenantID != "ten_a" || store.notificationTenantID != "ten_a" || store.notificationActorID != "usr_2" {
		t.Fatalf("expected tenant-scoped channel create, channel=%+v tenant=%q actor=%q result=%+v", channel, store.notificationTenantID, store.notificationActorID, result)
	}
	if strings.Contains(string(raw), "0123456789abcdef") {
		t.Fatalf("notification channel response exposed signing secret: %s", raw)
	}
}

func TestControlServiceNotificationDeliveryAccessRequiresOpsScopes(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{
		"signals.example": {netip.MustParseAddr("93.184.216.34")},
	}})
	reader := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleOperator, Scopes: []string{"ops:read"}}
	operator := authz.Actor{ID: "usr_2", TenantID: "ten_a", Role: authz.RoleOperator, Scopes: []string{"ops:write", "ops:read"}}

	_, err := svc.RetryNotificationDelivery(context.Background(), reader, "ndel_1", StateChangeRequest{Reason: "retry"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden notification retry, got %v", err)
	}
	_, err = svc.RetryNotificationDelivery(context.Background(), operator, "ndel_1", StateChangeRequest{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected notification retry reason validation, got %v", err)
	}
	deliveries, err := svc.ListNotificationDeliveries(context.Background(), reader, domain.SignalDeliveryScheduled, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 || deliveries[0].TenantID != "ten_a" || store.notificationTenantID != "ten_a" {
		t.Fatalf("expected tenant-scoped notification delivery list, deliveries=%+v tenant=%q", deliveries, store.notificationTenantID)
	}
}

func TestControlServiceSIEMSinksRequireSecurityWriteAndAuditRead(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{
		"siem.example": {netip.MustParseAddr("93.184.216.34")},
	}})
	auditor := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleAuditor, Scopes: []string{"audit:read"}}
	security := authz.Actor{ID: "usr_2", TenantID: "ten_a", Role: authz.RoleSecurity, Scopes: []string{"security:write", "audit:read"}}

	_, _, err := svc.CreateSIEMSink(context.Background(), auditor, CreateSIEMSinkRequest{Name: "siem", URL: "https://siem.example/ingest", SigningSecret: "0123456789abcdef"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden SIEM create, got %v", err)
	}
	_, result, err := svc.CreateSIEMSink(context.Background(), security, CreateSIEMSinkRequest{Name: "bad", URL: "http://169.254.169.254/latest", SigningSecret: "0123456789abcdef"})
	if !errors.Is(err, ErrInvalidInput) || result.Allowed {
		t.Fatalf("expected SIEM SSRF rejection, result=%+v err=%v", result, err)
	}
	sink, result, err := svc.CreateSIEMSink(context.Background(), security, CreateSIEMSinkRequest{Name: "siem", URL: "https://siem.example/ingest", SigningSecret: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(sink)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed || sink.TenantID != "ten_a" || store.siemTenantID != "ten_a" || store.siemActorID != "usr_2" {
		t.Fatalf("expected tenant-scoped SIEM create, sink=%+v tenant=%q actor=%q result=%+v", sink, store.siemTenantID, store.siemActorID, result)
	}
	if strings.Contains(string(raw), "0123456789abcdef") {
		t.Fatalf("SIEM sink response exposed signing secret: %s", raw)
	}
	_, err = svc.ListSIEMSinks(context.Background(), auditor, 10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestControlServiceSIEMDeliveriesRequireAuditReadAndSecurityRetry(t *testing.T) {
	store := &fakeControlStore{}
	svc := NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
	operator := authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleOperator, Scopes: []string{"ops:read"}}
	auditor := authz.Actor{ID: "usr_2", TenantID: "ten_a", Role: authz.RoleAuditor, Scopes: []string{"audit:read"}}
	security := authz.Actor{ID: "usr_3", TenantID: "ten_a", Role: authz.RoleSecurity, Scopes: []string{"security:write", "audit:read"}}

	_, err := svc.ListSIEMDeliveries(context.Background(), operator, "", 10)
	if err != ErrForbidden {
		t.Fatalf("expected forbidden SIEM delivery list, got %v", err)
	}
	deliveries, err := svc.ListSIEMDeliveries(context.Background(), auditor, domain.SignalDeliveryScheduled, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 || deliveries[0].TenantID != "ten_a" || store.siemTenantID != "ten_a" {
		t.Fatalf("expected tenant-scoped SIEM delivery list, deliveries=%+v tenant=%q", deliveries, store.siemTenantID)
	}
	_, err = svc.RetrySIEMDelivery(context.Background(), auditor, "sdel_1", StateChangeRequest{Reason: "retry"})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden SIEM retry, got %v", err)
	}
	_, err = svc.RetrySIEMDelivery(context.Background(), security, "sdel_1", StateChangeRequest{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected SIEM retry reason validation, got %v", err)
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
	eventTenantID                string
	eventSearchTenantID          string
	eventSearchReq               EventSearchRequest
	incidentTenantID             string
	incidentActorID              string
	incidentID                   string
	incidentEventID              string
	incidentReason               string
	auditExportTenantID          string
	auditExport                  domain.EvidenceExport
	auditExportDownloaded        bool
	auditExports                 []domain.EvidenceExport
	apiKeyInput                  APIKeyCreateInput
	producerClientTenantID       string
	producerClientActorID        string
	producerClientReason         string
	producerClientInput          ProducerClientCreateInput
	producerMTLSTenantID         string
	producerMTLSActorID          string
	producerMTLSReason           string
	producerMTLSIdentity         domain.ProducerMTLSIdentity
	eventSchema                  domain.EventSchema
	schemaTenantID               string
	schemaReason                 string
	retryPolicyTenantID          string
	retryPolicyID                string
	retryPolicyReq               UpdateRetryPolicyRequest
	normalizedTenantID           string
	normalizedMetadataOnly       bool
	rawPayloadTenantID           string
	rawPayloadEventID            string
	rawPayloadActorID            string
	rawPayloadReason             string
	sourceTenantID               string
	sourceID                     string
	sourceReason                 string
	endpointTenantID             string
	endpointID                   string
	endpointReason               string
	subscriptionTenantID         string
	subscriptionID               string
	subscriptionReason           string
	subscription                 domain.Subscription
	routeTenantID                string
	routeID                      string
	routeReason                  string
	route                        domain.Route
	transformationTenantID       string
	providerConnectionTenantID   string
	providerConnectionReq        CreateProviderConnectionRequest
	adapterTenantID              string
	adapterActorID               string
	adapterVersionReq            CreateAdapterVersionRequest
	reconciliationTenantID       string
	opsTenantID                  string
	metricName                   string
	alertTenantID                string
	alertActorID                 string
	notificationTenantID         string
	notificationActorID          string
	siemTenantID                 string
	siemActorID                  string
	replayReq                    ReplayRequest
	approveReplayTenantID        string
	approveReplayActorID         string
	approveReplayReason          string
	replayApprovalPolicyTenantID string
	replayApprovalPolicyActorID  string
	replayApprovalPolicyID       string
	replayApprovalPolicyReason   string
	replayApprovalPolicyReq      CreateReplayApprovalPolicyRequest
	endpoint                     domain.Endpoint
}

type policyDecisionStore struct {
	enterpriseFakeStore
	decision     authz.Decision
	err          error
	decide       func(tenantID, actorID string, req AuthzExplainRequest) (authz.Decision, error)
	lastTenantID string
	lastActorID  string
	lastReq      AuthzExplainRequest
	calls        []AuthzExplainRequest
}

func (s *policyDecisionStore) ExplainAuthorization(_ context.Context, tenantID, actorID string, req AuthzExplainRequest) (authz.Decision, error) {
	s.lastTenantID = tenantID
	s.lastActorID = actorID
	s.lastReq = req
	s.calls = append(s.calls, req)
	if s.err != nil {
		return authz.Decision{}, s.err
	}
	if s.decide != nil {
		return s.decide(tenantID, actorID, req)
	}
	return s.decision, nil
}

func testAuthorizationDecision(tenantID string, req AuthzExplainRequest, allowed bool) authz.Decision {
	decision := authz.Decision{
		Allowed: allowed,
		Action:  req.Action,
		Resource: authz.Resource{
			TenantID:    tenantID,
			Family:      req.ResourceFamily,
			ID:          req.ResourceID,
			Environment: req.Environment,
		},
		RequiredScopes: []string{req.Action},
	}
	if allowed {
		decision.Reason = "allowed by resource role binding"
		decision.MatchedRoleBindingID = "rb_1"
		return decision
	}
	decision.Reason = "denied by access policy"
	decision.MatchedPolicyRuleID = "pol_1"
	return decision
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
func (f *fakeControlStore) CreateProducerClient(_ context.Context, input ProducerClientCreateInput) (domain.ProducerClient, error) {
	f.producerClientInput = input
	f.producerClientTenantID = input.Client.TenantID
	f.producerClientActorID = input.ActorID
	input.Client.ID = "pcl_1"
	return input.Client, nil
}
func (f *fakeControlStore) ListProducerClients(_ context.Context, tenantID string, limit int) ([]domain.ProducerClient, error) {
	f.producerClientTenantID = tenantID
	return []domain.ProducerClient{{ID: "pcl_1", TenantID: tenantID, Name: "producer", Scopes: []string{"events:write"}, TokenTTLSeconds: 900, State: domain.StateActive}}, nil
}
func (f *fakeControlStore) GetProducerClient(_ context.Context, tenantID, clientID string) (domain.ProducerClient, error) {
	f.producerClientTenantID = tenantID
	return domain.ProducerClient{ID: clientID, TenantID: tenantID, Name: "producer", Scopes: []string{"events:write"}, TokenTTLSeconds: 900, State: domain.StateActive}, nil
}
func (f *fakeControlStore) UpdateProducerClient(_ context.Context, tenantID, clientID, actorID string, req UpdateProducerClientRequest) (domain.ProducerClient, error) {
	f.producerClientTenantID = tenantID
	f.producerClientActorID = actorID
	f.producerClientReason = req.Reason
	return domain.ProducerClient{ID: clientID, TenantID: tenantID, Name: "producer", Scopes: []string{"events:write"}, TokenTTLSeconds: 900, State: domain.StateActive}, nil
}
func (f *fakeControlStore) DeleteProducerClient(_ context.Context, tenantID, clientID, actorID, reason string) (domain.ProducerClient, error) {
	f.producerClientTenantID = tenantID
	f.producerClientActorID = actorID
	f.producerClientReason = reason
	return domain.ProducerClient{ID: clientID, TenantID: tenantID, Name: "producer", Scopes: []string{"events:write"}, TokenTTLSeconds: 900, State: domain.StateDisabled}, nil
}
func (f *fakeControlStore) RotateProducerClientSecret(_ context.Context, tenantID, clientID string, input ProducerClientSecretRotateInput) (domain.ProducerClientSecret, error) {
	f.producerClientTenantID = tenantID
	f.producerClientActorID = input.ActorID
	f.producerClientReason = input.Reason
	input.Secret.ID = "pcs_1"
	input.Secret.TenantID = tenantID
	input.Secret.ClientID = clientID
	return input.Secret, nil
}
func (f *fakeControlStore) CreateProducerMTLSIdentity(_ context.Context, tenantID, actorID string, identity domain.ProducerMTLSIdentity) (domain.ProducerMTLSIdentity, error) {
	f.producerMTLSTenantID = tenantID
	f.producerMTLSActorID = actorID
	identity.ID = "pmi_1"
	identity.TenantID = tenantID
	f.producerMTLSIdentity = identity
	return identity, nil
}
func (f *fakeControlStore) ListProducerMTLSIdentities(_ context.Context, tenantID string, limit int) ([]domain.ProducerMTLSIdentity, error) {
	f.producerMTLSTenantID = tenantID
	return []domain.ProducerMTLSIdentity{{ID: "pmi_1", TenantID: tenantID, Name: "producer", CertificateFingerprintSHA256: "sha256:test", State: domain.StateActive}}, nil
}
func (f *fakeControlStore) GetProducerMTLSIdentity(_ context.Context, tenantID, identityID string) (domain.ProducerMTLSIdentity, error) {
	f.producerMTLSTenantID = tenantID
	item := f.producerMTLSIdentity
	if item.ID == "" {
		item = domain.ProducerMTLSIdentity{ID: identityID, TenantID: tenantID, Name: "producer", CertificateFingerprintSHA256: "sha256:test", State: domain.StateActive}
	}
	return item, nil
}
func (f *fakeControlStore) UpdateProducerMTLSIdentity(_ context.Context, tenantID, identityID, actorID string, req UpdateProducerMTLSIdentityRequest) (domain.ProducerMTLSIdentity, error) {
	f.producerMTLSTenantID = tenantID
	f.producerMTLSActorID = actorID
	f.producerMTLSReason = req.Reason
	return domain.ProducerMTLSIdentity{ID: identityID, TenantID: tenantID, Name: "producer", State: domain.StateActive}, nil
}
func (f *fakeControlStore) DeleteProducerMTLSIdentity(_ context.Context, tenantID, identityID, actorID, reason string) (domain.ProducerMTLSIdentity, error) {
	f.producerMTLSTenantID = tenantID
	f.producerMTLSActorID = actorID
	f.producerMTLSReason = reason
	return domain.ProducerMTLSIdentity{ID: identityID, TenantID: tenantID, Name: "producer", State: domain.StateDisabled}, nil
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
func (f *fakeControlStore) ListEvents(_ context.Context, tenantID string, req EventSearchRequest) ([]domain.Event, error) {
	f.eventSearchTenantID = tenantID
	f.eventSearchReq = req
	return nil, nil
}
func (f *fakeControlStore) GetEvent(_ context.Context, tenantID, eventID string) (domain.Event, error) {
	f.eventTenantID = tenantID
	return domain.Event{
		ID:             eventID,
		TenantID:       tenantID,
		SourceID:       "src_1",
		Provider:       "stripe",
		Type:           "invoice.paid",
		ProviderID:     "evt_provider_1",
		RawPayloadID:   "raw_1",
		RawPayloadHash: "sha256:raw",
		Verified:       true,
		VerifyReason:   "valid_signature",
		DedupeStatus:   domain.DedupeUnique,
		ReceivedAt:     time.Unix(100, 0).UTC(),
	}, nil
}
func (f *fakeControlStore) GetRawPayload(_ context.Context, tenantID, eventID, actorID, reason string) (domain.RawPayload, error) {
	f.rawPayloadTenantID = tenantID
	f.rawPayloadEventID = eventID
	f.rawPayloadActorID = actorID
	f.rawPayloadReason = reason
	return domain.RawPayload{ID: "raw_1", TenantID: tenantID, EventID: eventID}, nil
}
func (f *fakeControlStore) GetNormalizedEvent(_ context.Context, tenantID, eventID, actorID string, includeData bool) (domain.NormalizedEnvelope, error) {
	f.normalizedTenantID = tenantID
	f.normalizedMetadataOnly = !includeData
	return domain.NormalizedEnvelope{ID: "nenv_1", TenantID: tenantID, EventID: eventID}, nil
}
func (f *fakeControlStore) ListEventTimeline(context.Context, string, string, int) ([]EventTimelineEntry, error) {
	return []EventTimelineEntry{
		{SchemaVersion: EventTimelineSchemaV1, Sequence: 1, Kind: "event", RefID: "evt_1", State: "unique", Detail: "valid_signature", OccurredAt: time.Unix(100, 0).UTC()},
		{SchemaVersion: EventTimelineSchemaV1, Sequence: 2, Kind: "delivery", RefID: "del_1", State: "failed", Detail: "route_version=rtv_1 subscription_version=none retry_policy=rtp_1", OccurredAt: time.Unix(101, 0).UTC()},
		{SchemaVersion: EventTimelineSchemaV1, Sequence: 3, Kind: "attempt", RefID: "att_1", State: "failed", Detail: "network_error retryable=true retry_delay_ms=1000", OccurredAt: time.Unix(102, 0).UTC()},
		{SchemaVersion: EventTimelineSchemaV1, Sequence: 4, Kind: "replay", RefID: "rpl_1", State: "completed", Detail: "reason_code=incident_recovery reason=receiver restored after DLQ config_mode=original event_id=evt_1", OccurredAt: time.Unix(102, 500000000).UTC()},
		{SchemaVersion: EventTimelineSchemaV1, Sequence: 5, Kind: "audit", RefID: "aud_1", State: "raw_payload.read", Detail: "operator reason", OccurredAt: time.Unix(103, 0).UTC()},
	}, nil
}
func (f *fakeControlStore) CreateIncident(_ context.Context, incident domain.Incident) (domain.Incident, error) {
	f.incidentTenantID = incident.TenantID
	f.incidentActorID = incident.CreatedBy
	if incident.ID == "" {
		incident.ID = "inc_1"
	}
	if incident.CreatedAt.IsZero() {
		incident.CreatedAt = time.Unix(1, 0).UTC()
		incident.UpdatedAt = incident.CreatedAt
	}
	return incident, nil
}
func (f *fakeControlStore) ListIncidents(_ context.Context, tenantID string, limit int) ([]domain.Incident, error) {
	f.incidentTenantID = tenantID
	return []domain.Incident{{ID: "inc_1", TenantID: tenantID, Title: "Stripe payment failed", State: domain.StateActive}}, nil
}
func (f *fakeControlStore) GetIncident(_ context.Context, tenantID, incidentID string) (domain.Incident, error) {
	f.incidentTenantID = tenantID
	f.incidentID = incidentID
	return domain.Incident{ID: incidentID, TenantID: tenantID, Title: "Stripe payment failed", Reason: "support case", State: domain.StateActive, CreatedBy: "usr_1", CreatedAt: time.Unix(1, 0).UTC()}, nil
}
func (f *fakeControlStore) AddIncidentEvent(_ context.Context, tenantID, incidentID, eventID, actorID, reason string) (domain.IncidentEvent, error) {
	f.incidentTenantID = tenantID
	f.incidentID = incidentID
	f.incidentEventID = eventID
	f.incidentActorID = actorID
	f.incidentReason = reason
	return domain.IncidentEvent{ID: "ine_1", TenantID: tenantID, IncidentID: incidentID, EventID: eventID, AddedBy: actorID, Reason: reason, CreatedAt: time.Unix(2, 0).UTC()}, nil
}
func (f *fakeControlStore) RemoveIncidentEvent(_ context.Context, tenantID, incidentID, eventID, actorID, reason string) (domain.IncidentEvent, error) {
	f.incidentTenantID = tenantID
	f.incidentID = incidentID
	f.incidentEventID = eventID
	f.incidentActorID = actorID
	f.incidentReason = reason
	return domain.IncidentEvent{ID: "ine_1", TenantID: tenantID, IncidentID: incidentID, EventID: eventID, AddedBy: actorID, Reason: reason, CreatedAt: time.Unix(2, 0).UTC()}, nil
}
func (f *fakeControlStore) ListIncidentEvents(_ context.Context, tenantID, incidentID string) ([]domain.IncidentEvent, error) {
	f.incidentTenantID = tenantID
	f.incidentID = incidentID
	eventID := f.incidentEventID
	if eventID == "" {
		eventID = "evt_1"
	}
	return []domain.IncidentEvent{{ID: "ine_1", TenantID: tenantID, IncidentID: incidentID, EventID: eventID, AddedBy: "usr_1", Reason: "investigate", CreatedAt: time.Unix(2, 0).UTC()}}, nil
}
func (f *fakeControlStore) CreateIncidentReportSnapshot(_ context.Context, tenantID, incidentID, actorID, reason string, report IncidentReport, markdown string) (domain.IncidentReportSnapshot, error) {
	f.incidentTenantID = tenantID
	f.incidentID = incidentID
	f.incidentActorID = actorID
	f.incidentReason = reason
	raw, err := json.Marshal(report)
	if err != nil {
		return domain.IncidentReportSnapshot{}, err
	}
	return domain.IncidentReportSnapshot{ID: "irs_1", TenantID: tenantID, IncidentID: incidentID, SchemaVersion: report.SchemaVersion, Report: raw, Markdown: markdown, GeneratedBy: actorID, GeneratedAt: report.GeneratedAt}, nil
}
func (f *fakeControlStore) GetIncidentReportSnapshot(_ context.Context, tenantID, incidentID string) (domain.IncidentReportSnapshot, error) {
	f.incidentTenantID = tenantID
	f.incidentID = incidentID
	return domain.IncidentReportSnapshot{ID: "irs_1", TenantID: tenantID, IncidentID: incidentID, SchemaVersion: incidentReportSchemaV1, Markdown: "incident report", GeneratedBy: "usr_1", GeneratedAt: time.Unix(3, 0).UTC()}, nil
}
func (f *fakeControlStore) CreateIncidentEvidenceExport(_ context.Context, tenantID, incidentID, actorID string, req CreateIncidentEvidenceExportRequest, report IncidentReport, markdown string) (domain.IncidentEvidenceExport, domain.EvidenceExport, error) {
	f.incidentTenantID = tenantID
	f.incidentID = incidentID
	f.incidentActorID = actorID
	f.incidentReason = req.Reason
	return domain.IncidentEvidenceExport{ID: "iex_1", TenantID: tenantID, IncidentID: incidentID, ExportID: "exp_1", CreatedBy: actorID}, domain.EvidenceExport{ID: "exp_1", TenantID: tenantID, IncludeTimelines: true, CreatedBy: actorID}, nil
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
func (f *fakeControlStore) CreateNotificationChannel(_ context.Context, tenantID, actorID string, req CreateNotificationChannelRequest) (domain.NotificationChannel, error) {
	f.notificationTenantID = tenantID
	f.notificationActorID = actorID
	return domain.NotificationChannel{ID: "nch_1", TenantID: tenantID, Name: req.Name, ChannelType: req.ChannelType, URL: req.URL, State: domain.StateActive, SecretHint: "configured", CreatedBy: actorID}, nil
}
func (f *fakeControlStore) ListNotificationChannels(_ context.Context, tenantID string, limit int) ([]domain.NotificationChannel, error) {
	f.notificationTenantID = tenantID
	return []domain.NotificationChannel{{ID: "nch_1", TenantID: tenantID, ChannelType: domain.NotificationChannelWebhook, State: domain.StateActive, SecretHint: "configured"}}, nil
}
func (f *fakeControlStore) GetNotificationChannel(_ context.Context, tenantID, channelID string) (domain.NotificationChannel, error) {
	f.notificationTenantID = tenantID
	return domain.NotificationChannel{ID: channelID, TenantID: tenantID, ChannelType: domain.NotificationChannelWebhook, URL: "https://signals.example/hook", State: domain.StateActive, SecretHint: "configured"}, nil
}
func (f *fakeControlStore) UpdateNotificationChannel(_ context.Context, tenantID, channelID, actorID string, req UpdateNotificationChannelRequest) (domain.NotificationChannel, error) {
	f.notificationTenantID = tenantID
	f.notificationActorID = actorID
	return domain.NotificationChannel{ID: channelID, TenantID: tenantID, State: domain.StateActive, SecretHint: "configured"}, nil
}
func (f *fakeControlStore) DeleteNotificationChannel(_ context.Context, tenantID, channelID, actorID, reason string) (domain.NotificationChannel, error) {
	f.notificationTenantID = tenantID
	f.notificationActorID = actorID
	return domain.NotificationChannel{ID: channelID, TenantID: tenantID, State: domain.StateDisabled, SecretHint: "configured"}, nil
}
func (f *fakeControlStore) TestNotificationChannel(_ context.Context, tenantID, channelID, actorID, reason string) (domain.NotificationDelivery, error) {
	f.notificationTenantID = tenantID
	f.notificationActorID = actorID
	return domain.NotificationDelivery{ID: "ndel_1", TenantID: tenantID, ChannelID: channelID, Transition: "test", State: domain.SignalDeliveryScheduled}, nil
}
func (f *fakeControlStore) ListNotificationDeliveries(_ context.Context, tenantID, state string, limit int) ([]domain.NotificationDelivery, error) {
	f.notificationTenantID = tenantID
	return []domain.NotificationDelivery{{ID: "ndel_1", TenantID: tenantID, ChannelID: "nch_1", Transition: "opened", State: state}}, nil
}
func (f *fakeControlStore) ListNotificationDeliveryAttempts(_ context.Context, tenantID, deliveryID string, limit int) ([]domain.NotificationDeliveryAttempt, error) {
	f.notificationTenantID = tenantID
	return []domain.NotificationDeliveryAttempt{{ID: "natt_1", TenantID: tenantID, DeliveryID: deliveryID, FailureClass: "success"}}, nil
}
func (f *fakeControlStore) RetryNotificationDelivery(_ context.Context, tenantID, deliveryID, actorID, reason string) (domain.NotificationDelivery, error) {
	f.notificationTenantID = tenantID
	f.notificationActorID = actorID
	return domain.NotificationDelivery{ID: deliveryID, TenantID: tenantID, State: domain.SignalDeliveryScheduled}, nil
}
func (f *fakeControlStore) CreateSIEMSink(_ context.Context, tenantID, actorID string, req CreateSIEMSinkRequest) (domain.SIEMSink, error) {
	f.siemTenantID = tenantID
	f.siemActorID = actorID
	return domain.SIEMSink{ID: "snk_1", TenantID: tenantID, Name: req.Name, SinkType: req.SinkType, URL: req.URL, State: domain.StateActive, SecretHint: "configured", CreatedBy: actorID}, nil
}
func (f *fakeControlStore) ListSIEMSinks(_ context.Context, tenantID string, limit int) ([]domain.SIEMSink, error) {
	f.siemTenantID = tenantID
	return []domain.SIEMSink{{ID: "snk_1", TenantID: tenantID, SinkType: domain.SIEMSinkWebhook, State: domain.StateActive, SecretHint: "configured"}}, nil
}
func (f *fakeControlStore) GetSIEMSink(_ context.Context, tenantID, sinkID string) (domain.SIEMSink, error) {
	f.siemTenantID = tenantID
	return domain.SIEMSink{ID: sinkID, TenantID: tenantID, SinkType: domain.SIEMSinkWebhook, URL: "https://siem.example/ingest", State: domain.StateActive, SecretHint: "configured"}, nil
}
func (f *fakeControlStore) UpdateSIEMSink(_ context.Context, tenantID, sinkID, actorID string, req UpdateSIEMSinkRequest) (domain.SIEMSink, error) {
	f.siemTenantID = tenantID
	f.siemActorID = actorID
	return domain.SIEMSink{ID: sinkID, TenantID: tenantID, State: domain.StateActive, SecretHint: "configured"}, nil
}
func (f *fakeControlStore) DeleteSIEMSink(_ context.Context, tenantID, sinkID, actorID, reason string) (domain.SIEMSink, error) {
	f.siemTenantID = tenantID
	f.siemActorID = actorID
	return domain.SIEMSink{ID: sinkID, TenantID: tenantID, State: domain.StateDisabled, SecretHint: "configured"}, nil
}
func (f *fakeControlStore) TestSIEMSink(_ context.Context, tenantID, sinkID, actorID, reason string) (domain.SIEMDelivery, error) {
	f.siemTenantID = tenantID
	f.siemActorID = actorID
	return domain.SIEMDelivery{ID: "sdel_1", TenantID: tenantID, SinkID: sinkID, State: domain.SignalDeliveryScheduled}, nil
}
func (f *fakeControlStore) ListSIEMDeliveries(_ context.Context, tenantID, state string, limit int) ([]domain.SIEMDelivery, error) {
	f.siemTenantID = tenantID
	return []domain.SIEMDelivery{{ID: "sdel_1", TenantID: tenantID, SinkID: "snk_1", State: state, FromSequence: 1, ToSequence: 2}}, nil
}
func (f *fakeControlStore) ListSIEMDeliveryAttempts(_ context.Context, tenantID, deliveryID string, limit int) ([]domain.SIEMDeliveryAttempt, error) {
	f.siemTenantID = tenantID
	return []domain.SIEMDeliveryAttempt{{ID: "satt_1", TenantID: tenantID, DeliveryID: deliveryID, FailureClass: "success"}}, nil
}
func (f *fakeControlStore) RetrySIEMDelivery(_ context.Context, tenantID, deliveryID, actorID, reason string) (domain.SIEMDelivery, error) {
	f.siemTenantID = tenantID
	f.siemActorID = actorID
	return domain.SIEMDelivery{ID: deliveryID, TenantID: tenantID, State: domain.SignalDeliveryScheduled}, nil
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
func (f *fakeControlStore) CreateProviderAdapter(_ context.Context, tenantID, actorID string, req CreateProviderAdapterRequest) (domain.ProviderAdapter, error) {
	f.adapterTenantID = tenantID
	f.adapterActorID = actorID
	return domain.ProviderAdapter{ID: "pad_1", TenantID: tenantID, Name: req.Name, Kind: req.Kind, State: domain.AdapterStateDraft, RiskLevel: req.RiskLevel, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) ListProviderAdapters(_ context.Context, tenantID string, limit int) ([]domain.ProviderAdapter, error) {
	f.adapterTenantID = tenantID
	return []domain.ProviderAdapter{{ID: "pad_1", TenantID: tenantID, Name: "acme", Kind: domain.AdapterKindDeclarative, State: domain.AdapterStateDraft, RiskLevel: domain.AdapterRiskMedium}}, nil
}
func (f *fakeControlStore) GetProviderAdapter(_ context.Context, tenantID, adapterID string) (domain.ProviderAdapter, error) {
	f.adapterTenantID = tenantID
	return domain.ProviderAdapter{ID: adapterID, TenantID: tenantID, Name: "acme", Kind: domain.AdapterKindDeclarative, State: domain.AdapterStateDraft, RiskLevel: domain.AdapterRiskMedium}, nil
}
func (f *fakeControlStore) CreateAdapterVersion(_ context.Context, tenantID, adapterID, actorID string, req CreateAdapterVersionRequest) (domain.AdapterVersion, error) {
	f.adapterTenantID = tenantID
	f.adapterActorID = actorID
	f.adapterVersionReq = req
	return domain.AdapterVersion{ID: "adv_1", TenantID: tenantID, AdapterID: adapterID, Name: "acme", Version: req.Version, Kind: domain.AdapterKindDeclarative, State: domain.AdapterStateDraft, Definition: req.Definition, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) ListAdapterVersions(_ context.Context, tenantID, adapterID string, limit int) ([]domain.AdapterVersion, error) {
	f.adapterTenantID = tenantID
	return []domain.AdapterVersion{{ID: "adv_1", TenantID: tenantID, AdapterID: adapterID, Name: "acme", Version: "2026-05-01", Kind: domain.AdapterKindDeclarative, State: domain.AdapterStateDraft}}, nil
}
func (f *fakeControlStore) CreateAdapterTestVector(_ context.Context, tenantID, adapterID, versionID, actorID string, req CreateAdapterTestVectorRequest) (domain.AdapterTestVector, error) {
	f.adapterTenantID = tenantID
	f.adapterActorID = actorID
	return domain.AdapterTestVector{ID: "atv_1", TenantID: tenantID, AdapterVersionID: versionID, Name: req.Name, Request: req.Request, Expected: req.Expected, State: domain.StateActive, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) TransitionAdapterVersion(_ context.Context, tenantID, adapterID, versionID, actorID string, req AdapterVersionTransitionRequest) (domain.AdapterVersion, error) {
	f.adapterTenantID = tenantID
	f.adapterActorID = actorID
	return domain.AdapterVersion{ID: versionID, TenantID: tenantID, AdapterID: adapterID, Name: "acme", Version: "2026-05-01", Kind: domain.AdapterKindDeclarative, State: req.Action, CreatedBy: actorID}, nil
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
func (f *fakeControlStore) ReleaseDeadLetter(context.Context, string, string, string, string, string) (ReplayJob, error) {
	return ReplayJob{}, nil
}
func (f *fakeControlStore) BulkReleaseDeadLetter(context.Context, string, []string, string, string, string) ([]ReplayJob, error) {
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
	return ReplayJob{ID: "rpl_1", State: "pending_approval", ScopeHash: "sha256:abc", ReasonCode: req.ReasonCode, Reason: req.Reason, TotalItems: 1, ApprovalRequired: req.RequireApproval, ApprovalExpiresAt: req.ApprovalExpiresAt}, nil
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
func (f *fakeControlStore) CreateReplayApprovalPolicy(_ context.Context, tenantID, actorID string, req CreateReplayApprovalPolicyRequest) (domain.ReplayApprovalPolicy, error) {
	f.replayApprovalPolicyTenantID = tenantID
	f.replayApprovalPolicyActorID = actorID
	f.replayApprovalPolicyReq = req
	return domain.ReplayApprovalPolicy{ID: "rap_1", TenantID: tenantID, ScopeType: req.ScopeType, ScopeID: req.ScopeID, RequireApproval: req.RequireApproval, DefaultExpirySeconds: req.DefaultExpirySeconds, State: domain.StateActive, Reason: req.Reason, CreatedBy: actorID}, nil
}
func (f *fakeControlStore) ListReplayApprovalPolicies(_ context.Context, tenantID string, limit int) ([]domain.ReplayApprovalPolicy, error) {
	f.replayApprovalPolicyTenantID = tenantID
	return []domain.ReplayApprovalPolicy{{ID: "rap_1", TenantID: tenantID, ScopeType: ReplayApprovalScopeTenant, RequireApproval: true, DefaultExpirySeconds: int(ReplayApprovalDefaultExpiry / time.Second), State: domain.StateActive}}, nil
}
func (f *fakeControlStore) DisableReplayApprovalPolicy(_ context.Context, tenantID, policyID, actorID, reason string) (domain.ReplayApprovalPolicy, error) {
	f.replayApprovalPolicyTenantID = tenantID
	f.replayApprovalPolicyActorID = actorID
	f.replayApprovalPolicyID = policyID
	f.replayApprovalPolicyReason = reason
	return domain.ReplayApprovalPolicy{ID: policyID, TenantID: tenantID, ScopeType: ReplayApprovalScopeTenant, RequireApproval: true, DefaultExpirySeconds: int(ReplayApprovalDefaultExpiry / time.Second), State: domain.StateDisabled, CreatedBy: actorID}, nil
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

func ptrInt(v int) *int {
	return &v
}
