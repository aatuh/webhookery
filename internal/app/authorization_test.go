package app

import (
	"context"
	"errors"
	"testing"

	"webhookery/internal/authz"
)

func TestAuthorizationServiceAllowsBaselineRoleAndScope(t *testing.T) {
	service := AuthorizationService{}
	decision := service.Authorize(context.Background(), AuthorizationRequest{
		Actor:          authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"events:read"}},
		TenantID:       "ten_1",
		Action:         "events:read",
		ResourceFamily: "event",
		ResourceID:     "evt_1",
	})
	if !decision.Allowed || decision.MatchedRole != string(authz.RoleDeveloper) {
		t.Fatalf("expected baseline allow, got %+v", decision)
	}
}

func TestAuthorizationServiceDeniesIncompleteAndWrongTenantContext(t *testing.T) {
	service := AuthorizationService{}
	base := AuthorizationRequest{
		Actor:          authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleOwner, Scopes: []string{"*"}},
		TenantID:       "ten_1",
		Action:         "events:read",
		ResourceFamily: "event",
		ResourceID:     "evt_1",
	}
	cases := map[string]AuthorizationRequest{
		"missing actor":   {TenantID: "ten_1", Action: "events:read", ResourceFamily: "event"},
		"missing tenant":  {Actor: base.Actor, Action: "events:read", ResourceFamily: "event"},
		"missing action":  {Actor: base.Actor, TenantID: "ten_1", ResourceFamily: "event"},
		"missing family":  {Actor: base.Actor, TenantID: "ten_1", Action: "events:read"},
		"wrong tenant":    {Actor: base.Actor, TenantID: "ten_2", Action: "events:read", ResourceFamily: "event"},
		"scope disallows": {Actor: authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleOwner, Scopes: []string{"events:read"}}, TenantID: "ten_1", Action: "events:raw", ResourceFamily: "event"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if decision := service.Authorize(context.Background(), req); decision.Allowed {
				t.Fatalf("expected deny, got %+v", decision)
			}
		})
	}
}

func TestAuthorizationServiceDeniesWrongTenantForSensitiveResourceFamilies(t *testing.T) {
	service := AuthorizationService{}
	cases := []struct {
		name   string
		action string
		family string
		id     string
	}{
		{"api key", "api_keys:write", "api_key", "key_1"},
		{"source", "sources:write", "source", "src_1"},
		{"provider connection", "sources:write", "provider_connection", "pco_1"},
		{"endpoint", "endpoints:write", "endpoint", "end_1"},
		{"subscription", "subscriptions:write", "subscription", "sub_1"},
		{"route", "routes:write", "route", "rou_1"},
		{"retry policy", "routes:write", "retry_policy", "rtp_1"},
		{"event type", "schemas:write", "event_type", "invoice.paid"},
		{"event schema", "schemas:write", "event_schema", "invoice.paid:2026-05-01"},
		{"event raw", "events:raw", "event", "evt_1"},
		{"delivery", "deliveries:retry", "delivery", "del_1"},
		{"replay", "replay:write", "replay", "rpl_1"},
		{"audit event", "audit:read", "audit_event", "aud_1"},
		{"audit export", "audit:read", "audit_export", "exp_1"},
		{"audit anchor", "security:write", "audit_chain_anchor", "anc_1"},
		{"retention policy", "security:write", "retention_policy", "ret_1"},
		{"reconciliation", "replay:write", "reconciliation_job", "rec_1"},
		{"transformation", "routes:write", "transformation", "trn_1"},
		{"notification channel", "ops:write", "notification_channel", "nch_1"},
		{"notification delivery", "ops:write", "notification_delivery", "ndl_1"},
		{"siem sink", "security:write", "siem_sink", "snk_1"},
		{"siem delivery", "security:write", "siem_delivery", "sdl_1"},
		{"producer client", "security:write", "producer_client", "pcl_1"},
		{"producer mtls", "security:write", "producer_mtls_identity", "pmi_1"},
		{"identity provider", "security:write", "identity_provider", "idp_1"},
		{"auth session", "security:write", "auth_session", "ses_1"},
		{"scim token", "security:write", "scim_token", "scm_1"},
		{"role binding", "security:write", "role_binding", "rbd_1"},
		{"access policy", "security:write", "access_policy", "pol_1"},
		{"provider adapter", "security:write", "provider_adapter", "pad_1"},
		{"adapter version", "security:write", "adapter_version", "adv_1"},
		{"dead letter", "deliveries:retry", "dead_letter", "dlq_1"},
		{"quarantine", "security:write", "quarantine", "qua_1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := service.Authorize(context.Background(), AuthorizationRequest{
				Actor:          authz.Actor{ID: "usr_1", TenantID: "ten_a", Role: authz.RoleOwner, Scopes: []string{"*"}},
				TenantID:       "ten_b",
				Action:         tc.action,
				ResourceFamily: tc.family,
				ResourceID:     tc.id,
				Environment:    "production",
			})
			if decision.Allowed || decision.Reason != "actor tenant does not match resource tenant" {
				t.Fatalf("expected wrong-tenant deny, got %+v", decision)
			}
		})
	}
}

func TestAuthorizationServiceUsesEnterpriseExplainWithResourceContext(t *testing.T) {
	store := &authorizationFakeStore{decision: authz.Decision{
		Allowed:              true,
		Action:               "endpoints:write",
		Resource:             authz.Resource{TenantID: "ten_1", Family: "endpoint", ID: "end_1", Environment: "production"},
		Reason:               "allowed by resource role binding",
		MatchedRoleBindingID: "rb_1",
	}}
	service := NewAuthorizationService(store)
	decision := service.Authorize(context.Background(), AuthorizationRequest{
		Actor:          authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleSupport, Scopes: []string{"endpoints:write"}},
		TenantID:       "ten_1",
		Action:         "endpoints:write",
		ResourceFamily: "endpoint",
		ResourceID:     "end_1",
		Environment:    "production",
	})
	if !decision.Allowed || decision.MatchedRoleBindingID != "rb_1" {
		t.Fatalf("expected enterprise allow, got %+v", decision)
	}
	if store.lastTenantID != "ten_1" || store.lastActorID != "usr_1" || store.lastReq.ResourceID != "end_1" || store.lastReq.Environment != "production" {
		t.Fatalf("enterprise explain did not receive resource context: %+v", store)
	}
}

func TestAuthorizationServicePreservesEnterpriseDenyAndScopeLimit(t *testing.T) {
	store := &authorizationFakeStore{decision: authz.Decision{
		Allowed:  false,
		Action:   "events:raw",
		Resource: authz.Resource{TenantID: "ten_1", Family: "event", ID: "evt_1"},
		Reason:   "denied by access policy",
	}}
	service := NewAuthorizationService(store)
	denied := service.Authorize(context.Background(), AuthorizationRequest{
		Actor:          authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleOwner, Scopes: []string{"*"}},
		TenantID:       "ten_1",
		Action:         "events:raw",
		ResourceFamily: "event",
		ResourceID:     "evt_1",
	})
	if denied.Allowed || denied.Reason != "denied by access policy" {
		t.Fatalf("expected enterprise deny, got %+v", denied)
	}

	store.decision.Allowed = true
	limited := service.Authorize(context.Background(), AuthorizationRequest{
		Actor:          authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleOwner, Scopes: []string{"events:read"}},
		TenantID:       "ten_1",
		Action:         "events:raw",
		ResourceFamily: "event",
		ResourceID:     "evt_1",
	})
	if limited.Allowed || limited.Reason != "actor scope does not allow action" {
		t.Fatalf("expected scope-limited deny, got %+v", limited)
	}
}

func TestAuthorizationServiceFallsBackToBaselineOnExplainError(t *testing.T) {
	store := &authorizationFakeStore{err: errors.New("temporary policy store unavailable")}
	service := NewAuthorizationService(store)
	decision := service.Authorize(context.Background(), AuthorizationRequest{
		Actor:          authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleOwner, Scopes: []string{"*"}},
		TenantID:       "ten_1",
		Action:         "replay:write",
		ResourceFamily: "replay",
		ResourceID:     "rpl_1",
	})
	if !decision.Allowed || decision.Reason != "allowed by baseline role" {
		t.Fatalf("expected baseline fallback allow, got %+v", decision)
	}
}

type authorizationFakeStore struct {
	enterpriseFakeStore
	decision     authz.Decision
	err          error
	lastTenantID string
	lastActorID  string
	lastReq      AuthzExplainRequest
}

func (s *authorizationFakeStore) ExplainAuthorization(_ context.Context, tenantID, actorID string, req AuthzExplainRequest) (authz.Decision, error) {
	s.lastTenantID = tenantID
	s.lastActorID = actorID
	s.lastReq = req
	if s.err != nil {
		return authz.Decision{}, s.err
	}
	return s.decision, nil
}
