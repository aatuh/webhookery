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
