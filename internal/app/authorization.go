package app

import (
	"context"
	"strings"

	"webhookery/internal/authz"
)

type AuthorizationService struct {
	store EnterpriseIdentityStore
}

type AuthorizationRequest struct {
	Actor          authz.Actor
	TenantID       string
	Action         string
	ResourceFamily string
	ResourceID     string
	Environment    string
}

func NewAuthorizationService(store ControlStore) AuthorizationService {
	enterpriseStore, _ := store.(EnterpriseIdentityStore)
	return AuthorizationService{store: enterpriseStore}
}

func (s AuthorizationService) Authorize(ctx context.Context, req AuthorizationRequest) authz.Decision {
	resource := authz.Resource{
		TenantID:    strings.TrimSpace(req.TenantID),
		Family:      strings.TrimSpace(req.ResourceFamily),
		ID:          strings.TrimSpace(req.ResourceID),
		Environment: strings.TrimSpace(req.Environment),
	}
	action := strings.TrimSpace(req.Action)
	decision := authz.Decision{
		Allowed:        false,
		Action:         action,
		Resource:       resource,
		Reason:         "authorization context is incomplete",
		RequiredScopes: []string{action},
	}
	if req.Actor.ID == "" || req.Actor.TenantID == "" || resource.TenantID == "" || action == "" || resource.Family == "" {
		return decision
	}
	if req.Actor.TenantID != resource.TenantID {
		decision.Reason = "actor tenant does not match resource tenant"
		return decision
	}
	if s.store != nil {
		explained, err := s.store.ExplainAuthorization(ctx, resource.TenantID, req.Actor.ID, AuthzExplainRequest{
			Action:         action,
			ResourceFamily: resource.Family,
			ResourceID:     resource.ID,
			Environment:    resource.Environment,
		})
		if err == nil {
			explained.RequiredScopes = []string{action}
			if !explained.Allowed {
				return explained
			}
			if !actorScopesAllow(req.Actor, action) {
				explained.Allowed = false
				explained.Reason = "actor scope does not allow action"
			}
			return explained
		}
	}
	if !authz.Can(req.Actor, action, resource.TenantID) {
		decision.Reason = "baseline role or scope does not allow action"
		return decision
	}
	decision.Allowed = true
	decision.Reason = "allowed by baseline role"
	decision.MatchedRole = string(req.Actor.Role)
	return decision
}
