package app

import (
	"context"
	"strings"
	"testing"

	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/ssrf"
)

func TestEnterpriseIdentityProviderRequiresSecurityWrite(t *testing.T) {
	store := &enterpriseFakeStore{}
	svc := NewControlService(store, ssrf.Validator{})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAuditor, Scopes: []string{"security:read"}}

	_, err := svc.CreateIdentityProvider(context.Background(), actor, CreateIdentityProviderRequest{
		Name:         "Okta",
		IssuerURL:    "https://idp.example.com",
		ClientID:     "client",
		ClientSecret: "secret",
	})
	if err != ErrForbidden {
		t.Fatalf("expected forbidden identity provider create, got %v", err)
	}
	if store.identityTenantID != "" {
		t.Fatal("store must not be called before authorization")
	}
}

func TestCreateSCIMTokenPersistsHashOnlyAndReturnsValueOnce(t *testing.T) {
	store := &enterpriseFakeStore{}
	svc := NewControlService(store, ssrf.Validator{})
	actor := authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleSecurity, Scopes: []string{"security:write"}}

	created, err := svc.CreateSCIMToken(context.Background(), actor, CreateSCIMTokenRequest{Name: "Azure AD"})
	if err != nil {
		t.Fatal(err)
	}
	if created.Value == "" {
		t.Fatal("raw SCIM token was not returned on create")
	}
	if store.scimToken.Hash == "" || !strings.HasPrefix(store.scimToken.Hash, "sha256:") {
		t.Fatalf("SCIM token was not hashed at persistence boundary: %+v", store.scimToken)
	}
	if strings.Contains(store.scimToken.Hash, created.Value) {
		t.Fatal("raw SCIM token leaked into persisted hash")
	}
	if created.Token.Hash != "" {
		t.Fatal("SCIM token hash must not be exposed in create response")
	}
}

type enterpriseFakeStore struct {
	fakeControlStore
	identityTenantID string
	scimToken        domain.SCIMToken
}

func (s *enterpriseFakeStore) CreateIdentityProvider(_ context.Context, tenantID, actorID string, req CreateIdentityProviderRequest) (domain.IdentityProvider, error) {
	s.identityTenantID = tenantID
	return domain.IdentityProvider{ID: "idp_1", TenantID: tenantID, Name: req.Name, CreatedBy: actorID, State: domain.StateActive}, nil
}
func (s *enterpriseFakeStore) ListIdentityProviders(context.Context, string, int) ([]domain.IdentityProvider, error) {
	return nil, nil
}
func (s *enterpriseFakeStore) GetIdentityProvider(context.Context, string, string) (domain.IdentityProvider, error) {
	return domain.IdentityProvider{}, nil
}
func (s *enterpriseFakeStore) UpdateIdentityProvider(context.Context, string, string, string, UpdateIdentityProviderRequest) (domain.IdentityProvider, error) {
	return domain.IdentityProvider{}, nil
}
func (s *enterpriseFakeStore) DisableIdentityProvider(context.Context, string, string, string, string) (domain.IdentityProvider, error) {
	return domain.IdentityProvider{}, nil
}
func (s *enterpriseFakeStore) TestIdentityProvider(context.Context, string, string, string, string) (domain.IdentityProvider, error) {
	return domain.IdentityProvider{}, nil
}
func (s *enterpriseFakeStore) CreateOIDCLoginState(context.Context, domain.OIDCLoginState) error {
	return nil
}
func (s *enterpriseFakeStore) ConsumeOIDCLoginState(context.Context, string) (domain.OIDCLoginState, domain.IdentityProvider, error) {
	return domain.OIDCLoginState{}, domain.IdentityProvider{}, nil
}
func (s *enterpriseFakeStore) CreateOIDCSession(context.Context, OIDCSessionInput) (domain.AuthSession, authz.Actor, error) {
	return domain.AuthSession{}, authz.Actor{}, nil
}
func (s *enterpriseFakeStore) RevokeAuthSession(context.Context, string, string, string, string) error {
	return nil
}
func (s *enterpriseFakeStore) CurrentAuthSession(context.Context, string, string, string) (domain.AuthSession, error) {
	return domain.AuthSession{}, nil
}
func (s *enterpriseFakeStore) AuthenticateSCIMTokenHash(context.Context, string) (authz.Actor, error) {
	return authz.Actor{}, nil
}
func (s *enterpriseFakeStore) CreateSCIMToken(_ context.Context, tenantID, actorID string, token domain.SCIMToken) (domain.SCIMToken, error) {
	s.scimToken = token
	token.Hash = ""
	token.TenantID = tenantID
	token.CreatedBy = actorID
	return token, nil
}
func (s *enterpriseFakeStore) ListSCIMTokens(context.Context, string, int) ([]domain.SCIMToken, error) {
	return nil, nil
}
func (s *enterpriseFakeStore) RevokeSCIMToken(context.Context, string, string, string, string) (domain.SCIMToken, error) {
	return domain.SCIMToken{}, nil
}
func (s *enterpriseFakeStore) SCIMCreateOrReplaceUser(context.Context, string, string, SCIMUserRequest, bool) (SCIMUser, error) {
	return SCIMUser{}, nil
}
func (s *enterpriseFakeStore) SCIMListUsers(context.Context, string, int) ([]SCIMUser, error) {
	return nil, nil
}
func (s *enterpriseFakeStore) SCIMGetUser(context.Context, string, string) (SCIMUser, error) {
	return SCIMUser{}, nil
}
func (s *enterpriseFakeStore) SCIMPatchUser(context.Context, string, string, string, SCIMPatchRequest) (SCIMUser, error) {
	return SCIMUser{}, nil
}
func (s *enterpriseFakeStore) SCIMDeactivateUser(context.Context, string, string, string) (SCIMUser, error) {
	return SCIMUser{}, nil
}
func (s *enterpriseFakeStore) SCIMCreateOrReplaceGroup(context.Context, string, string, SCIMGroupRequest, bool) (SCIMGroup, error) {
	return SCIMGroup{}, nil
}
func (s *enterpriseFakeStore) SCIMListGroups(context.Context, string, int) ([]SCIMGroup, error) {
	return nil, nil
}
func (s *enterpriseFakeStore) SCIMGetGroup(context.Context, string, string) (SCIMGroup, error) {
	return SCIMGroup{}, nil
}
func (s *enterpriseFakeStore) SCIMPatchGroup(context.Context, string, string, string, SCIMPatchRequest) (SCIMGroup, error) {
	return SCIMGroup{}, nil
}
func (s *enterpriseFakeStore) SCIMDeactivateGroup(context.Context, string, string, string) (SCIMGroup, error) {
	return SCIMGroup{}, nil
}
func (s *enterpriseFakeStore) CreateRoleBinding(context.Context, string, string, CreateRoleBindingRequest) (domain.RoleBinding, error) {
	return domain.RoleBinding{}, nil
}
func (s *enterpriseFakeStore) ListRoleBindings(context.Context, string, int) ([]domain.RoleBinding, error) {
	return nil, nil
}
func (s *enterpriseFakeStore) UpdateRoleBinding(context.Context, string, string, string, UpdateRoleBindingRequest) (domain.RoleBinding, error) {
	return domain.RoleBinding{}, nil
}
func (s *enterpriseFakeStore) DisableRoleBinding(context.Context, string, string, string, string) (domain.RoleBinding, error) {
	return domain.RoleBinding{}, nil
}
func (s *enterpriseFakeStore) CreateAccessPolicyRule(context.Context, string, string, CreateAccessPolicyRuleRequest) (domain.AccessPolicyRule, error) {
	return domain.AccessPolicyRule{}, nil
}
func (s *enterpriseFakeStore) ListAccessPolicyRules(context.Context, string, int) ([]domain.AccessPolicyRule, error) {
	return nil, nil
}
func (s *enterpriseFakeStore) UpdateAccessPolicyRule(context.Context, string, string, string, UpdateAccessPolicyRuleRequest) (domain.AccessPolicyRule, error) {
	return domain.AccessPolicyRule{}, nil
}
func (s *enterpriseFakeStore) DisableAccessPolicyRule(context.Context, string, string, string, string) (domain.AccessPolicyRule, error) {
	return domain.AccessPolicyRule{}, nil
}
func (s *enterpriseFakeStore) ExplainAuthorization(context.Context, string, string, AuthzExplainRequest) (authz.Decision, error) {
	return authz.Decision{}, nil
}
