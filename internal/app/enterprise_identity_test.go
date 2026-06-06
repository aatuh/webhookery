package app

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestEnterpriseIdentityProviderManagementScopesAndValidates(t *testing.T) {
	issuer := newFakeOIDCIssuer(t, "client", "nonce")
	store := &enterpriseFakeStore{
		idp: domain.IdentityProvider{
			ID:           "idp_1",
			TenantID:     "ten_1",
			IssuerURL:    issuer.URL,
			ClientID:     "client",
			ClientSecret: []byte("secret"),
			RedirectURI:  "https://webhookery.example/v1/auth/oidc/callback",
			State:        domain.StateActive,
		},
	}
	svc := NewControlService(store, ssrf.Validator{})
	actor := authz.Actor{ID: "usr_security", TenantID: "ten_1", Role: authz.RoleSecurity, Scopes: []string{"security:read", "security:write"}}

	if _, err := svc.CreateIdentityProvider(context.Background(), actor, CreateIdentityProviderRequest{
		Name:         "Okta",
		IssuerURL:    "://bad",
		ClientID:     "client",
		ClientSecret: "secret",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid issuer URL to be rejected, got %v", err)
	}
	created, err := svc.CreateIdentityProvider(context.Background(), actor, CreateIdentityProviderRequest{
		Name:         "Okta",
		IssuerURL:    issuer.URL,
		ClientID:     "client",
		ClientSecret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.TenantID != "ten_1" || created.CreatedBy != "usr_security" || store.identityTenantID != "ten_1" {
		t.Fatalf("identity provider create was not tenant/actor scoped: created=%+v tenant=%q", created, store.identityTenantID)
	}
	if _, err := svc.ListIdentityProviders(context.Background(), actor, 250); err != nil {
		t.Fatal(err)
	}
	if store.listIdentityTenantID != "ten_1" || store.listIdentityLimit != 50 {
		t.Fatalf("identity provider list tenant/limit=%q/%d", store.listIdentityTenantID, store.listIdentityLimit)
	}
	if _, err := svc.GetIdentityProvider(context.Background(), actor, "idp_1"); err != nil {
		t.Fatal(err)
	}
	if store.getIdentityProviderID != "idp_1" {
		t.Fatalf("identity provider get did not use provider id: %q", store.getIdentityProviderID)
	}
	if _, err := svc.UpdateIdentityProvider(context.Background(), actor, "idp_1", UpdateIdentityProviderRequest{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected update reason validation, got %v", err)
	}
	name := "Okta workforce"
	if _, err := svc.UpdateIdentityProvider(context.Background(), actor, "idp_1", UpdateIdentityProviderRequest{Name: &name, Reason: "rename"}); err != nil {
		t.Fatal(err)
	}
	if store.updatedProviderID != "idp_1" || store.updatedProviderReason != "rename" {
		t.Fatalf("identity provider update was not scoped with reason: provider=%q reason=%q", store.updatedProviderID, store.updatedProviderReason)
	}
	if _, err := svc.DisableIdentityProvider(context.Background(), actor, "idp_1", StateChangeRequest{Reason: "offboard"}); err != nil {
		t.Fatal(err)
	}
	if store.disabledProviderID != "idp_1" || store.disabledProviderReason != "offboard" {
		t.Fatalf("identity provider disable was not scoped with reason: provider=%q reason=%q", store.disabledProviderID, store.disabledProviderReason)
	}
	if _, err := svc.TestIdentityProvider(context.Background(), actor, "idp_1", StateChangeRequest{Reason: "preflight"}); err != nil {
		t.Fatal(err)
	}
	if store.testedProviderID != "idp_1" || store.testedProviderReason != "preflight" {
		t.Fatalf("identity provider test was not scoped with reason: provider=%q reason=%q", store.testedProviderID, store.testedProviderReason)
	}

	start, err := svc.BeginOIDCLogin(context.Background(), " ten_1 ", " idp_1 ", "https://evil.example/after")
	if err != nil {
		t.Fatal(err)
	}
	if start.AuthURL == "" || start.State == "" || start.Nonce == "" {
		t.Fatalf("OIDC login start did not return browser flow data: %+v", start)
	}
	if store.loginState.TenantID != "ten_1" || store.loginState.IdentityProviderID != "idp_1" || store.loginState.RedirectAfter != "/" {
		t.Fatalf("OIDC login state was not scoped or sanitized: %+v", store.loginState)
	}
	if strings.Contains(store.loginState.StateHash, start.State) || strings.Contains(store.loginState.NonceHash, start.Nonce) {
		t.Fatalf("raw OIDC state or nonce leaked into persisted hashes: state=%+v", store.loginState)
	}
}

func TestEnterpriseIdentitySecurityHelpersNormalizeRedirectsAndDomains(t *testing.T) {
	redirects := map[string]string{
		"":                       "/",
		"/console?tab=security":  "/console?tab=security",
		"https://evil.test/path": "/",
		"//evil.test/path":       "/",
		"relative/path":          "/",
		"://bad":                 "/",
	}
	for raw, want := range redirects {
		t.Run(raw, func(t *testing.T) {
			if got := safeRedirectPath(raw); got != want {
				t.Fatalf("safeRedirectPath(%q)=%q want %q", raw, got, want)
			}
		})
	}

	if !emailDomainAllowed(" Person@Example.COM ", []string{"example.com"}) {
		t.Fatal("expected matching email domain to be allowed")
	}
	if emailDomainAllowed("person@example.org", []string{"example.com"}) {
		t.Fatal("unexpected non-matching email domain allowed")
	}
	if emailDomainAllowed("not-an-email", []string{"example.com"}) {
		t.Fatal("malformed email should not match restricted domains")
	}
	if !emailDomainAllowed("person@anything.test", nil) {
		t.Fatal("empty allowed domain list should allow any email domain")
	}

	if identityWildcard(" ") != "*" || identityWildcard(" security ") != "security" {
		t.Fatal("identity wildcard should trim and default empty values")
	}
	if !wouldDenySecurityWrite("deny", "*", " ", " ") {
		t.Fatal("wildcard deny should protect security write")
	}
	if wouldDenySecurityWrite("allow", "security:write", "security", "*") {
		t.Fatal("allow rule should not be treated as a deny")
	}
}

func TestEnterpriseSessionLifecycleHashesTokensAndScopesTenant(t *testing.T) {
	store := &enterpriseFakeStore{}
	svc := NewControlService(store, ssrf.Validator{})
	actor := authz.Actor{ID: "usr_security", TenantID: "ten_1", Role: authz.RoleSecurity, Scopes: []string{"security:read", "security:write"}}

	if err := svc.LogoutSession(context.Background(), actor, "raw-session-token"); err != nil {
		t.Fatal(err)
	}
	if store.revokedSessionTenantID != "ten_1" || store.revokedSessionActorID != "usr_security" || store.revokedSessionReason != "logout" {
		t.Fatalf("logout revoke was not tenant/actor scoped: tenant=%q actor=%q reason=%q", store.revokedSessionTenantID, store.revokedSessionActorID, store.revokedSessionReason)
	}
	if store.revokedSessionHash == "" || store.revokedSessionHash == "raw-session-token" || !strings.HasPrefix(store.revokedSessionHash, "sha256:") {
		t.Fatalf("raw session token reached store boundary: %q", store.revokedSessionHash)
	}
	if _, err := svc.CurrentAuthSession(context.Background(), actor, "raw-session-token"); err != nil {
		t.Fatal(err)
	}
	if store.currentSessionTenantID != "ten_1" || store.currentSessionActorID != "usr_security" || store.currentSessionHash == "raw-session-token" {
		t.Fatalf("current session lookup was not hashed/scoped: tenant=%q actor=%q hash=%q", store.currentSessionTenantID, store.currentSessionActorID, store.currentSessionHash)
	}
	if _, err := svc.ListAuthSessions(context.Background(), actor, 500); err != nil {
		t.Fatal(err)
	}
	if store.listAuthSessionTenantID != "ten_1" || store.listAuthSessionLimit != 50 {
		t.Fatalf("auth session list tenant/limit=%q/%d", store.listAuthSessionTenantID, store.listAuthSessionLimit)
	}
	if _, err := svc.RevokeAuthSessionByID(context.Background(), actor, "ses_1", StateChangeRequest{Reason: "suspected compromise"}); err != nil {
		t.Fatal(err)
	}
	if store.revokedByIDTenantID != "ten_1" || store.revokedByIDActorID != "usr_security" || store.revokedByIDSessionID != "ses_1" || store.revokedByIDReason != "suspected compromise" {
		t.Fatalf("session revoke-by-id was not scoped with reason: tenant=%q actor=%q session=%q reason=%q", store.revokedByIDTenantID, store.revokedByIDActorID, store.revokedByIDSessionID, store.revokedByIDReason)
	}
	if _, err := svc.AuthenticateSCIMToken(context.Background(), "raw-scim-token"); err != nil {
		t.Fatal(err)
	}
	if store.scimAuthTokenHash == "" || store.scimAuthTokenHash == "raw-scim-token" || !strings.HasPrefix(store.scimAuthTokenHash, "sha256:") {
		t.Fatalf("raw SCIM token reached auth lookup: %q", store.scimAuthTokenHash)
	}
	if _, err := svc.AuthenticateSCIMToken(context.Background(), ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("empty SCIM token must be unauthorized, got %v", err)
	}
}

func TestEnterpriseSCIMProvisioningScopesTenantAndValidatesInputs(t *testing.T) {
	store := &enterpriseFakeStore{}
	svc := NewControlService(store, ssrf.Validator{})
	actor := authz.Actor{ID: "scim_sync", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"*"}}

	if _, err := svc.SCIMCreateUser(context.Background(), actor, SCIMUserRequest{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected missing SCIM userName to be rejected, got %v", err)
	}
	if _, err := svc.SCIMCreateUser(context.Background(), actor, SCIMUserRequest{UserName: "person@example.com"}); err != nil {
		t.Fatal(err)
	}
	if store.scimUserTenantID != "ten_1" || store.scimUserActorID != "scim_sync" || store.scimUserReplace || store.scimUserName != "person@example.com" {
		t.Fatalf("SCIM create user was not scoped correctly: tenant=%q actor=%q replace=%v user=%q", store.scimUserTenantID, store.scimUserActorID, store.scimUserReplace, store.scimUserName)
	}
	if _, err := svc.SCIMReplaceUser(context.Background(), actor, SCIMUserRequest{ID: "usr_scim", UserName: "renamed@example.com"}); err != nil {
		t.Fatal(err)
	}
	if !store.scimUserReplace || store.scimUserName != "renamed@example.com" {
		t.Fatalf("SCIM replace user did not set replace flag/name: replace=%v name=%q", store.scimUserReplace, store.scimUserName)
	}
	if _, err := svc.SCIMListUsers(context.Background(), actor, 500); err != nil {
		t.Fatal(err)
	}
	if store.scimListUsersTenantID != "ten_1" || store.scimListUsersLimit != 50 {
		t.Fatalf("SCIM list users tenant/limit=%q/%d", store.scimListUsersTenantID, store.scimListUsersLimit)
	}
	if _, err := svc.SCIMGetUser(context.Background(), actor, "usr_scim"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SCIMPatchUser(context.Background(), actor, "usr_scim", SCIMPatchRequest{Operations: []SCIMOperation{{Op: "replace", Path: "active"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SCIMDeactivateUser(context.Background(), actor, "usr_scim"); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.SCIMCreateGroup(context.Background(), actor, SCIMGroupRequest{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected missing SCIM displayName to be rejected, got %v", err)
	}
	if _, err := svc.SCIMCreateGroup(context.Background(), actor, SCIMGroupRequest{DisplayName: "Support"}); err != nil {
		t.Fatal(err)
	}
	if store.scimGroupTenantID != "ten_1" || store.scimGroupActorID != "scim_sync" || store.scimGroupReplace || store.scimGroupName != "Support" {
		t.Fatalf("SCIM create group was not scoped correctly: tenant=%q actor=%q replace=%v group=%q", store.scimGroupTenantID, store.scimGroupActorID, store.scimGroupReplace, store.scimGroupName)
	}
	if _, err := svc.SCIMReplaceGroup(context.Background(), actor, SCIMGroupRequest{ID: "grp_scim", DisplayName: "Security"}); err != nil {
		t.Fatal(err)
	}
	if !store.scimGroupReplace || store.scimGroupName != "Security" {
		t.Fatalf("SCIM replace group did not set replace flag/name: replace=%v name=%q", store.scimGroupReplace, store.scimGroupName)
	}
	if _, err := svc.SCIMListGroups(context.Background(), actor, 500); err != nil {
		t.Fatal(err)
	}
	if store.scimListGroupsTenantID != "ten_1" || store.scimListGroupsLimit != 50 {
		t.Fatalf("SCIM list groups tenant/limit=%q/%d", store.scimListGroupsTenantID, store.scimListGroupsLimit)
	}
	if _, err := svc.SCIMGetGroup(context.Background(), actor, "grp_scim"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SCIMPatchGroup(context.Background(), actor, "grp_scim", SCIMPatchRequest{Operations: []SCIMOperation{{Op: "add", Path: "members"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SCIMDeactivateGroup(context.Background(), actor, "grp_scim"); err != nil {
		t.Fatal(err)
	}
}

func TestEnterpriseRoleBindingsAndPoliciesValidateDangerousChanges(t *testing.T) {
	store := &enterpriseFakeStore{}
	svc := NewControlService(store, ssrf.Validator{})
	actor := authz.Actor{ID: "usr_security", TenantID: "ten_1", Role: authz.RoleSecurity, Scopes: []string{"security:read", "security:write"}}

	if _, err := svc.CreateRoleBinding(context.Background(), actor, CreateRoleBindingRequest{
		PrincipalType:  PrincipalUser,
		PrincipalID:    "usr_support",
		Role:           authz.RoleSupport,
		ResourceFamily: "incident",
		Environment:    "prod",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected role binding reason validation, got %v", err)
	}
	if _, err := svc.CreateRoleBinding(context.Background(), actor, CreateRoleBindingRequest{
		PrincipalType:  PrincipalUser,
		PrincipalID:    "usr_support",
		Role:           authz.RoleSupport,
		ResourceFamily: "incident",
		ResourceID:     "inc_1",
		Environment:    "prod",
		Reason:         "least privilege",
	}); err != nil {
		t.Fatal(err)
	}
	if store.roleBindingTenantID != "ten_1" || store.roleBindingActorID != "usr_security" {
		t.Fatalf("role binding create was not tenant/actor scoped: tenant=%q actor=%q", store.roleBindingTenantID, store.roleBindingActorID)
	}
	if _, err := svc.ListRoleBindings(context.Background(), actor, 500); err != nil {
		t.Fatal(err)
	}
	if store.listRoleBindingsTenantID != "ten_1" || store.listRoleBindingsLimit != 50 {
		t.Fatalf("role binding list tenant/limit=%q/%d", store.listRoleBindingsTenantID, store.listRoleBindingsLimit)
	}
	nextRole := authz.RoleDeveloper
	if _, err := svc.UpdateRoleBinding(context.Background(), actor, "rb_1", UpdateRoleBindingRequest{Role: &nextRole, Reason: "temporary access"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DisableRoleBinding(context.Background(), actor, "rb_1", StateChangeRequest{Reason: "expired"}); err != nil {
		t.Fatal(err)
	}
	if store.updatedRoleBindingID != "rb_1" || store.disabledRoleBindingID != "rb_1" {
		t.Fatalf("role binding update/disable did not target rb_1: update=%q disable=%q", store.updatedRoleBindingID, store.disabledRoleBindingID)
	}

	if _, err := svc.CreateAccessPolicyRule(context.Background(), actor, CreateAccessPolicyRuleRequest{
		Name:           "lockout",
		Action:         "security:write",
		Effect:         PolicyEffectDeny,
		ResourceFamily: "security",
		Environment:    "*",
		Reason:         "bad",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected self-locking deny policy to be rejected, got %v", err)
	}
	if _, err := svc.CreateAccessPolicyRule(context.Background(), actor, CreateAccessPolicyRuleRequest{
		Name:           "incident reads",
		Action:         "incidents:read",
		Effect:         PolicyEffectAllow,
		ResourceFamily: "incident",
		Environment:    "prod",
		Reason:         "support workflow",
	}); err != nil {
		t.Fatal(err)
	}
	if store.accessPolicyTenantID != "ten_1" || store.accessPolicyActorID != "usr_security" {
		t.Fatalf("access policy create was not tenant/actor scoped: tenant=%q actor=%q", store.accessPolicyTenantID, store.accessPolicyActorID)
	}
	if _, err := svc.ListAccessPolicyRules(context.Background(), actor, 500); err != nil {
		t.Fatal(err)
	}
	deny := PolicyEffectDeny
	securityWrite := "security:write"
	securityFamily := "security"
	allEnvironments := "*"
	if _, err := svc.UpdateAccessPolicyRule(context.Background(), actor, "apr_1", UpdateAccessPolicyRuleRequest{
		Effect:         &deny,
		Action:         &securityWrite,
		ResourceFamily: &securityFamily,
		Environment:    &allEnvironments,
		Reason:         "bad",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected self-locking update policy to be rejected, got %v", err)
	}
	policyName := "incident reads v2"
	if _, err := svc.UpdateAccessPolicyRule(context.Background(), actor, "apr_1", UpdateAccessPolicyRuleRequest{Name: &policyName, Reason: "rename"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DisableAccessPolicyRule(context.Background(), actor, "apr_1", StateChangeRequest{Reason: "superseded"}); err != nil {
		t.Fatal(err)
	}
	decision, err := svc.ExplainAuthorization(context.Background(), actor, AuthzExplainRequest{Action: "incidents:read", ResourceFamily: "incident", ResourceID: "inc_1"})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || store.explainTenantID != "ten_1" || store.explainActorID != "usr_security" {
		t.Fatalf("authorization explanation was not scoped: decision=%+v tenant=%q actor=%q", decision, store.explainTenantID, store.explainActorID)
	}
}

func TestCompleteOIDCCallbackValidatesIDTokenNonce(t *testing.T) {
	issuer := newFakeOIDCIssuer(t, "client", "wrong-nonce")
	store := &enterpriseFakeStore{
		idp: domain.IdentityProvider{
			ID:           "idp_1",
			TenantID:     "ten_1",
			IssuerURL:    issuer.URL,
			ClientID:     "client",
			ClientSecret: []byte("secret"),
			RedirectURI:  "https://webhookery.example/v1/auth/oidc/callback",
			State:        domain.StateActive,
		},
		loginState: domain.OIDCLoginState{
			TenantID:           "ten_1",
			IdentityProviderID: "idp_1",
			StateHash:          HashToken("state"),
			NonceHash:          HashToken("expected-nonce"),
			PKCEVerifier:       []byte("verifier"),
			ExpiresAt:          time.Now().Add(time.Hour),
		},
	}
	svc := NewControlService(store, ssrf.Validator{})

	_, err := svc.CompleteOIDCCallback(context.Background(), "state", "code", "user-agent", "127.0.0.1")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected nonce mismatch to be unauthorized, got %v", err)
	}
	if store.createdSession.SessionHash != "" {
		t.Fatal("OIDC session must not be created when nonce validation fails")
	}
}

func TestCompleteOIDCCallbackCreatesHashedSession(t *testing.T) {
	issuer := newFakeOIDCIssuer(t, "client", "expected-nonce")
	store := &enterpriseFakeStore{
		idp: domain.IdentityProvider{
			ID:                  "idp_1",
			TenantID:            "ten_1",
			IssuerURL:           issuer.URL,
			ClientID:            "client",
			ClientSecret:        []byte("secret"),
			RedirectURI:         "https://webhookery.example/v1/auth/oidc/callback",
			AllowedEmailDomains: []string{"example.com"},
			State:               domain.StateActive,
		},
		loginState: domain.OIDCLoginState{
			TenantID:           "ten_1",
			IdentityProviderID: "idp_1",
			StateHash:          HashToken("state"),
			NonceHash:          HashToken("expected-nonce"),
			PKCEVerifier:       []byte("verifier"),
			ExpiresAt:          time.Now().Add(time.Hour),
		},
	}
	svc := NewControlService(store, ssrf.Validator{})

	result, err := svc.CompleteOIDCCallback(context.Background(), "state", "code", "user-agent", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionToken == "" || store.createdSession.SessionHash == "" || !strings.HasPrefix(store.createdSession.SessionHash, "sha256:") {
		t.Fatalf("session token/hash not created correctly: result=%+v input=%+v", result, store.createdSession)
	}
	if strings.Contains(store.createdSession.SessionHash, result.SessionToken) {
		t.Fatal("raw session token leaked into persisted session hash")
	}
}

type enterpriseFakeStore struct {
	fakeControlStore
	identityTenantID         string
	listIdentityTenantID     string
	listIdentityLimit        int
	getIdentityTenantID      string
	getIdentityProviderID    string
	updatedProviderID        string
	updatedProviderReason    string
	disabledProviderID       string
	disabledProviderReason   string
	testedProviderID         string
	testedProviderReason     string
	scimToken                domain.SCIMToken
	idp                      domain.IdentityProvider
	loginState               domain.OIDCLoginState
	createdSession           OIDCSessionInput
	listAuthSessionTenantID  string
	listAuthSessionLimit     int
	revokedByIDTenantID      string
	revokedByIDSessionID     string
	revokedByIDActorID       string
	revokedByIDReason        string
	revokedSessionTenantID   string
	revokedSessionActorID    string
	revokedSessionHash       string
	revokedSessionReason     string
	currentSessionTenantID   string
	currentSessionActorID    string
	currentSessionHash       string
	scimAuthTokenHash        string
	scimUserTenantID         string
	scimUserActorID          string
	scimUserName             string
	scimUserReplace          bool
	scimListUsersTenantID    string
	scimListUsersLimit       int
	scimGroupTenantID        string
	scimGroupActorID         string
	scimGroupName            string
	scimGroupReplace         bool
	scimListGroupsTenantID   string
	scimListGroupsLimit      int
	roleBindingTenantID      string
	roleBindingActorID       string
	listRoleBindingsTenantID string
	listRoleBindingsLimit    int
	updatedRoleBindingID     string
	disabledRoleBindingID    string
	accessPolicyTenantID     string
	accessPolicyActorID      string
	listAccessPolicyTenantID string
	listAccessPolicyLimit    int
	updatedAccessPolicyID    string
	disabledAccessPolicyID   string
	explainTenantID          string
	explainActorID           string
}

func (s *enterpriseFakeStore) CreateIdentityProvider(_ context.Context, tenantID, actorID string, req CreateIdentityProviderRequest) (domain.IdentityProvider, error) {
	s.identityTenantID = tenantID
	return domain.IdentityProvider{ID: "idp_1", TenantID: tenantID, Name: req.Name, CreatedBy: actorID, State: domain.StateActive}, nil
}
func (s *enterpriseFakeStore) ListIdentityProviders(_ context.Context, tenantID string, limit int) ([]domain.IdentityProvider, error) {
	s.listIdentityTenantID = tenantID
	s.listIdentityLimit = limit
	return []domain.IdentityProvider{{ID: "idp_1", TenantID: tenantID, State: domain.StateActive}}, nil
}
func (s *enterpriseFakeStore) GetIdentityProvider(_ context.Context, tenantID, providerID string) (domain.IdentityProvider, error) {
	s.getIdentityTenantID = tenantID
	s.getIdentityProviderID = providerID
	return s.idp, nil
}
func (s *enterpriseFakeStore) UpdateIdentityProvider(_ context.Context, tenantID, providerID, actorID string, req UpdateIdentityProviderRequest) (domain.IdentityProvider, error) {
	s.updatedProviderID = providerID
	s.updatedProviderReason = req.Reason
	return domain.IdentityProvider{ID: providerID, TenantID: tenantID, UpdatedAt: time.Now().UTC(), CreatedBy: actorID, State: domain.StateActive}, nil
}
func (s *enterpriseFakeStore) DisableIdentityProvider(_ context.Context, tenantID, providerID, actorID, reason string) (domain.IdentityProvider, error) {
	s.disabledProviderID = providerID
	s.disabledProviderReason = reason
	return domain.IdentityProvider{ID: providerID, TenantID: tenantID, CreatedBy: actorID, State: domain.StateDisabled, DisabledAt: time.Now().UTC()}, nil
}
func (s *enterpriseFakeStore) TestIdentityProvider(_ context.Context, tenantID, providerID, actorID, reason string) (domain.IdentityProvider, error) {
	s.testedProviderID = providerID
	s.testedProviderReason = reason
	return domain.IdentityProvider{ID: providerID, TenantID: tenantID, CreatedBy: actorID, State: domain.StateActive}, nil
}
func (s *enterpriseFakeStore) CreateOIDCLoginState(_ context.Context, state domain.OIDCLoginState) error {
	s.loginState = state
	return nil
}
func (s *enterpriseFakeStore) ConsumeOIDCLoginState(context.Context, string) (domain.OIDCLoginState, domain.IdentityProvider, error) {
	return s.loginState, s.idp, nil
}
func (s *enterpriseFakeStore) CreateOIDCSession(_ context.Context, input OIDCSessionInput) (domain.AuthSession, authz.Actor, error) {
	s.createdSession = input
	return domain.AuthSession{ID: "ses_1", TenantID: input.TenantID, UserID: "usr_1", SessionHash: input.SessionHash, State: domain.StateActive, ExpiresAt: input.ExpiresAt}, authz.Actor{ID: "usr_1", TenantID: input.TenantID, Role: authz.RoleSupport}, nil
}
func (s *enterpriseFakeStore) ListAuthSessions(_ context.Context, tenantID string, limit int) ([]domain.AuthSession, error) {
	s.listAuthSessionTenantID = tenantID
	s.listAuthSessionLimit = limit
	return []domain.AuthSession{{ID: "ses_1", TenantID: tenantID, State: domain.StateActive}}, nil
}
func (s *enterpriseFakeStore) RevokeAuthSessionByID(_ context.Context, tenantID, sessionID, actorID, reason string) (domain.AuthSession, error) {
	s.revokedByIDTenantID = tenantID
	s.revokedByIDSessionID = sessionID
	s.revokedByIDActorID = actorID
	s.revokedByIDReason = reason
	return domain.AuthSession{ID: sessionID, TenantID: tenantID, UserID: actorID, State: "revoked", RevokedAt: time.Now().UTC()}, nil
}
func (s *enterpriseFakeStore) RevokeAuthSession(_ context.Context, tenantID, actorID, sessionHash, reason string) error {
	s.revokedSessionTenantID = tenantID
	s.revokedSessionActorID = actorID
	s.revokedSessionHash = sessionHash
	s.revokedSessionReason = reason
	return nil
}
func (s *enterpriseFakeStore) CurrentAuthSession(_ context.Context, tenantID, actorID, sessionHash string) (domain.AuthSession, error) {
	s.currentSessionTenantID = tenantID
	s.currentSessionActorID = actorID
	s.currentSessionHash = sessionHash
	return domain.AuthSession{ID: "ses_1", TenantID: tenantID, UserID: actorID, SessionHash: sessionHash, State: domain.StateActive}, nil
}
func (s *enterpriseFakeStore) AuthenticateSCIMTokenHash(_ context.Context, tokenHash string) (authz.Actor, error) {
	s.scimAuthTokenHash = tokenHash
	return authz.Actor{ID: "scim_sync", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"*"}}, nil
}
func (s *enterpriseFakeStore) CreateSCIMToken(_ context.Context, tenantID, actorID string, token domain.SCIMToken) (domain.SCIMToken, error) {
	s.scimToken = token
	token.Hash = ""
	token.TenantID = tenantID
	token.CreatedBy = actorID
	return token, nil
}
func (s *enterpriseFakeStore) ListSCIMTokens(_ context.Context, tenantID string, limit int) ([]domain.SCIMToken, error) {
	return []domain.SCIMToken{{ID: "sct_1", TenantID: tenantID, State: domain.StateActive}}, nil
}
func (s *enterpriseFakeStore) RevokeSCIMToken(_ context.Context, tenantID, tokenID, actorID, reason string) (domain.SCIMToken, error) {
	return domain.SCIMToken{ID: tokenID, TenantID: tenantID, CreatedBy: actorID, State: "revoked"}, nil
}
func (s *enterpriseFakeStore) SCIMCreateOrReplaceUser(_ context.Context, tenantID, actorID string, req SCIMUserRequest, replace bool) (SCIMUser, error) {
	s.scimUserTenantID = tenantID
	s.scimUserActorID = actorID
	s.scimUserName = req.UserName
	s.scimUserReplace = replace
	return SCIMUser{ID: "usr_scim", UserName: req.UserName, Active: true}, nil
}
func (s *enterpriseFakeStore) SCIMListUsers(_ context.Context, tenantID string, limit int) ([]SCIMUser, error) {
	s.scimListUsersTenantID = tenantID
	s.scimListUsersLimit = limit
	return []SCIMUser{{ID: "usr_scim", UserName: "person@example.com", Active: true}}, nil
}
func (s *enterpriseFakeStore) SCIMGetUser(_ context.Context, tenantID, userID string) (SCIMUser, error) {
	return SCIMUser{ID: userID, UserName: "person@example.com", Active: true}, nil
}
func (s *enterpriseFakeStore) SCIMPatchUser(_ context.Context, tenantID, actorID, userID string, req SCIMPatchRequest) (SCIMUser, error) {
	return SCIMUser{ID: userID, UserName: "person@example.com", Active: true}, nil
}
func (s *enterpriseFakeStore) SCIMDeactivateUser(_ context.Context, tenantID, actorID, userID string) (SCIMUser, error) {
	return SCIMUser{ID: userID, UserName: "person@example.com", Active: false}, nil
}
func (s *enterpriseFakeStore) SCIMCreateOrReplaceGroup(_ context.Context, tenantID, actorID string, req SCIMGroupRequest, replace bool) (SCIMGroup, error) {
	s.scimGroupTenantID = tenantID
	s.scimGroupActorID = actorID
	s.scimGroupName = req.DisplayName
	s.scimGroupReplace = replace
	return SCIMGroup{ID: "grp_scim", DisplayName: req.DisplayName, Active: true}, nil
}
func (s *enterpriseFakeStore) SCIMListGroups(_ context.Context, tenantID string, limit int) ([]SCIMGroup, error) {
	s.scimListGroupsTenantID = tenantID
	s.scimListGroupsLimit = limit
	return []SCIMGroup{{ID: "grp_scim", DisplayName: "Support", Active: true}}, nil
}
func (s *enterpriseFakeStore) SCIMGetGroup(_ context.Context, tenantID, groupID string) (SCIMGroup, error) {
	return SCIMGroup{ID: groupID, DisplayName: "Support", Active: true}, nil
}
func (s *enterpriseFakeStore) SCIMPatchGroup(_ context.Context, tenantID, actorID, groupID string, req SCIMPatchRequest) (SCIMGroup, error) {
	return SCIMGroup{ID: groupID, DisplayName: "Support", Active: true}, nil
}
func (s *enterpriseFakeStore) SCIMDeactivateGroup(_ context.Context, tenantID, actorID, groupID string) (SCIMGroup, error) {
	return SCIMGroup{ID: groupID, DisplayName: "Support", Active: false}, nil
}
func (s *enterpriseFakeStore) CreateRoleBinding(_ context.Context, tenantID, actorID string, req CreateRoleBindingRequest) (domain.RoleBinding, error) {
	s.roleBindingTenantID = tenantID
	s.roleBindingActorID = actorID
	return domain.RoleBinding{ID: "rb_1", TenantID: tenantID, PrincipalType: req.PrincipalType, PrincipalID: req.PrincipalID, Role: string(req.Role), ResourceFamily: req.ResourceFamily, ResourceID: req.ResourceID, Environment: req.Environment, CreatedBy: actorID, State: domain.StateActive}, nil
}
func (s *enterpriseFakeStore) ListRoleBindings(_ context.Context, tenantID string, limit int) ([]domain.RoleBinding, error) {
	s.listRoleBindingsTenantID = tenantID
	s.listRoleBindingsLimit = limit
	return []domain.RoleBinding{{ID: "rb_1", TenantID: tenantID, State: domain.StateActive}}, nil
}
func (s *enterpriseFakeStore) UpdateRoleBinding(_ context.Context, tenantID, bindingID, actorID string, req UpdateRoleBindingRequest) (domain.RoleBinding, error) {
	s.updatedRoleBindingID = bindingID
	return domain.RoleBinding{ID: bindingID, TenantID: tenantID, UpdatedAt: time.Now().UTC(), CreatedBy: actorID, State: domain.StateActive}, nil
}
func (s *enterpriseFakeStore) DisableRoleBinding(_ context.Context, tenantID, bindingID, actorID, reason string) (domain.RoleBinding, error) {
	s.disabledRoleBindingID = bindingID
	return domain.RoleBinding{ID: bindingID, TenantID: tenantID, CreatedBy: actorID, State: domain.StateDisabled, UpdatedAt: time.Now().UTC()}, nil
}
func (s *enterpriseFakeStore) CreateAccessPolicyRule(_ context.Context, tenantID, actorID string, req CreateAccessPolicyRuleRequest) (domain.AccessPolicyRule, error) {
	s.accessPolicyTenantID = tenantID
	s.accessPolicyActorID = actorID
	return domain.AccessPolicyRule{ID: "apr_1", TenantID: tenantID, Name: req.Name, Action: req.Action, Effect: req.Effect, ResourceFamily: req.ResourceFamily, Environment: req.Environment, CreatedBy: actorID, State: domain.StateActive}, nil
}
func (s *enterpriseFakeStore) ListAccessPolicyRules(_ context.Context, tenantID string, limit int) ([]domain.AccessPolicyRule, error) {
	s.listAccessPolicyTenantID = tenantID
	s.listAccessPolicyLimit = limit
	return []domain.AccessPolicyRule{{ID: "apr_1", TenantID: tenantID, State: domain.StateActive}}, nil
}
func (s *enterpriseFakeStore) UpdateAccessPolicyRule(_ context.Context, tenantID, policyID, actorID string, req UpdateAccessPolicyRuleRequest) (domain.AccessPolicyRule, error) {
	s.updatedAccessPolicyID = policyID
	return domain.AccessPolicyRule{ID: policyID, TenantID: tenantID, UpdatedAt: time.Now().UTC(), CreatedBy: actorID, State: domain.StateActive}, nil
}
func (s *enterpriseFakeStore) DisableAccessPolicyRule(_ context.Context, tenantID, policyID, actorID, reason string) (domain.AccessPolicyRule, error) {
	s.disabledAccessPolicyID = policyID
	return domain.AccessPolicyRule{ID: policyID, TenantID: tenantID, CreatedBy: actorID, State: domain.StateDisabled, UpdatedAt: time.Now().UTC()}, nil
}
func (s *enterpriseFakeStore) ExplainAuthorization(_ context.Context, tenantID, actorID string, req AuthzExplainRequest) (authz.Decision, error) {
	s.explainTenantID = tenantID
	s.explainActorID = actorID
	return authz.Decision{Allowed: true, Reason: "allowed by test policy", MatchedRoleBindingID: "rb_1"}, nil
}

func newFakeOIDCIssuer(t *testing.T, clientID, nonce string) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuerURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(t, w, map[string]any{
			"issuer":                 issuerURL,
			"authorization_endpoint": issuerURL + "/authorize",
			"token_endpoint":         issuerURL + "/token",
			"jwks_uri":               issuerURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(t, w, map[string]any{"keys": []map[string]any{rsaJWK(&key.PublicKey, "kid-1")}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := map[string]any{
			"iss":            issuerURL,
			"sub":            "sub_123",
			"aud":            clientID,
			"nonce":          nonce,
			"email":          "person@example.com",
			"email_verified": true,
			"name":           "Person Example",
			"iat":            time.Now().Add(-time.Minute).Unix(),
			"exp":            time.Now().Add(time.Hour).Unix(),
		}
		writeTestJSON(t, w, map[string]any{
			"access_token": "access",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     signedJWT(t, key, "kid-1", claims),
		})
	})
	server := httptest.NewServer(mux)
	issuerURL = server.URL
	t.Cleanup(server.Close)
	return server
}

func signedJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	encodedHeader := encodeJWTPart(t, header)
	encodedClaims := encodeJWTPart(t, claims)
	signingInput := encodedHeader + "." + encodedClaims
	sum := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func encodeJWTPart(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func rsaJWK(key *rsa.PublicKey, kid string) map[string]any {
	exponent := big.NewInt(int64(key.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"kid": kid,
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(exponent),
	}
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}
