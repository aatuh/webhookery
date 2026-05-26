package app

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/random"
)

const (
	IdentityProviderOIDC = "oidc"
	PrincipalUser        = "user"
	PrincipalGroup       = "group"
	PolicyEffectAllow    = "allow"
	PolicyEffectDeny     = "deny"
)

type EnterpriseIdentityStore interface {
	CreateIdentityProvider(ctx context.Context, tenantID, actorID string, req CreateIdentityProviderRequest) (domain.IdentityProvider, error)
	ListIdentityProviders(ctx context.Context, tenantID string, limit int) ([]domain.IdentityProvider, error)
	GetIdentityProvider(ctx context.Context, tenantID, providerID string) (domain.IdentityProvider, error)
	UpdateIdentityProvider(ctx context.Context, tenantID, providerID, actorID string, req UpdateIdentityProviderRequest) (domain.IdentityProvider, error)
	DisableIdentityProvider(ctx context.Context, tenantID, providerID, actorID, reason string) (domain.IdentityProvider, error)
	TestIdentityProvider(ctx context.Context, tenantID, providerID, actorID, reason string) (domain.IdentityProvider, error)
	CreateOIDCLoginState(ctx context.Context, state domain.OIDCLoginState) error
	ConsumeOIDCLoginState(ctx context.Context, stateHash string) (domain.OIDCLoginState, domain.IdentityProvider, error)
	CreateOIDCSession(ctx context.Context, input OIDCSessionInput) (domain.AuthSession, authz.Actor, error)
	ListAuthSessions(ctx context.Context, tenantID string, limit int) ([]domain.AuthSession, error)
	RevokeAuthSessionByID(ctx context.Context, tenantID, sessionID, actorID, reason string) (domain.AuthSession, error)
	RevokeAuthSession(ctx context.Context, tenantID, actorID, sessionHash, reason string) error
	CurrentAuthSession(ctx context.Context, tenantID, actorID, sessionHash string) (domain.AuthSession, error)
	AuthenticateSCIMTokenHash(ctx context.Context, tokenHash string) (authz.Actor, error)
	CreateSCIMToken(ctx context.Context, tenantID, actorID string, token domain.SCIMToken) (domain.SCIMToken, error)
	ListSCIMTokens(ctx context.Context, tenantID string, limit int) ([]domain.SCIMToken, error)
	RevokeSCIMToken(ctx context.Context, tenantID, tokenID, actorID, reason string) (domain.SCIMToken, error)
	SCIMCreateOrReplaceUser(ctx context.Context, tenantID, actorID string, req SCIMUserRequest, replace bool) (SCIMUser, error)
	SCIMListUsers(ctx context.Context, tenantID string, limit int) ([]SCIMUser, error)
	SCIMGetUser(ctx context.Context, tenantID, userID string) (SCIMUser, error)
	SCIMPatchUser(ctx context.Context, tenantID, actorID, userID string, req SCIMPatchRequest) (SCIMUser, error)
	SCIMDeactivateUser(ctx context.Context, tenantID, actorID, userID string) (SCIMUser, error)
	SCIMCreateOrReplaceGroup(ctx context.Context, tenantID, actorID string, req SCIMGroupRequest, replace bool) (SCIMGroup, error)
	SCIMListGroups(ctx context.Context, tenantID string, limit int) ([]SCIMGroup, error)
	SCIMGetGroup(ctx context.Context, tenantID, groupID string) (SCIMGroup, error)
	SCIMPatchGroup(ctx context.Context, tenantID, actorID, groupID string, req SCIMPatchRequest) (SCIMGroup, error)
	SCIMDeactivateGroup(ctx context.Context, tenantID, actorID, groupID string) (SCIMGroup, error)
	CreateRoleBinding(ctx context.Context, tenantID, actorID string, req CreateRoleBindingRequest) (domain.RoleBinding, error)
	ListRoleBindings(ctx context.Context, tenantID string, limit int) ([]domain.RoleBinding, error)
	UpdateRoleBinding(ctx context.Context, tenantID, bindingID, actorID string, req UpdateRoleBindingRequest) (domain.RoleBinding, error)
	DisableRoleBinding(ctx context.Context, tenantID, bindingID, actorID, reason string) (domain.RoleBinding, error)
	CreateAccessPolicyRule(ctx context.Context, tenantID, actorID string, req CreateAccessPolicyRuleRequest) (domain.AccessPolicyRule, error)
	ListAccessPolicyRules(ctx context.Context, tenantID string, limit int) ([]domain.AccessPolicyRule, error)
	UpdateAccessPolicyRule(ctx context.Context, tenantID, policyID, actorID string, req UpdateAccessPolicyRuleRequest) (domain.AccessPolicyRule, error)
	DisableAccessPolicyRule(ctx context.Context, tenantID, policyID, actorID, reason string) (domain.AccessPolicyRule, error)
	ExplainAuthorization(ctx context.Context, tenantID, actorID string, req AuthzExplainRequest) (authz.Decision, error)
}

type CreateIdentityProviderRequest struct {
	Name                string   `json:"name"`
	ProviderType        string   `json:"provider_type"`
	IssuerURL           string   `json:"issuer_url"`
	AuthorizationURL    string   `json:"authorization_endpoint,omitempty"`
	TokenURL            string   `json:"token_endpoint,omitempty"`
	JWKSURL             string   `json:"jwks_uri,omitempty"`
	ClientID            string   `json:"client_id"`
	ClientSecret        string   `json:"client_secret"`
	RedirectURI         string   `json:"redirect_uri,omitempty"`
	AllowedEmailDomains []string `json:"allowed_email_domains,omitempty"`
}

type UpdateIdentityProviderRequest struct {
	Name                *string  `json:"name,omitempty"`
	IssuerURL           *string  `json:"issuer_url,omitempty"`
	AuthorizationURL    *string  `json:"authorization_endpoint,omitempty"`
	TokenURL            *string  `json:"token_endpoint,omitempty"`
	JWKSURL             *string  `json:"jwks_uri,omitempty"`
	ClientID            *string  `json:"client_id,omitempty"`
	ClientSecret        *string  `json:"client_secret,omitempty"`
	RedirectURI         *string  `json:"redirect_uri,omitempty"`
	AllowedEmailDomains []string `json:"allowed_email_domains,omitempty"`
	State               *string  `json:"state,omitempty"`
	Reason              string   `json:"reason"`
}

type OIDCLoginStart struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"-"`
	Nonce   string `json:"-"`
}

type OIDCSessionInput struct {
	TenantID           string
	IdentityProviderID string
	ExternalSubject    string
	Email              string
	EmailVerified      bool
	DisplayName        string
	SessionHash        string
	UserAgentHash      string
	IPHash             string
	ExpiresAt          time.Time
}

type OIDCSessionResult struct {
	Session      domain.AuthSession `json:"session"`
	Actor        authz.Actor        `json:"actor"`
	SessionToken string             `json:"-"`
}

type CreateSCIMTokenRequest struct {
	Name string `json:"name"`
}

type SCIMTokenCreated struct {
	Token domain.SCIMToken `json:"token"`
	Value string           `json:"value"`
}

type SCIMUser struct {
	ID          string    `json:"id"`
	ExternalID  string    `json:"externalId,omitempty"`
	UserName    string    `json:"userName"`
	DisplayName string    `json:"displayName,omitempty"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
}

type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type SCIMUserRequest struct {
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName,omitempty"`
	Name        SCIMName `json:"name,omitempty"`
	Active      *bool    `json:"active,omitempty"`
}

type SCIMGroup struct {
	ID          string            `json:"id"`
	ExternalID  string            `json:"externalId,omitempty"`
	DisplayName string            `json:"displayName"`
	Active      bool              `json:"active"`
	Members     []SCIMGroupMember `json:"members,omitempty"`
}

type SCIMGroupMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

type SCIMGroupRequest struct {
	ID          string            `json:"id,omitempty"`
	ExternalID  string            `json:"externalId,omitempty"`
	DisplayName string            `json:"displayName"`
	Members     []SCIMGroupMember `json:"members,omitempty"`
}

type SCIMPatchRequest struct {
	Schemas    []string        `json:"schemas,omitempty"`
	Operations []SCIMOperation `json:"Operations"`
}

type SCIMOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

type CreateRoleBindingRequest struct {
	PrincipalType  string     `json:"principal_type"`
	PrincipalID    string     `json:"principal_id"`
	Role           authz.Role `json:"role"`
	ResourceFamily string     `json:"resource_family"`
	ResourceID     string     `json:"resource_id"`
	Environment    string     `json:"environment"`
	Reason         string     `json:"reason"`
}

type UpdateRoleBindingRequest struct {
	Role           *authz.Role `json:"role,omitempty"`
	ResourceFamily *string     `json:"resource_family,omitempty"`
	ResourceID     *string     `json:"resource_id,omitempty"`
	Environment    *string     `json:"environment,omitempty"`
	State          *string     `json:"state,omitempty"`
	Reason         string      `json:"reason"`
}

type CreateAccessPolicyRuleRequest struct {
	Name           string          `json:"name"`
	Action         string          `json:"action"`
	Effect         string          `json:"effect"`
	ResourceFamily string          `json:"resource_family"`
	Environment    string          `json:"environment"`
	Conditions     json.RawMessage `json:"conditions,omitempty"`
	Reason         string          `json:"reason"`
}

type UpdateAccessPolicyRuleRequest struct {
	Name           *string         `json:"name,omitempty"`
	Action         *string         `json:"action,omitempty"`
	Effect         *string         `json:"effect,omitempty"`
	ResourceFamily *string         `json:"resource_family,omitempty"`
	Environment    *string         `json:"environment,omitempty"`
	Conditions     json.RawMessage `json:"conditions,omitempty"`
	State          *string         `json:"state,omitempty"`
	Reason         string          `json:"reason"`
}

type AuthzExplainRequest struct {
	ActorID        string            `json:"actor_id,omitempty"`
	Action         string            `json:"action"`
	ResourceFamily string            `json:"resource_family"`
	ResourceID     string            `json:"resource_id,omitempty"`
	Environment    string            `json:"environment,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
}

func (s *ControlService) enterpriseStore() (EnterpriseIdentityStore, error) {
	store, ok := s.store.(EnterpriseIdentityStore)
	if !ok {
		return nil, fmt.Errorf("%w: enterprise identity store is unavailable", ErrInvalidInput)
	}
	return store, nil
}

func (s *ControlService) CreateIdentityProvider(ctx context.Context, actor authz.Actor, req CreateIdentityProviderRequest) (domain.IdentityProvider, error) {
	if !s.authorized(ctx, actor, "security:write", "identity_provider", "", "") {
		return domain.IdentityProvider{}, ErrForbidden
	}
	if err := validateIdentityProviderRequest(req); err != nil {
		return domain.IdentityProvider{}, err
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return domain.IdentityProvider{}, err
	}
	return store.CreateIdentityProvider(ctx, actor.TenantID, actor.ID, req)
}

func (s *ControlService) ListIdentityProviders(ctx context.Context, actor authz.Actor, limit int) ([]domain.IdentityProvider, error) {
	if !s.authorized(ctx, actor, "security:read", "identity_provider", "", "") {
		return nil, ErrForbidden
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return nil, err
	}
	return store.ListIdentityProviders(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetIdentityProvider(ctx context.Context, actor authz.Actor, providerID string) (domain.IdentityProvider, error) {
	if !s.authorized(ctx, actor, "security:read", "identity_provider", providerID, "") {
		return domain.IdentityProvider{}, ErrForbidden
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return domain.IdentityProvider{}, err
	}
	return store.GetIdentityProvider(ctx, actor.TenantID, providerID)
}

func (s *ControlService) UpdateIdentityProvider(ctx context.Context, actor authz.Actor, providerID string, req UpdateIdentityProviderRequest) (domain.IdentityProvider, error) {
	if !s.authorized(ctx, actor, "security:write", "identity_provider", providerID, "") {
		return domain.IdentityProvider{}, ErrForbidden
	}
	if strings.TrimSpace(req.Reason) == "" {
		return domain.IdentityProvider{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return domain.IdentityProvider{}, err
	}
	return store.UpdateIdentityProvider(ctx, actor.TenantID, providerID, actor.ID, req)
}

func (s *ControlService) DisableIdentityProvider(ctx context.Context, actor authz.Actor, providerID string, req StateChangeRequest) (domain.IdentityProvider, error) {
	if !s.authorized(ctx, actor, "security:write", "identity_provider", providerID, "") {
		return domain.IdentityProvider{}, ErrForbidden
	}
	if strings.TrimSpace(req.Reason) == "" {
		return domain.IdentityProvider{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return domain.IdentityProvider{}, err
	}
	return store.DisableIdentityProvider(ctx, actor.TenantID, providerID, actor.ID, req.Reason)
}

func (s *ControlService) TestIdentityProvider(ctx context.Context, actor authz.Actor, providerID string, req StateChangeRequest) (domain.IdentityProvider, error) {
	if !s.authorized(ctx, actor, "security:write", "identity_provider", providerID, "") {
		return domain.IdentityProvider{}, ErrForbidden
	}
	if strings.TrimSpace(req.Reason) == "" {
		return domain.IdentityProvider{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return domain.IdentityProvider{}, err
	}
	idp, err := store.GetIdentityProvider(ctx, actor.TenantID, providerID)
	if err != nil {
		return domain.IdentityProvider{}, err
	}
	provider, _, err := oidcProviderEndpoint(ctx, idp)
	if err != nil {
		return domain.IdentityProvider{}, err
	}
	if provider == nil && strings.TrimSpace(idp.JWKSURL) == "" {
		return domain.IdentityProvider{}, fmt.Errorf("%w: jwks_uri is required when OIDC discovery is unavailable", ErrInvalidInput)
	}
	return store.TestIdentityProvider(ctx, actor.TenantID, providerID, actor.ID, req.Reason)
}

func (s *ControlService) BeginOIDCLogin(ctx context.Context, tenantID, providerID, redirectAfter string) (OIDCLoginStart, error) {
	tenantID = strings.TrimSpace(tenantID)
	providerID = strings.TrimSpace(providerID)
	if tenantID == "" || providerID == "" {
		return OIDCLoginStart{}, fmt.Errorf("%w: tenant_id and provider_id are required", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return OIDCLoginStart{}, err
	}
	idp, err := store.GetIdentityProvider(ctx, tenantID, providerID)
	if err != nil {
		return OIDCLoginStart{}, err
	}
	if idp.State != domain.StateActive {
		return OIDCLoginStart{}, fmt.Errorf("%w: identity provider is disabled", ErrInvalidInput)
	}
	_, endpoint, err := oidcProviderEndpoint(ctx, idp)
	if err != nil {
		return OIDCLoginStart{}, err
	}
	state, err := random.Token("oidcst", 32)
	if err != nil {
		return OIDCLoginStart{}, err
	}
	nonce, err := random.Token("oidcn", 32)
	if err != nil {
		return OIDCLoginStart{}, err
	}
	verifier := oauth2.GenerateVerifier()
	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	loginState := domain.OIDCLoginState{
		TenantID:           idp.TenantID,
		IdentityProviderID: idp.ID,
		StateHash:          HashToken(state),
		NonceHash:          HashToken(nonce),
		PKCEVerifier:       []byte(verifier),
		RedirectAfter:      safeRedirectPath(redirectAfter),
		ExpiresAt:          expiresAt,
	}
	if err := store.CreateOIDCLoginState(ctx, loginState); err != nil {
		return OIDCLoginStart{}, err
	}
	oauthConfig := oauth2.Config{
		ClientID:    idp.ClientID,
		RedirectURL: idp.RedirectURI,
		Scopes:      []string{oidc.ScopeOpenID, "email", "profile"},
		Endpoint:    endpoint,
	}
	return OIDCLoginStart{
		AuthURL: oauthConfig.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)),
		State:   state,
		Nonce:   nonce,
	}, nil
}

func (s *ControlService) CompleteOIDCCallback(ctx context.Context, rawState, code, userAgent, remoteAddr string) (OIDCSessionResult, error) {
	if strings.TrimSpace(rawState) == "" || strings.TrimSpace(code) == "" {
		return OIDCSessionResult{}, fmt.Errorf("%w: state and code are required", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return OIDCSessionResult{}, err
	}
	loginState, idp, err := store.ConsumeOIDCLoginState(ctx, HashToken(rawState))
	if err != nil {
		return OIDCSessionResult{}, err
	}
	if time.Now().UTC().After(loginState.ExpiresAt) {
		return OIDCSessionResult{}, fmt.Errorf("%w: oidc login state expired", ErrInvalidInput)
	}
	provider, endpoint, err := oidcProviderEndpoint(ctx, idp)
	if err != nil {
		return OIDCSessionResult{}, err
	}
	oauthConfig := oauth2.Config{
		ClientID:     idp.ClientID,
		ClientSecret: string(idp.ClientSecret),
		RedirectURL:  idp.RedirectURI,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		Endpoint:     endpoint,
	}
	token, err := oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(string(loginState.PKCEVerifier)))
	if err != nil {
		return OIDCSessionResult{}, fmt.Errorf("%w: oidc token exchange failed", ErrUnauthorized)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return OIDCSessionResult{}, fmt.Errorf("%w: missing id_token", ErrUnauthorized)
	}
	verifier := oidcVerifier(ctx, provider, idp)
	if verifier == nil {
		return OIDCSessionResult{}, fmt.Errorf("%w: oidc verifier unavailable", ErrUnauthorized)
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return OIDCSessionResult{}, fmt.Errorf("%w: oidc id_token verification failed", ErrUnauthorized)
	}
	var claims struct {
		Subject       string `json:"sub"`
		Nonce         string `json:"nonce"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return OIDCSessionResult{}, fmt.Errorf("%w: oidc claims invalid", ErrUnauthorized)
	}
	if claims.Subject == "" || claims.Nonce == "" || subtle.ConstantTimeCompare([]byte(HashToken(claims.Nonce)), []byte(loginState.NonceHash)) != 1 {
		return OIDCSessionResult{}, fmt.Errorf("%w: oidc nonce invalid", ErrUnauthorized)
	}
	if !emailDomainAllowed(claims.Email, idp.AllowedEmailDomains) {
		return OIDCSessionResult{}, fmt.Errorf("%w: oidc email domain is not allowed", ErrForbidden)
	}
	sessionToken, err := random.Token("sess", 32)
	if err != nil {
		return OIDCSessionResult{}, err
	}
	session, actor, err := store.CreateOIDCSession(ctx, OIDCSessionInput{
		TenantID:           idp.TenantID,
		IdentityProviderID: idp.ID,
		ExternalSubject:    claims.Subject,
		Email:              strings.ToLower(strings.TrimSpace(claims.Email)),
		EmailVerified:      claims.EmailVerified,
		DisplayName:        strings.TrimSpace(claims.Name),
		SessionHash:        HashToken(sessionToken),
		UserAgentHash:      HashToken(userAgent),
		IPHash:             HashToken(remoteAddr),
		ExpiresAt:          time.Now().UTC().Add(12 * time.Hour),
	})
	if err != nil {
		return OIDCSessionResult{}, err
	}
	return OIDCSessionResult{Session: session, Actor: actor, SessionToken: sessionToken}, nil
}

func (s *ControlService) LogoutSession(ctx context.Context, actor authz.Actor, rawSessionToken string) error {
	if rawSessionToken == "" {
		return ErrUnauthorized
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return err
	}
	return store.RevokeAuthSession(ctx, actor.TenantID, actor.ID, HashToken(rawSessionToken), "logout")
}

func (s *ControlService) CurrentAuthSession(ctx context.Context, actor authz.Actor, rawSessionToken string) (domain.AuthSession, error) {
	if rawSessionToken == "" {
		return domain.AuthSession{}, ErrUnauthorized
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return domain.AuthSession{}, err
	}
	return store.CurrentAuthSession(ctx, actor.TenantID, actor.ID, HashToken(rawSessionToken))
}

func (s *ControlService) ListAuthSessions(ctx context.Context, actor authz.Actor, limit int) ([]domain.AuthSession, error) {
	if !s.authorized(ctx, actor, "security:read", "auth_session", "", "") {
		return nil, ErrForbidden
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return nil, err
	}
	return store.ListAuthSessions(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) RevokeAuthSessionByID(ctx context.Context, actor authz.Actor, sessionID string, req StateChangeRequest) (domain.AuthSession, error) {
	if !s.authorized(ctx, actor, "security:write", "auth_session", sessionID, "") {
		return domain.AuthSession{}, ErrForbidden
	}
	if strings.TrimSpace(sessionID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.AuthSession{}, fmt.Errorf("%w: session_id and reason are required", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return domain.AuthSession{}, err
	}
	return store.RevokeAuthSessionByID(ctx, actor.TenantID, sessionID, actor.ID, req.Reason)
}

func (s *ControlService) AuthenticateSCIMToken(ctx context.Context, rawToken string) (authz.Actor, error) {
	if rawToken == "" {
		return authz.Actor{}, ErrUnauthorized
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return authz.Actor{}, err
	}
	return store.AuthenticateSCIMTokenHash(ctx, HashToken(rawToken))
}

func (s *ControlService) CreateSCIMToken(ctx context.Context, actor authz.Actor, req CreateSCIMTokenRequest) (SCIMTokenCreated, error) {
	if !s.authorized(ctx, actor, "security:write", "scim_token", "", "") {
		return SCIMTokenCreated{}, ErrForbidden
	}
	if strings.TrimSpace(req.Name) == "" {
		return SCIMTokenCreated{}, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	rawToken, err := random.Token("scim", 32)
	if err != nil {
		return SCIMTokenCreated{}, err
	}
	token := domain.SCIMToken{
		TenantID: actor.TenantID,
		Name:     strings.TrimSpace(req.Name),
		Hash:     HashToken(rawToken),
		Prefix:   tokenPrefix(rawToken),
		Last4:    tokenLast4(rawToken),
		State:    domain.StateActive,
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return SCIMTokenCreated{}, err
	}
	created, err := store.CreateSCIMToken(ctx, actor.TenantID, actor.ID, token)
	if err != nil {
		return SCIMTokenCreated{}, err
	}
	return SCIMTokenCreated{Token: created, Value: rawToken}, nil
}

func (s *ControlService) ListSCIMTokens(ctx context.Context, actor authz.Actor, limit int) ([]domain.SCIMToken, error) {
	if !s.authorized(ctx, actor, "security:read", "scim_token", "", "") {
		return nil, ErrForbidden
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return nil, err
	}
	return store.ListSCIMTokens(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) RevokeSCIMToken(ctx context.Context, actor authz.Actor, tokenID string, req StateChangeRequest) (domain.SCIMToken, error) {
	if !s.authorized(ctx, actor, "security:write", "scim_token", tokenID, "") {
		return domain.SCIMToken{}, ErrForbidden
	}
	if strings.TrimSpace(req.Reason) == "" {
		return domain.SCIMToken{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return domain.SCIMToken{}, err
	}
	return store.RevokeSCIMToken(ctx, actor.TenantID, tokenID, actor.ID, req.Reason)
}

func (s *ControlService) SCIMCreateUser(ctx context.Context, actor authz.Actor, req SCIMUserRequest) (SCIMUser, error) {
	return s.scimCreateOrReplaceUser(ctx, actor, req, false)
}

func (s *ControlService) SCIMReplaceUser(ctx context.Context, actor authz.Actor, req SCIMUserRequest) (SCIMUser, error) {
	return s.scimCreateOrReplaceUser(ctx, actor, req, true)
}

func (s *ControlService) scimCreateOrReplaceUser(ctx context.Context, actor authz.Actor, req SCIMUserRequest, replace bool) (SCIMUser, error) {
	if actor.TenantID == "" {
		return SCIMUser{}, ErrUnauthorized
	}
	if strings.TrimSpace(req.UserName) == "" {
		return SCIMUser{}, fmt.Errorf("%w: userName is required", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return SCIMUser{}, err
	}
	return store.SCIMCreateOrReplaceUser(ctx, actor.TenantID, actor.ID, req, replace)
}

func (s *ControlService) SCIMListUsers(ctx context.Context, actor authz.Actor, limit int) ([]SCIMUser, error) {
	store, err := s.enterpriseStore()
	if err != nil {
		return nil, err
	}
	return store.SCIMListUsers(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) SCIMGetUser(ctx context.Context, actor authz.Actor, userID string) (SCIMUser, error) {
	store, err := s.enterpriseStore()
	if err != nil {
		return SCIMUser{}, err
	}
	return store.SCIMGetUser(ctx, actor.TenantID, userID)
}

func (s *ControlService) SCIMPatchUser(ctx context.Context, actor authz.Actor, userID string, req SCIMPatchRequest) (SCIMUser, error) {
	store, err := s.enterpriseStore()
	if err != nil {
		return SCIMUser{}, err
	}
	return store.SCIMPatchUser(ctx, actor.TenantID, actor.ID, userID, req)
}

func (s *ControlService) SCIMDeactivateUser(ctx context.Context, actor authz.Actor, userID string) (SCIMUser, error) {
	store, err := s.enterpriseStore()
	if err != nil {
		return SCIMUser{}, err
	}
	return store.SCIMDeactivateUser(ctx, actor.TenantID, actor.ID, userID)
}

func (s *ControlService) SCIMCreateGroup(ctx context.Context, actor authz.Actor, req SCIMGroupRequest) (SCIMGroup, error) {
	return s.scimCreateOrReplaceGroup(ctx, actor, req, false)
}

func (s *ControlService) SCIMReplaceGroup(ctx context.Context, actor authz.Actor, req SCIMGroupRequest) (SCIMGroup, error) {
	return s.scimCreateOrReplaceGroup(ctx, actor, req, true)
}

func (s *ControlService) scimCreateOrReplaceGroup(ctx context.Context, actor authz.Actor, req SCIMGroupRequest, replace bool) (SCIMGroup, error) {
	if actor.TenantID == "" {
		return SCIMGroup{}, ErrUnauthorized
	}
	if strings.TrimSpace(req.DisplayName) == "" {
		return SCIMGroup{}, fmt.Errorf("%w: displayName is required", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return SCIMGroup{}, err
	}
	return store.SCIMCreateOrReplaceGroup(ctx, actor.TenantID, actor.ID, req, replace)
}

func (s *ControlService) SCIMListGroups(ctx context.Context, actor authz.Actor, limit int) ([]SCIMGroup, error) {
	store, err := s.enterpriseStore()
	if err != nil {
		return nil, err
	}
	return store.SCIMListGroups(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) SCIMGetGroup(ctx context.Context, actor authz.Actor, groupID string) (SCIMGroup, error) {
	store, err := s.enterpriseStore()
	if err != nil {
		return SCIMGroup{}, err
	}
	return store.SCIMGetGroup(ctx, actor.TenantID, groupID)
}

func (s *ControlService) SCIMPatchGroup(ctx context.Context, actor authz.Actor, groupID string, req SCIMPatchRequest) (SCIMGroup, error) {
	store, err := s.enterpriseStore()
	if err != nil {
		return SCIMGroup{}, err
	}
	return store.SCIMPatchGroup(ctx, actor.TenantID, actor.ID, groupID, req)
}

func (s *ControlService) SCIMDeactivateGroup(ctx context.Context, actor authz.Actor, groupID string) (SCIMGroup, error) {
	store, err := s.enterpriseStore()
	if err != nil {
		return SCIMGroup{}, err
	}
	return store.SCIMDeactivateGroup(ctx, actor.TenantID, actor.ID, groupID)
}

func (s *ControlService) CreateRoleBinding(ctx context.Context, actor authz.Actor, req CreateRoleBindingRequest) (domain.RoleBinding, error) {
	if !s.authorized(ctx, actor, "security:write", "role_binding", "", "") {
		return domain.RoleBinding{}, ErrForbidden
	}
	if err := validateRoleBinding(req.PrincipalType, req.PrincipalID, req.ResourceFamily, req.Environment, req.Reason); err != nil {
		return domain.RoleBinding{}, err
	}
	if !validRole(req.Role) {
		return domain.RoleBinding{}, fmt.Errorf("%w: invalid role", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return domain.RoleBinding{}, err
	}
	return store.CreateRoleBinding(ctx, actor.TenantID, actor.ID, req)
}

func (s *ControlService) ListRoleBindings(ctx context.Context, actor authz.Actor, limit int) ([]domain.RoleBinding, error) {
	if !s.authorized(ctx, actor, "security:read", "role_binding", "", "") {
		return nil, ErrForbidden
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return nil, err
	}
	return store.ListRoleBindings(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) UpdateRoleBinding(ctx context.Context, actor authz.Actor, bindingID string, req UpdateRoleBindingRequest) (domain.RoleBinding, error) {
	if !s.authorized(ctx, actor, "security:write", "role_binding", bindingID, "") {
		return domain.RoleBinding{}, ErrForbidden
	}
	if strings.TrimSpace(req.Reason) == "" {
		return domain.RoleBinding{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return domain.RoleBinding{}, err
	}
	return store.UpdateRoleBinding(ctx, actor.TenantID, bindingID, actor.ID, req)
}

func (s *ControlService) DisableRoleBinding(ctx context.Context, actor authz.Actor, bindingID string, req StateChangeRequest) (domain.RoleBinding, error) {
	if !s.authorized(ctx, actor, "security:write", "role_binding", bindingID, "") {
		return domain.RoleBinding{}, ErrForbidden
	}
	if strings.TrimSpace(req.Reason) == "" {
		return domain.RoleBinding{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return domain.RoleBinding{}, err
	}
	return store.DisableRoleBinding(ctx, actor.TenantID, bindingID, actor.ID, req.Reason)
}

func (s *ControlService) CreateAccessPolicyRule(ctx context.Context, actor authz.Actor, req CreateAccessPolicyRuleRequest) (domain.AccessPolicyRule, error) {
	if !s.authorized(ctx, actor, "security:write", "access_policy", "", "") {
		return domain.AccessPolicyRule{}, ErrForbidden
	}
	if err := validateAccessPolicy(req.Name, req.Action, req.Effect, req.ResourceFamily, req.Environment, req.Conditions, req.Reason); err != nil {
		return domain.AccessPolicyRule{}, err
	}
	if wouldDenySecurityWrite(req.Effect, req.Action, req.ResourceFamily, req.Environment) {
		return domain.AccessPolicyRule{}, fmt.Errorf("%w: refusing policy that can lock out security administration", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return domain.AccessPolicyRule{}, err
	}
	return store.CreateAccessPolicyRule(ctx, actor.TenantID, actor.ID, req)
}

func (s *ControlService) ListAccessPolicyRules(ctx context.Context, actor authz.Actor, limit int) ([]domain.AccessPolicyRule, error) {
	if !s.authorized(ctx, actor, "security:read", "access_policy", "", "") {
		return nil, ErrForbidden
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return nil, err
	}
	return store.ListAccessPolicyRules(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) UpdateAccessPolicyRule(ctx context.Context, actor authz.Actor, policyID string, req UpdateAccessPolicyRuleRequest) (domain.AccessPolicyRule, error) {
	if !s.authorized(ctx, actor, "security:write", "access_policy", policyID, "") {
		return domain.AccessPolicyRule{}, ErrForbidden
	}
	if strings.TrimSpace(req.Reason) == "" {
		return domain.AccessPolicyRule{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	if req.Effect != nil || req.Action != nil || req.ResourceFamily != nil || req.Environment != nil {
		effect := ""
		action := ""
		resourceFamily := ""
		environment := ""
		if req.Effect != nil {
			effect = *req.Effect
		}
		if req.Action != nil {
			action = *req.Action
		}
		if req.ResourceFamily != nil {
			resourceFamily = *req.ResourceFamily
		}
		if req.Environment != nil {
			environment = *req.Environment
		}
		if wouldDenySecurityWrite(effect, action, resourceFamily, environment) {
			return domain.AccessPolicyRule{}, fmt.Errorf("%w: refusing policy that can lock out security administration", ErrInvalidInput)
		}
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return domain.AccessPolicyRule{}, err
	}
	return store.UpdateAccessPolicyRule(ctx, actor.TenantID, policyID, actor.ID, req)
}

func (s *ControlService) DisableAccessPolicyRule(ctx context.Context, actor authz.Actor, policyID string, req StateChangeRequest) (domain.AccessPolicyRule, error) {
	if !s.authorized(ctx, actor, "security:write", "access_policy", policyID, "") {
		return domain.AccessPolicyRule{}, ErrForbidden
	}
	if strings.TrimSpace(req.Reason) == "" {
		return domain.AccessPolicyRule{}, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return domain.AccessPolicyRule{}, err
	}
	return store.DisableAccessPolicyRule(ctx, actor.TenantID, policyID, actor.ID, req.Reason)
}

func (s *ControlService) ExplainAuthorization(ctx context.Context, actor authz.Actor, req AuthzExplainRequest) (authz.Decision, error) {
	if !s.authorized(ctx, actor, "security:read", "authz", "", "") {
		return authz.Decision{}, ErrForbidden
	}
	if strings.TrimSpace(req.Action) == "" || strings.TrimSpace(req.ResourceFamily) == "" {
		return authz.Decision{}, fmt.Errorf("%w: action and resource_family are required", ErrInvalidInput)
	}
	store, err := s.enterpriseStore()
	if err != nil {
		return authz.Decision{}, err
	}
	targetActorID := actor.ID
	if strings.TrimSpace(req.ActorID) != "" {
		targetActorID = strings.TrimSpace(req.ActorID)
	}
	return store.ExplainAuthorization(ctx, actor.TenantID, targetActorID, req)
}

func (s *ControlService) authorized(ctx context.Context, actor authz.Actor, action, resourceFamily, resourceID, environment string) bool {
	return s.authorizer.Authorize(ctx, AuthorizationRequest{
		Actor:          actor,
		TenantID:       actor.TenantID,
		Action:         action,
		ResourceFamily: resourceFamily,
		ResourceID:     resourceID,
		Environment:    environment,
	}).Allowed
}

func actorScopesAllow(actor authz.Actor, action string) bool {
	if len(actor.Scopes) == 0 {
		return true
	}
	for _, scope := range actor.Scopes {
		if scope == "*" || scope == action {
			return true
		}
	}
	return false
}

func validateIdentityProviderRequest(req CreateIdentityProviderRequest) error {
	providerType := req.ProviderType
	if providerType == "" {
		providerType = IdentityProviderOIDC
	}
	if providerType != IdentityProviderOIDC {
		return fmt.Errorf("%w: only oidc identity providers are supported", ErrInvalidInput)
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.IssuerURL) == "" || strings.TrimSpace(req.ClientID) == "" || strings.TrimSpace(req.ClientSecret) == "" {
		return fmt.Errorf("%w: name, issuer_url, client_id, and client_secret are required", ErrInvalidInput)
	}
	if _, err := url.ParseRequestURI(req.IssuerURL); err != nil {
		return fmt.Errorf("%w: issuer_url must be an absolute URL", ErrInvalidInput)
	}
	if strings.TrimSpace(req.RedirectURI) != "" {
		if _, err := url.ParseRequestURI(req.RedirectURI); err != nil {
			return fmt.Errorf("%w: redirect_uri must be an absolute URL", ErrInvalidInput)
		}
	}
	return nil
}

func validateRoleBinding(principalType, principalID, resourceFamily, environment, reason string) error {
	if principalType != PrincipalUser && principalType != PrincipalGroup {
		return fmt.Errorf("%w: principal_type must be user or group", ErrInvalidInput)
	}
	if strings.TrimSpace(principalID) == "" {
		return fmt.Errorf("%w: principal_id is required", ErrInvalidInput)
	}
	if strings.TrimSpace(resourceFamily) == "" || strings.TrimSpace(environment) == "" {
		return fmt.Errorf("%w: resource_family and environment are required", ErrInvalidInput)
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	return nil
}

func validateAccessPolicy(name, action, effect, resourceFamily, environment string, conditions json.RawMessage, reason string) error {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(action) == "" || strings.TrimSpace(resourceFamily) == "" || strings.TrimSpace(environment) == "" {
		return fmt.Errorf("%w: name, action, resource_family, and environment are required", ErrInvalidInput)
	}
	if effect != PolicyEffectAllow && effect != PolicyEffectDeny {
		return fmt.Errorf("%w: effect must be allow or deny", ErrInvalidInput)
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	if len(conditions) > 0 && !json.Valid(conditions) {
		return fmt.Errorf("%w: conditions must be valid JSON", ErrInvalidInput)
	}
	return nil
}

func wouldDenySecurityWrite(effect, action, resourceFamily, environment string) bool {
	return strings.EqualFold(strings.TrimSpace(effect), PolicyEffectDeny) &&
		(strings.TrimSpace(action) == "security:write" || strings.TrimSpace(action) == "*") &&
		(identityWildcard(resourceFamily) == "*" || strings.EqualFold(strings.TrimSpace(resourceFamily), "security")) &&
		identityWildcard(environment) == "*"
}

func identityWildcard(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "*"
	}
	return value
}

func oidcProviderEndpoint(ctx context.Context, idp domain.IdentityProvider) (*oidc.Provider, oauth2.Endpoint, error) {
	provider, err := oidc.NewProvider(ctx, idp.IssuerURL)
	if err != nil {
		if idp.AuthorizationURL == "" || idp.TokenURL == "" {
			return nil, oauth2.Endpoint{}, fmt.Errorf("%w: oidc discovery failed", ErrInvalidInput)
		}
		return nil, oauth2.Endpoint{AuthURL: idp.AuthorizationURL, TokenURL: idp.TokenURL}, nil
	}
	endpoint := provider.Endpoint()
	if idp.AuthorizationURL != "" {
		endpoint.AuthURL = idp.AuthorizationURL
	}
	if idp.TokenURL != "" {
		endpoint.TokenURL = idp.TokenURL
	}
	return provider, endpoint, nil
}

func oidcVerifier(ctx context.Context, provider *oidc.Provider, idp domain.IdentityProvider) *oidc.IDTokenVerifier {
	config := &oidc.Config{ClientID: idp.ClientID}
	if provider != nil {
		return provider.Verifier(config)
	}
	if strings.TrimSpace(idp.JWKSURL) == "" {
		return nil
	}
	return oidc.NewVerifier(idp.IssuerURL, oidc.NewRemoteKeySet(ctx, idp.JWKSURL), config)
}

func emailDomainAllowed(email string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	_, domainPart, ok := strings.Cut(strings.ToLower(strings.TrimSpace(email)), "@")
	if !ok || domainPart == "" {
		return false
	}
	for _, item := range allowed {
		if strings.EqualFold(strings.TrimSpace(item), domainPart) {
			return true
		}
	}
	return false
}

func safeRedirectPath(raw string) string {
	if raw == "" {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || strings.HasPrefix(raw, "//") {
		return "/"
	}
	if !strings.HasPrefix(u.Path, "/") {
		return "/"
	}
	if u.RawQuery != "" {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path
}
