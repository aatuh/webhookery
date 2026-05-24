package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/domain"
)

func (s *Store) AuthenticateSession(ctx context.Context, sessionHash string) (authz.Actor, error) {
	var actor authz.Actor
	var role string
	err := s.pool.QueryRow(ctx, `
		SELECT sess.user_id, sess.tenant_id, m.role
		FROM auth_sessions sess
		JOIN memberships m ON m.tenant_id=sess.tenant_id AND m.user_id=sess.user_id AND m.state='active'
		LEFT JOIN external_identities ei ON ei.id=sess.external_identity_id
		LEFT JOIN identity_providers idp ON idp.id=ei.identity_provider_id
		WHERE sess.session_hash=$1
		  AND sess.state='active'
		  AND sess.expires_at > now()
		  AND (ei.id IS NULL OR ei.state='active')
		  AND (idp.id IS NULL OR idp.state='active')`,
		sessionHash,
	).Scan(&actor.ID, &actor.TenantID, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.Actor{}, app.ErrUnauthorized
	}
	if err != nil {
		return authz.Actor{}, err
	}
	actor.Role = authz.Role(role)
	_, _ = s.pool.Exec(ctx, `UPDATE auth_sessions SET last_seen_at=now() WHERE session_hash=$1`, sessionHash)
	return actor, nil
}

func (s *Store) CreateIdentityProvider(ctx context.Context, tenantID, actorID string, req app.CreateIdentityProviderRequest) (domain.IdentityProvider, error) {
	if req.ProviderType == "" {
		req.ProviderType = app.IdentityProviderOIDC
	}
	encryptedSecret, err := s.box.Encrypt([]byte(req.ClientSecret))
	if err != nil {
		return domain.IdentityProvider{}, err
	}
	idp := domain.IdentityProvider{
		ID:                  mustID("idp"),
		TenantID:            tenantID,
		Name:                strings.TrimSpace(req.Name),
		ProviderType:        req.ProviderType,
		IssuerURL:           strings.TrimSpace(req.IssuerURL),
		AuthorizationURL:    strings.TrimSpace(req.AuthorizationURL),
		TokenURL:            strings.TrimSpace(req.TokenURL),
		JWKSURL:             strings.TrimSpace(req.JWKSURL),
		ClientID:            strings.TrimSpace(req.ClientID),
		RedirectURI:         strings.TrimSpace(req.RedirectURI),
		AllowedEmailDomains: normalizeStringList(req.AllowedEmailDomains),
		State:               domain.StateActive,
		CreatedBy:           actorID,
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.IdentityProvider{}, err
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, "INSERT INTO tenants(id, name) VALUES($1, $1) ON CONFLICT (id) DO NOTHING", tenantID); err != nil {
		return domain.IdentityProvider{}, err
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO identity_providers(id, tenant_id, name, provider_type, issuer_url, authorization_endpoint, token_endpoint, jwks_uri,
			client_id, encrypted_client_secret, redirect_uri, allowed_email_domains, state, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		RETURNING created_at, updated_at`,
		idp.ID, idp.TenantID, idp.Name, idp.ProviderType, idp.IssuerURL, idp.AuthorizationURL, idp.TokenURL, idp.JWKSURL,
		idp.ClientID, encryptedSecret, idp.RedirectURI, idp.AllowedEmailDomains, idp.State, idp.CreatedBy,
	).Scan(&idp.CreatedAt, &idp.UpdatedAt)
	if err != nil {
		return domain.IdentityProvider{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "identity_provider.created", Resource: "identity_provider", ResourceID: idp.ID, Reason: idp.Name}); err != nil {
		return domain.IdentityProvider{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.IdentityProvider{}, err
	}
	return idp, nil
}

func (s *Store) ListIdentityProviders(ctx context.Context, tenantID string, limit int) ([]domain.IdentityProvider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, provider_type, issuer_url, authorization_endpoint, token_endpoint, jwks_uri, client_id,
		       redirect_uri, allowed_email_domains, state, created_by, created_at, updated_at, COALESCE(disabled_at, 'epoch'::timestamptz)
		FROM identity_providers
		WHERE tenant_id=$1
		ORDER BY created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.IdentityProvider
	for rows.Next() {
		var item domain.IdentityProvider
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Name, &item.ProviderType, &item.IssuerURL, &item.AuthorizationURL, &item.TokenURL, &item.JWKSURL,
			&item.ClientID, &item.RedirectURI, &item.AllowedEmailDomains, &item.State, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt, &item.DisabledAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetIdentityProvider(ctx context.Context, tenantID, providerID string) (domain.IdentityProvider, error) {
	item, _, err := s.getIdentityProvider(ctx, nil, tenantID, providerID, true)
	return item, err
}

func (s *Store) getIdentityProvider(ctx context.Context, tx pgx.Tx, tenantID, providerID string, decrypt bool) (domain.IdentityProvider, []byte, error) {
	var queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	} = s.pool
	if tx != nil {
		queryer = tx
	}
	var item domain.IdentityProvider
	var encrypted []byte
	err := queryer.QueryRow(ctx, `
		SELECT id, tenant_id, name, provider_type, issuer_url, authorization_endpoint, token_endpoint, jwks_uri, client_id,
		       encrypted_client_secret, redirect_uri, allowed_email_domains, state, created_by, created_at, updated_at,
		       COALESCE(disabled_at, 'epoch'::timestamptz)
		FROM identity_providers
		WHERE tenant_id=$1 AND id=$2`, tenantID, providerID).Scan(
		&item.ID, &item.TenantID, &item.Name, &item.ProviderType, &item.IssuerURL, &item.AuthorizationURL, &item.TokenURL, &item.JWKSURL, &item.ClientID,
		&encrypted, &item.RedirectURI, &item.AllowedEmailDomains, &item.State, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt, &item.DisabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.IdentityProvider{}, nil, app.ErrNotFound
	}
	if err != nil {
		return domain.IdentityProvider{}, nil, err
	}
	if decrypt {
		plain, err := s.box.Decrypt(encrypted)
		if err != nil {
			return domain.IdentityProvider{}, nil, err
		}
		item.ClientSecret = plain
	}
	return item, encrypted, nil
}

func (s *Store) UpdateIdentityProvider(ctx context.Context, tenantID, providerID, actorID string, req app.UpdateIdentityProviderRequest) (domain.IdentityProvider, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.IdentityProvider{}, err
	}
	defer rollback(ctx, tx)
	item, encryptedSecret, err := s.getIdentityProvider(ctx, tx, tenantID, providerID, false)
	if err != nil {
		return domain.IdentityProvider{}, err
	}
	if req.Name != nil {
		item.Name = strings.TrimSpace(*req.Name)
	}
	if req.IssuerURL != nil {
		item.IssuerURL = strings.TrimSpace(*req.IssuerURL)
	}
	if req.AuthorizationURL != nil {
		item.AuthorizationURL = strings.TrimSpace(*req.AuthorizationURL)
	}
	if req.TokenURL != nil {
		item.TokenURL = strings.TrimSpace(*req.TokenURL)
	}
	if req.JWKSURL != nil {
		item.JWKSURL = strings.TrimSpace(*req.JWKSURL)
	}
	if req.ClientID != nil {
		item.ClientID = strings.TrimSpace(*req.ClientID)
	}
	if req.RedirectURI != nil {
		item.RedirectURI = strings.TrimSpace(*req.RedirectURI)
	}
	if req.AllowedEmailDomains != nil {
		item.AllowedEmailDomains = normalizeStringList(req.AllowedEmailDomains)
	}
	if req.State != nil {
		item.State = strings.TrimSpace(*req.State)
	}
	if req.ClientSecret != nil {
		encryptedSecret, err = s.box.Encrypt([]byte(*req.ClientSecret))
		if err != nil {
			return domain.IdentityProvider{}, err
		}
	}
	err = tx.QueryRow(ctx, `
		UPDATE identity_providers
		SET name=$3, issuer_url=$4, authorization_endpoint=$5, token_endpoint=$6, jwks_uri=$7, client_id=$8,
		    encrypted_client_secret=$9, redirect_uri=$10, allowed_email_domains=$11, state=$12, updated_at=now(),
		    disabled_at=CASE WHEN $12='disabled' THEN COALESCE(disabled_at, now()) ELSE NULL END
		WHERE tenant_id=$1 AND id=$2
		RETURNING created_at, updated_at, COALESCE(disabled_at, 'epoch'::timestamptz)`,
		tenantID, providerID, item.Name, item.IssuerURL, item.AuthorizationURL, item.TokenURL, item.JWKSURL, item.ClientID,
		encryptedSecret, item.RedirectURI, item.AllowedEmailDomains, item.State,
	).Scan(&item.CreatedAt, &item.UpdatedAt, &item.DisabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.IdentityProvider{}, app.ErrNotFound
	}
	if err != nil {
		return domain.IdentityProvider{}, err
	}
	if item.State == domain.StateDisabled {
		if _, err := tx.Exec(ctx, `
			UPDATE auth_sessions sess
			SET state='revoked', revoked_at=now()
			FROM external_identities ei
			WHERE sess.external_identity_id=ei.id
			  AND ei.identity_provider_id=$1
			  AND sess.tenant_id=$2
			  AND sess.state='active'`, providerID, tenantID); err != nil {
			return domain.IdentityProvider{}, err
		}
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "identity_provider.updated", Resource: "identity_provider", ResourceID: providerID, Reason: req.Reason}); err != nil {
		return domain.IdentityProvider{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.IdentityProvider{}, err
	}
	return item, nil
}

func (s *Store) DisableIdentityProvider(ctx context.Context, tenantID, providerID, actorID, reason string) (domain.IdentityProvider, error) {
	state := domain.StateDisabled
	return s.UpdateIdentityProvider(ctx, tenantID, providerID, actorID, app.UpdateIdentityProviderRequest{State: &state, Reason: reason})
}

func (s *Store) TestIdentityProvider(ctx context.Context, tenantID, providerID, actorID, reason string) (domain.IdentityProvider, error) {
	item, err := s.GetIdentityProvider(ctx, tenantID, providerID)
	if err != nil {
		return domain.IdentityProvider{}, err
	}
	if err := s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "identity_provider.tested", Resource: "identity_provider", ResourceID: providerID, Reason: reason}); err != nil {
		return domain.IdentityProvider{}, err
	}
	item.ClientSecret = nil
	return item, nil
}

func (s *Store) CreateOIDCLoginState(ctx context.Context, state domain.OIDCLoginState) error {
	if state.ID == "" {
		state.ID = mustID("olst")
	}
	encryptedVerifier, err := s.box.Encrypt(state.PKCEVerifier)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO oidc_login_states(id, tenant_id, identity_provider_id, state_hash, nonce_hash, encrypted_pkce_verifier, redirect_after, expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		state.ID, state.TenantID, state.IdentityProviderID, state.StateHash, state.NonceHash, encryptedVerifier, state.RedirectAfter, state.ExpiresAt)
	return err
}

func (s *Store) ConsumeOIDCLoginState(ctx context.Context, stateHash string) (domain.OIDCLoginState, domain.IdentityProvider, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.OIDCLoginState{}, domain.IdentityProvider{}, err
	}
	defer rollback(ctx, tx)
	var state domain.OIDCLoginState
	var encryptedVerifier []byte
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, identity_provider_id, state_hash, nonce_hash, encrypted_pkce_verifier, redirect_after, expires_at, COALESCE(consumed_at, 'epoch'::timestamptz), created_at
		FROM oidc_login_states
		WHERE state_hash=$1
		FOR UPDATE`, stateHash).Scan(&state.ID, &state.TenantID, &state.IdentityProviderID, &state.StateHash, &state.NonceHash, &encryptedVerifier, &state.RedirectAfter, &state.ExpiresAt, &state.ConsumedAt, &state.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.OIDCLoginState{}, domain.IdentityProvider{}, app.ErrUnauthorized
	}
	if err != nil {
		return domain.OIDCLoginState{}, domain.IdentityProvider{}, err
	}
	if !state.ConsumedAt.IsZero() && !state.ConsumedAt.Equal(time.Unix(0, 0).UTC()) {
		return domain.OIDCLoginState{}, domain.IdentityProvider{}, app.ErrUnauthorized
	}
	plain, err := s.box.Decrypt(encryptedVerifier)
	if err != nil {
		return domain.OIDCLoginState{}, domain.IdentityProvider{}, err
	}
	state.PKCEVerifier = plain
	if _, err := tx.Exec(ctx, `UPDATE oidc_login_states SET consumed_at=now() WHERE id=$1`, state.ID); err != nil {
		return domain.OIDCLoginState{}, domain.IdentityProvider{}, err
	}
	idp, _, err := s.getIdentityProvider(ctx, tx, state.TenantID, state.IdentityProviderID, true)
	if err != nil {
		return domain.OIDCLoginState{}, domain.IdentityProvider{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.OIDCLoginState{}, domain.IdentityProvider{}, err
	}
	return state, idp, nil
}

func (s *Store) CreateOIDCSession(ctx context.Context, input app.OIDCSessionInput) (domain.AuthSession, authz.Actor, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AuthSession{}, authz.Actor{}, err
	}
	defer rollback(ctx, tx)
	userID, role, externalIdentityID, err := s.upsertOIDCIdentityTx(ctx, tx, input)
	if err != nil {
		return domain.AuthSession{}, authz.Actor{}, err
	}
	session := domain.AuthSession{
		ID:                 mustID("ses"),
		TenantID:           input.TenantID,
		UserID:             userID,
		ExternalIdentityID: externalIdentityID,
		SessionHash:        input.SessionHash,
		State:              domain.StateActive,
		UserAgentHash:      input.UserAgentHash,
		IPHash:             input.IPHash,
		ExpiresAt:          input.ExpiresAt,
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO auth_sessions(id, tenant_id, user_id, external_identity_id, session_hash, state, user_agent_hash, ip_hash, expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING created_at, last_seen_at`,
		session.ID, session.TenantID, session.UserID, session.ExternalIdentityID, session.SessionHash, session.State, session.UserAgentHash, session.IPHash, session.ExpiresAt,
	).Scan(&session.CreatedAt, &session.LastSeenAt)
	if err != nil {
		return domain.AuthSession{}, authz.Actor{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: input.TenantID, ActorID: userID, Action: "auth.login", Resource: "auth_session", ResourceID: session.ID, Reason: "oidc"}); err != nil {
		return domain.AuthSession{}, authz.Actor{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.AuthSession{}, authz.Actor{}, err
	}
	return session, authz.Actor{ID: userID, TenantID: input.TenantID, Role: authz.Role(role)}, nil
}

func (s *Store) upsertOIDCIdentityTx(ctx context.Context, tx pgx.Tx, input app.OIDCSessionInput) (string, string, string, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if email == "" {
		email = input.ExternalSubject + "@oidc.local"
	}
	displayName := strings.TrimSpace(input.DisplayName)
	if displayName == "" {
		displayName = email
	}
	var userID, membershipState, role string
	err := tx.QueryRow(ctx, `
		SELECT u.id, COALESCE(m.state,''), COALESCE(m.role,'')
		FROM users u
		LEFT JOIN memberships m ON m.tenant_id=$1 AND m.user_id=u.id
		WHERE lower(u.email)=lower($2)`, input.TenantID, email).Scan(&userID, &membershipState, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		userID = mustID("usr")
		if _, err := tx.Exec(ctx, `INSERT INTO users(id, email, name, state) VALUES($1,$2,$3,'active')`, userID, email, displayName); err != nil {
			return "", "", "", err
		}
		role = string(authz.RoleSupport)
		if _, err := tx.Exec(ctx, `INSERT INTO memberships(id, tenant_id, user_id, role, state) VALUES($1,$2,$3,$4,'active')`, mustID("mem"), input.TenantID, userID, role); err != nil {
			return "", "", "", err
		}
	} else if err != nil {
		return "", "", "", err
	} else {
		if membershipState == domain.StateDisabled || membershipState == domain.StateInactive {
			return "", "", "", app.ErrForbidden
		}
		if membershipState == "" {
			role = string(authz.RoleSupport)
			if _, err := tx.Exec(ctx, `INSERT INTO memberships(id, tenant_id, user_id, role, state) VALUES($1,$2,$3,$4,'active')`, mustID("mem"), input.TenantID, userID, role); err != nil {
				return "", "", "", err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET name=COALESCE(NULLIF($2,''), name), state='active' WHERE id=$1`, userID, displayName); err != nil {
			return "", "", "", err
		}
	}
	externalIdentityID := mustID("eid")
	err = tx.QueryRow(ctx, `
		INSERT INTO external_identities(id, tenant_id, user_id, identity_provider_id, external_subject, email, email_verified, display_name, state)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active')
		ON CONFLICT (tenant_id, identity_provider_id, external_subject)
		DO UPDATE SET user_id=EXCLUDED.user_id, email=EXCLUDED.email, email_verified=EXCLUDED.email_verified,
		              display_name=EXCLUDED.display_name, state='active', last_seen_at=now(), disabled_at=NULL
		RETURNING id`,
		externalIdentityID, input.TenantID, userID, input.IdentityProviderID, input.ExternalSubject, email, input.EmailVerified, displayName,
	).Scan(&externalIdentityID)
	if err != nil {
		return "", "", "", err
	}
	if role == "" {
		role = string(authz.RoleSupport)
	}
	return userID, role, externalIdentityID, nil
}

func (s *Store) RevokeAuthSession(ctx context.Context, tenantID, actorID, sessionHash, reason string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	var sessionID string
	err = tx.QueryRow(ctx, `
		UPDATE auth_sessions
		SET state='revoked', revoked_at=now()
		WHERE tenant_id=$1 AND session_hash=$2 AND state='active'
		RETURNING id`, tenantID, sessionHash).Scan(&sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "auth.logout", Resource: "auth_session", ResourceID: sessionID, Reason: reason}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ListAuthSessions(ctx context.Context, tenantID string, limit int) ([]domain.AuthSession, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, user_id, COALESCE(external_identity_id,''), state, created_at, last_seen_at, expires_at, COALESCE(revoked_at, 'epoch'::timestamptz)
		FROM auth_sessions
		WHERE tenant_id=$1
		ORDER BY created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AuthSession
	for rows.Next() {
		var item domain.AuthSession
		if err := rows.Scan(&item.ID, &item.TenantID, &item.UserID, &item.ExternalIdentityID, &item.State, &item.CreatedAt, &item.LastSeenAt, &item.ExpiresAt, &item.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAuthSessionByID(ctx context.Context, tenantID, sessionID, actorID, reason string) (domain.AuthSession, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AuthSession{}, err
	}
	defer rollback(ctx, tx)
	var item domain.AuthSession
	err = tx.QueryRow(ctx, `
		UPDATE auth_sessions
		SET state='revoked', revoked_at=now()
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, user_id, COALESCE(external_identity_id,''), state, created_at, last_seen_at, expires_at, COALESCE(revoked_at, 'epoch'::timestamptz)`,
		tenantID, sessionID).Scan(&item.ID, &item.TenantID, &item.UserID, &item.ExternalIdentityID, &item.State, &item.CreatedAt, &item.LastSeenAt, &item.ExpiresAt, &item.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AuthSession{}, app.ErrNotFound
	}
	if err != nil {
		return domain.AuthSession{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "auth_session.revoked", Resource: "auth_session", ResourceID: sessionID, Reason: reason}); err != nil {
		return domain.AuthSession{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) CurrentAuthSession(ctx context.Context, tenantID, actorID, sessionHash string) (domain.AuthSession, error) {
	var session domain.AuthSession
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, user_id, COALESCE(external_identity_id,''), state, created_at, last_seen_at, expires_at, COALESCE(revoked_at, 'epoch'::timestamptz)
		FROM auth_sessions
		WHERE tenant_id=$1 AND user_id=$2 AND session_hash=$3`, tenantID, actorID, sessionHash).Scan(
		&session.ID, &session.TenantID, &session.UserID, &session.ExternalIdentityID, &session.State, &session.CreatedAt, &session.LastSeenAt, &session.ExpiresAt, &session.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AuthSession{}, app.ErrNotFound
	}
	return session, err
}

func (s *Store) AuthenticateSCIMTokenHash(ctx context.Context, tokenHash string) (authz.Actor, error) {
	var tokenID, tenantID string
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id
		FROM scim_tokens
		WHERE token_hash=$1 AND state='active'`, tokenHash).Scan(&tokenID, &tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.Actor{}, app.ErrUnauthorized
	}
	if err != nil {
		return authz.Actor{}, err
	}
	_, _ = s.pool.Exec(ctx, `UPDATE scim_tokens SET last_used_at=now() WHERE id=$1`, tokenID)
	return authz.Actor{ID: "scim:" + tokenID, TenantID: tenantID, Role: authz.RoleSecurity, Scopes: []string{"*"}}, nil
}

func (s *Store) CreateSCIMToken(ctx context.Context, tenantID, actorID string, token domain.SCIMToken) (domain.SCIMToken, error) {
	if token.ID == "" {
		token.ID = mustID("sct")
	}
	token.TenantID = tenantID
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.SCIMToken{}, err
	}
	defer rollback(ctx, tx)
	err = tx.QueryRow(ctx, `
		INSERT INTO scim_tokens(id, tenant_id, name, token_hash, token_prefix, token_last4, state, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING created_at`,
		token.ID, tenantID, token.Name, token.Hash, token.Prefix, token.Last4, domain.StateActive, actorID,
	).Scan(&token.CreatedAt)
	if err != nil {
		return domain.SCIMToken{}, err
	}
	token.State = domain.StateActive
	token.CreatedBy = actorID
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "scim_token.created", Resource: "scim_token", ResourceID: token.ID, Reason: token.Name}); err != nil {
		return domain.SCIMToken{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.SCIMToken{}, err
	}
	return token, nil
}

func (s *Store) ListSCIMTokens(ctx context.Context, tenantID string, limit int) ([]domain.SCIMToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, token_prefix, token_last4, state, created_by, created_at, COALESCE(last_used_at, 'epoch'::timestamptz), COALESCE(revoked_at, 'epoch'::timestamptz)
		FROM scim_tokens
		WHERE tenant_id=$1
		ORDER BY created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.SCIMToken
	for rows.Next() {
		var item domain.SCIMToken
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Name, &item.Prefix, &item.Last4, &item.State, &item.CreatedBy, &item.CreatedAt, &item.LastUsedAt, &item.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) RevokeSCIMToken(ctx context.Context, tenantID, tokenID, actorID, reason string) (domain.SCIMToken, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.SCIMToken{}, err
	}
	defer rollback(ctx, tx)
	var item domain.SCIMToken
	err = tx.QueryRow(ctx, `
		UPDATE scim_tokens
		SET state='revoked', revoked_at=now()
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, name, token_prefix, token_last4, state, created_by, created_at, COALESCE(last_used_at, 'epoch'::timestamptz), COALESCE(revoked_at, 'epoch'::timestamptz)`,
		tenantID, tokenID).Scan(&item.ID, &item.TenantID, &item.Name, &item.Prefix, &item.Last4, &item.State, &item.CreatedBy, &item.CreatedAt, &item.LastUsedAt, &item.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.SCIMToken{}, app.ErrNotFound
	}
	if err != nil {
		return domain.SCIMToken{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "scim_token.revoked", Resource: "scim_token", ResourceID: tokenID, Reason: reason}); err != nil {
		return domain.SCIMToken{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) SCIMCreateOrReplaceUser(ctx context.Context, tenantID, actorID string, req app.SCIMUserRequest, replace bool) (app.SCIMUser, error) {
	_ = replace
	active := true
	if req.Active != nil {
		active = *req.Active
	}
	externalID := strings.TrimSpace(req.ExternalID)
	if externalID == "" {
		externalID = strings.TrimSpace(req.ID)
	}
	if externalID == "" {
		externalID = strings.TrimSpace(req.UserName)
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = req.Name.Formatted
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return app.SCIMUser{}, err
	}
	defer rollback(ctx, tx)
	userID := strings.TrimSpace(req.ID)
	if userID == "" {
		err := tx.QueryRow(ctx, `SELECT user_id FROM scim_users WHERE tenant_id=$1 AND external_id=$2`, tenantID, externalID).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			userID = mustID("usr")
		} else if err != nil {
			return app.SCIMUser{}, err
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO users(id, email, name, state)
		VALUES($1,$2,$3,$4)
		ON CONFLICT (id) DO UPDATE SET email=EXCLUDED.email, name=EXCLUDED.name, state=EXCLUDED.state`,
		userID, strings.ToLower(strings.TrimSpace(req.UserName)), displayName, stateFromActive(active)); err != nil {
		return app.SCIMUser{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO memberships(id, tenant_id, user_id, role, state)
		VALUES($1,$2,$3,$4,$5)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET state=EXCLUDED.state`,
		mustID("mem"), tenantID, userID, string(authz.RoleSupport), stateFromActive(active)); err != nil {
		return app.SCIMUser{}, err
	}
	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO scim_users(tenant_id, user_id, external_id, user_name, display_name, active)
		VALUES($1,$2,$3,$4,$5,$6)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET external_id=EXCLUDED.external_id, user_name=EXCLUDED.user_name,
			display_name=EXCLUDED.display_name, active=EXCLUDED.active, updated_at=now()
		RETURNING created_at`,
		tenantID, userID, externalID, strings.ToLower(strings.TrimSpace(req.UserName)), displayName, active).Scan(&createdAt)
	if err != nil {
		return app.SCIMUser{}, err
	}
	if !active {
		if _, err := tx.Exec(ctx, `UPDATE auth_sessions SET state='revoked', revoked_at=now() WHERE tenant_id=$1 AND user_id=$2 AND state='active'`, tenantID, userID); err != nil {
			return app.SCIMUser{}, err
		}
	}
	action := "scim_user.provisioned"
	if !active {
		action = "scim_user.deactivated"
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: action, Resource: "user", ResourceID: userID, Reason: "scim"}); err != nil {
		return app.SCIMUser{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return app.SCIMUser{}, err
	}
	return app.SCIMUser{ID: userID, ExternalID: externalID, UserName: req.UserName, DisplayName: displayName, Active: active, CreatedAt: createdAt}, nil
}

func (s *Store) SCIMListUsers(ctx context.Context, tenantID string, limit int) ([]app.SCIMUser, error) {
	rows, err := s.pool.Query(ctx, `SELECT user_id, external_id, user_name, display_name, active, created_at FROM scim_users WHERE tenant_id=$1 ORDER BY user_name LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.SCIMUser
	for rows.Next() {
		var item app.SCIMUser
		if err := rows.Scan(&item.ID, &item.ExternalID, &item.UserName, &item.DisplayName, &item.Active, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) SCIMGetUser(ctx context.Context, tenantID, userID string) (app.SCIMUser, error) {
	var item app.SCIMUser
	err := s.pool.QueryRow(ctx, `SELECT user_id, external_id, user_name, display_name, active, created_at FROM scim_users WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID).
		Scan(&item.ID, &item.ExternalID, &item.UserName, &item.DisplayName, &item.Active, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.SCIMUser{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) SCIMPatchUser(ctx context.Context, tenantID, actorID, userID string, req app.SCIMPatchRequest) (app.SCIMUser, error) {
	current, err := s.SCIMGetUser(ctx, tenantID, userID)
	if err != nil {
		return app.SCIMUser{}, err
	}
	userReq := app.SCIMUserRequest{ID: current.ID, ExternalID: current.ExternalID, UserName: current.UserName, DisplayName: current.DisplayName, Active: &current.Active}
	for _, op := range req.Operations {
		switch strings.ToLower(op.Op) {
		case "replace", "add":
			switch strings.ToLower(op.Path) {
			case "active":
				var active bool
				if err := json.Unmarshal(op.Value, &active); err != nil {
					return app.SCIMUser{}, fmt.Errorf("%w: invalid active patch", app.ErrInvalidInput)
				}
				userReq.Active = &active
			case "displayname":
				var display string
				if err := json.Unmarshal(op.Value, &display); err != nil {
					return app.SCIMUser{}, fmt.Errorf("%w: invalid displayName patch", app.ErrInvalidInput)
				}
				userReq.DisplayName = display
			default:
				return app.SCIMUser{}, fmt.Errorf("%w: unsupported SCIM user patch path", app.ErrInvalidInput)
			}
		default:
			return app.SCIMUser{}, fmt.Errorf("%w: unsupported SCIM patch operation", app.ErrInvalidInput)
		}
	}
	return s.SCIMCreateOrReplaceUser(ctx, tenantID, actorID, userReq, true)
}

func (s *Store) SCIMDeactivateUser(ctx context.Context, tenantID, actorID, userID string) (app.SCIMUser, error) {
	current, err := s.SCIMGetUser(ctx, tenantID, userID)
	if err != nil {
		return app.SCIMUser{}, err
	}
	active := false
	return s.SCIMCreateOrReplaceUser(ctx, tenantID, actorID, app.SCIMUserRequest{ID: current.ID, ExternalID: current.ExternalID, UserName: current.UserName, DisplayName: current.DisplayName, Active: &active}, true)
}

func (s *Store) SCIMCreateOrReplaceGroup(ctx context.Context, tenantID, actorID string, req app.SCIMGroupRequest, replace bool) (app.SCIMGroup, error) {
	_ = replace
	externalID := strings.TrimSpace(req.ExternalID)
	if externalID == "" {
		externalID = strings.TrimSpace(req.ID)
	}
	if externalID == "" {
		externalID = strings.TrimSpace(req.DisplayName)
	}
	groupID := strings.TrimSpace(req.ID)
	if groupID == "" {
		err := s.pool.QueryRow(ctx, `SELECT id FROM scim_groups WHERE tenant_id=$1 AND external_id=$2`, tenantID, externalID).Scan(&groupID)
		if errors.Is(err, pgx.ErrNoRows) {
			groupID = mustID("scg")
		} else if err != nil {
			return app.SCIMGroup{}, err
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return app.SCIMGroup{}, err
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO scim_groups(id, tenant_id, external_id, display_name, role, state)
		VALUES($1,$2,$3,$4,$5,'active')
		ON CONFLICT (tenant_id, external_id) DO UPDATE SET display_name=EXCLUDED.display_name, state='active', updated_at=now()`,
		groupID, tenantID, externalID, req.DisplayName, string(authz.RoleSupport)); err != nil {
		return app.SCIMGroup{}, err
	}
	if replace {
		if _, err := tx.Exec(ctx, `DELETE FROM scim_group_memberships WHERE tenant_id=$1 AND group_id=$2`, tenantID, groupID); err != nil {
			return app.SCIMGroup{}, err
		}
	}
	for _, member := range req.Members {
		userID := strings.TrimSpace(member.Value)
		if userID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO scim_group_memberships(tenant_id, group_id, user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, tenantID, groupID, userID); err != nil {
			return app.SCIMGroup{}, err
		}
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "scim_group.provisioned", Resource: "scim_group", ResourceID: groupID, Reason: "scim"}); err != nil {
		return app.SCIMGroup{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return app.SCIMGroup{}, err
	}
	return s.SCIMGetGroup(ctx, tenantID, groupID)
}

func (s *Store) SCIMListGroups(ctx context.Context, tenantID string, limit int) ([]app.SCIMGroup, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, external_id, display_name, state FROM scim_groups WHERE tenant_id=$1 ORDER BY display_name LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.SCIMGroup
	for rows.Next() {
		var item app.SCIMGroup
		var state string
		if err := rows.Scan(&item.ID, &item.ExternalID, &item.DisplayName, &state); err != nil {
			return nil, err
		}
		item.Active = state == domain.StateActive
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) SCIMGetGroup(ctx context.Context, tenantID, groupID string) (app.SCIMGroup, error) {
	var item app.SCIMGroup
	var state string
	err := s.pool.QueryRow(ctx, `SELECT id, external_id, display_name, state FROM scim_groups WHERE tenant_id=$1 AND id=$2`, tenantID, groupID).Scan(&item.ID, &item.ExternalID, &item.DisplayName, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.SCIMGroup{}, app.ErrNotFound
	}
	if err != nil {
		return app.SCIMGroup{}, err
	}
	item.Active = state == domain.StateActive
	rows, err := s.pool.Query(ctx, `SELECT user_id FROM scim_group_memberships WHERE tenant_id=$1 AND group_id=$2 ORDER BY user_id`, tenantID, groupID)
	if err != nil {
		return app.SCIMGroup{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var member app.SCIMGroupMember
		if err := rows.Scan(&member.Value); err != nil {
			return app.SCIMGroup{}, err
		}
		item.Members = append(item.Members, member)
	}
	return item, rows.Err()
}

func (s *Store) SCIMPatchGroup(ctx context.Context, tenantID, actorID, groupID string, req app.SCIMPatchRequest) (app.SCIMGroup, error) {
	current, err := s.SCIMGetGroup(ctx, tenantID, groupID)
	if err != nil {
		return app.SCIMGroup{}, err
	}
	groupReq := app.SCIMGroupRequest{ID: current.ID, ExternalID: current.ExternalID, DisplayName: current.DisplayName, Members: current.Members}
	for _, op := range req.Operations {
		switch strings.ToLower(op.Op) {
		case "replace":
			if strings.EqualFold(op.Path, "displayName") {
				if err := json.Unmarshal(op.Value, &groupReq.DisplayName); err != nil {
					return app.SCIMGroup{}, fmt.Errorf("%w: invalid displayName patch", app.ErrInvalidInput)
				}
				continue
			}
			if strings.EqualFold(op.Path, "members") || op.Path == "" {
				if err := json.Unmarshal(op.Value, &groupReq.Members); err != nil {
					return app.SCIMGroup{}, fmt.Errorf("%w: invalid members patch", app.ErrInvalidInput)
				}
				continue
			}
			return app.SCIMGroup{}, fmt.Errorf("%w: unsupported SCIM group patch path", app.ErrInvalidInput)
		default:
			return app.SCIMGroup{}, fmt.Errorf("%w: unsupported SCIM patch operation", app.ErrInvalidInput)
		}
	}
	return s.SCIMCreateOrReplaceGroup(ctx, tenantID, actorID, groupReq, true)
}

func (s *Store) SCIMDeactivateGroup(ctx context.Context, tenantID, actorID, groupID string) (app.SCIMGroup, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return app.SCIMGroup{}, err
	}
	defer rollback(ctx, tx)
	tag, err := tx.Exec(ctx, `UPDATE scim_groups SET state='disabled', updated_at=now() WHERE tenant_id=$1 AND id=$2`, tenantID, groupID)
	if err != nil {
		return app.SCIMGroup{}, err
	}
	if tag.RowsAffected() == 0 {
		return app.SCIMGroup{}, app.ErrNotFound
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "scim_group.deactivated", Resource: "scim_group", ResourceID: groupID, Reason: "scim"}); err != nil {
		return app.SCIMGroup{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return app.SCIMGroup{}, err
	}
	return s.SCIMGetGroup(ctx, tenantID, groupID)
}

func (s *Store) CreateRoleBinding(ctx context.Context, tenantID, actorID string, req app.CreateRoleBindingRequest) (domain.RoleBinding, error) {
	item := domain.RoleBinding{
		ID:             mustID("rbn"),
		TenantID:       tenantID,
		PrincipalType:  strings.TrimSpace(req.PrincipalType),
		PrincipalID:    strings.TrimSpace(req.PrincipalID),
		Role:           string(req.Role),
		ResourceFamily: defaultWildcard(req.ResourceFamily),
		ResourceID:     defaultWildcard(req.ResourceID),
		Environment:    defaultWildcard(req.Environment),
		State:          domain.StateActive,
		Reason:         req.Reason,
		CreatedBy:      actorID,
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.RoleBinding{}, err
	}
	defer rollback(ctx, tx)
	err = tx.QueryRow(ctx, `
		INSERT INTO role_bindings(id, tenant_id, principal_type, principal_id, role, resource_family, resource_id, environment, state, reason, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING created_at, updated_at`,
		item.ID, item.TenantID, item.PrincipalType, item.PrincipalID, item.Role, item.ResourceFamily, item.ResourceID, item.Environment, item.State, item.Reason, item.CreatedBy,
	).Scan(&item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.RoleBinding{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "role_binding.created", Resource: "role_binding", ResourceID: item.ID, Reason: req.Reason}); err != nil {
		return domain.RoleBinding{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) ListRoleBindings(ctx context.Context, tenantID string, limit int) ([]domain.RoleBinding, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, principal_type, principal_id, role, resource_family, resource_id, environment, state, reason, created_by, created_at, updated_at
		FROM role_bindings
		WHERE tenant_id=$1
		ORDER BY created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.RoleBinding
	for rows.Next() {
		var item domain.RoleBinding
		if err := rows.Scan(&item.ID, &item.TenantID, &item.PrincipalType, &item.PrincipalID, &item.Role, &item.ResourceFamily, &item.ResourceID, &item.Environment, &item.State, &item.Reason, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) UpdateRoleBinding(ctx context.Context, tenantID, bindingID, actorID string, req app.UpdateRoleBindingRequest) (domain.RoleBinding, error) {
	current, err := s.getRoleBinding(ctx, tenantID, bindingID)
	if err != nil {
		return domain.RoleBinding{}, err
	}
	if req.Role != nil {
		current.Role = string(*req.Role)
	}
	if req.ResourceFamily != nil {
		current.ResourceFamily = defaultWildcard(*req.ResourceFamily)
	}
	if req.ResourceID != nil {
		current.ResourceID = defaultWildcard(*req.ResourceID)
	}
	if req.Environment != nil {
		current.Environment = defaultWildcard(*req.Environment)
	}
	if req.State != nil {
		current.State = *req.State
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.RoleBinding{}, err
	}
	defer rollback(ctx, tx)
	err = tx.QueryRow(ctx, `
		UPDATE role_bindings
		SET role=$3, resource_family=$4, resource_id=$5, environment=$6, state=$7, reason=$8, updated_at=now()
		WHERE tenant_id=$1 AND id=$2
		RETURNING created_at, updated_at`,
		tenantID, bindingID, current.Role, current.ResourceFamily, current.ResourceID, current.Environment, current.State, req.Reason,
	).Scan(&current.CreatedAt, &current.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RoleBinding{}, app.ErrNotFound
	}
	if err != nil {
		return domain.RoleBinding{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "role_binding.updated", Resource: "role_binding", ResourceID: bindingID, Reason: req.Reason}); err != nil {
		return domain.RoleBinding{}, err
	}
	return current, tx.Commit(ctx)
}

func (s *Store) DisableRoleBinding(ctx context.Context, tenantID, bindingID, actorID, reason string) (domain.RoleBinding, error) {
	state := domain.StateDisabled
	return s.UpdateRoleBinding(ctx, tenantID, bindingID, actorID, app.UpdateRoleBindingRequest{State: &state, Reason: reason})
}

func (s *Store) getRoleBinding(ctx context.Context, tenantID, bindingID string) (domain.RoleBinding, error) {
	var item domain.RoleBinding
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, principal_type, principal_id, role, resource_family, resource_id, environment, state, reason, created_by, created_at, updated_at
		FROM role_bindings WHERE tenant_id=$1 AND id=$2`, tenantID, bindingID).Scan(
		&item.ID, &item.TenantID, &item.PrincipalType, &item.PrincipalID, &item.Role, &item.ResourceFamily, &item.ResourceID, &item.Environment, &item.State, &item.Reason, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RoleBinding{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) CreateAccessPolicyRule(ctx context.Context, tenantID, actorID string, req app.CreateAccessPolicyRuleRequest) (domain.AccessPolicyRule, error) {
	conditions := req.Conditions
	if len(conditions) == 0 {
		conditions = []byte(`{}`)
	}
	item := domain.AccessPolicyRule{
		ID:             mustID("apr"),
		TenantID:       tenantID,
		Name:           strings.TrimSpace(req.Name),
		Action:         strings.TrimSpace(req.Action),
		Effect:         strings.TrimSpace(req.Effect),
		ResourceFamily: defaultWildcard(req.ResourceFamily),
		Environment:    defaultWildcard(req.Environment),
		Conditions:     conditions,
		State:          domain.StateActive,
		Reason:         req.Reason,
		CreatedBy:      actorID,
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AccessPolicyRule{}, err
	}
	defer rollback(ctx, tx)
	err = tx.QueryRow(ctx, `
		INSERT INTO access_policy_rules(id, tenant_id, name, action, effect, resource_family, environment, conditions, state, reason, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING created_at, updated_at`,
		item.ID, item.TenantID, item.Name, item.Action, item.Effect, item.ResourceFamily, item.Environment, item.Conditions, item.State, item.Reason, item.CreatedBy,
	).Scan(&item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.AccessPolicyRule{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "access_policy.created", Resource: "access_policy", ResourceID: item.ID, Reason: req.Reason}); err != nil {
		return domain.AccessPolicyRule{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) ListAccessPolicyRules(ctx context.Context, tenantID string, limit int) ([]domain.AccessPolicyRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, action, effect, resource_family, environment, conditions, state, reason, created_by, created_at, updated_at
		FROM access_policy_rules
		WHERE tenant_id=$1
		ORDER BY created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AccessPolicyRule
	for rows.Next() {
		var item domain.AccessPolicyRule
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Name, &item.Action, &item.Effect, &item.ResourceFamily, &item.Environment, &item.Conditions, &item.State, &item.Reason, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) UpdateAccessPolicyRule(ctx context.Context, tenantID, policyID, actorID string, req app.UpdateAccessPolicyRuleRequest) (domain.AccessPolicyRule, error) {
	current, err := s.getAccessPolicyRule(ctx, tenantID, policyID)
	if err != nil {
		return domain.AccessPolicyRule{}, err
	}
	if req.Name != nil {
		current.Name = strings.TrimSpace(*req.Name)
	}
	if req.Action != nil {
		current.Action = strings.TrimSpace(*req.Action)
	}
	if req.Effect != nil {
		current.Effect = strings.TrimSpace(*req.Effect)
	}
	if req.ResourceFamily != nil {
		current.ResourceFamily = defaultWildcard(*req.ResourceFamily)
	}
	if req.Environment != nil {
		current.Environment = defaultWildcard(*req.Environment)
	}
	if req.Conditions != nil {
		current.Conditions = req.Conditions
	}
	if req.State != nil {
		current.State = *req.State
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AccessPolicyRule{}, err
	}
	defer rollback(ctx, tx)
	err = tx.QueryRow(ctx, `
		UPDATE access_policy_rules
		SET name=$3, action=$4, effect=$5, resource_family=$6, environment=$7, conditions=$8, state=$9, reason=$10, updated_at=now()
		WHERE tenant_id=$1 AND id=$2
		RETURNING created_at, updated_at`,
		tenantID, policyID, current.Name, current.Action, current.Effect, current.ResourceFamily, current.Environment, current.Conditions, current.State, req.Reason,
	).Scan(&current.CreatedAt, &current.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AccessPolicyRule{}, app.ErrNotFound
	}
	if err != nil {
		return domain.AccessPolicyRule{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "access_policy.updated", Resource: "access_policy", ResourceID: policyID, Reason: req.Reason}); err != nil {
		return domain.AccessPolicyRule{}, err
	}
	return current, tx.Commit(ctx)
}

func (s *Store) DisableAccessPolicyRule(ctx context.Context, tenantID, policyID, actorID, reason string) (domain.AccessPolicyRule, error) {
	state := domain.StateDisabled
	return s.UpdateAccessPolicyRule(ctx, tenantID, policyID, actorID, app.UpdateAccessPolicyRuleRequest{State: &state, Reason: reason})
}

func (s *Store) getAccessPolicyRule(ctx context.Context, tenantID, policyID string) (domain.AccessPolicyRule, error) {
	var item domain.AccessPolicyRule
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, action, effect, resource_family, environment, conditions, state, reason, created_by, created_at, updated_at
		FROM access_policy_rules WHERE tenant_id=$1 AND id=$2`, tenantID, policyID).Scan(
		&item.ID, &item.TenantID, &item.Name, &item.Action, &item.Effect, &item.ResourceFamily, &item.Environment, &item.Conditions, &item.State, &item.Reason, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AccessPolicyRule{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) ExplainAuthorization(ctx context.Context, tenantID, actorID string, req app.AuthzExplainRequest) (authz.Decision, error) {
	decision := authz.Decision{
		Allowed: false,
		Action:  req.Action,
		Resource: authz.Resource{
			TenantID:    tenantID,
			Family:      req.ResourceFamily,
			ID:          req.ResourceID,
			Environment: req.Environment,
			Attributes:  req.Attributes,
		},
		Reason: "no matching role binding or baseline role",
	}
	var role string
	err := s.pool.QueryRow(ctx, `SELECT role FROM memberships WHERE tenant_id=$1 AND user_id=$2 AND state='active'`, tenantID, actorID).Scan(&role)
	if err == nil && authz.Can(authz.Actor{ID: actorID, TenantID: tenantID, Role: authz.Role(role)}, req.Action, tenantID) {
		decision.Allowed = true
		decision.MatchedRole = role
		decision.Reason = "allowed by baseline role"
	} else {
		var bindingID, bindingRole string
		err := s.pool.QueryRow(ctx, `
			SELECT id, role
			FROM role_bindings
			WHERE tenant_id=$1 AND principal_type='user' AND principal_id=$2 AND state='active'
			  AND (resource_family='*' OR resource_family=$3)
			  AND (resource_id='*' OR resource_id=$4)
			  AND (environment='*' OR environment=$5)
			ORDER BY created_at DESC
			LIMIT 1`, tenantID, actorID, req.ResourceFamily, defaultWildcard(req.ResourceID), defaultWildcard(req.Environment)).Scan(&bindingID, &bindingRole)
		if err == nil && authz.Can(authz.Actor{ID: actorID, TenantID: tenantID, Role: authz.Role(bindingRole)}, req.Action, tenantID) {
			decision.Allowed = true
			decision.MatchedRole = bindingRole
			decision.MatchedRoleBindingID = bindingID
			decision.Reason = "allowed by resource role binding"
		} else {
			err = s.pool.QueryRow(ctx, `
				SELECT rb.id, rb.role
				FROM role_bindings rb
				JOIN scim_group_memberships gm ON gm.tenant_id=rb.tenant_id AND gm.group_id=rb.principal_id
				WHERE rb.tenant_id=$1 AND gm.user_id=$2 AND rb.principal_type='group' AND rb.state='active'
				  AND (rb.resource_family='*' OR rb.resource_family=$3)
				  AND (rb.resource_id='*' OR rb.resource_id=$4)
				  AND (rb.environment='*' OR rb.environment=$5)
				ORDER BY rb.created_at DESC
				LIMIT 1`, tenantID, actorID, req.ResourceFamily, defaultWildcard(req.ResourceID), defaultWildcard(req.Environment)).Scan(&bindingID, &bindingRole)
			if err == nil && authz.Can(authz.Actor{ID: actorID, TenantID: tenantID, Role: authz.Role(bindingRole)}, req.Action, tenantID) {
				decision.Allowed = true
				decision.MatchedRole = bindingRole
				decision.MatchedRoleBindingID = bindingID
				decision.Reason = "allowed by group role binding"
			}
		}
	}
	var policyID, effect string
	err = s.pool.QueryRow(ctx, `
		SELECT id, effect
		FROM access_policy_rules
		WHERE tenant_id=$1 AND state='active'
		  AND (action='*' OR action=$2)
		  AND (resource_family='*' OR resource_family=$3)
		  AND (environment='*' OR environment=$4)
		ORDER BY CASE effect WHEN 'deny' THEN 0 ELSE 1 END, created_at DESC
		LIMIT 1`, tenantID, req.Action, req.ResourceFamily, defaultWildcard(req.Environment)).Scan(&policyID, &effect)
	if err == nil {
		decision.MatchedPolicyRuleID = policyID
		switch effect {
		case app.PolicyEffectDeny:
			decision.Allowed = false
			decision.Reason = "denied by access policy"
		case app.PolicyEffectAllow:
			decision.Allowed = true
			decision.Reason = "allowed by access policy"
		}
	}
	_, _ = s.pool.Exec(ctx, `
		INSERT INTO authz_decision_logs(id, tenant_id, actor_id, action, resource_family, resource_id, environment, allowed, matched_role_binding_id, matched_policy_rule_id, reason, sampled)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true)`,
		mustID("adl"), tenantID, actorID, req.Action, req.ResourceFamily, req.ResourceID, req.Environment, decision.Allowed, decision.MatchedRoleBindingID, decision.MatchedPolicyRuleID, decision.Reason)
	return decision, nil
}

func normalizeStringList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func stateFromActive(active bool) string {
	if active {
		return domain.StateActive
	}
	return domain.StateDisabled
}

func defaultWildcard(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "*"
	}
	return value
}
