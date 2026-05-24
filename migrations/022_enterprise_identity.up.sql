CREATE TABLE IF NOT EXISTS identity_providers (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    provider_type text NOT NULL DEFAULT 'oidc',
    issuer_url text NOT NULL,
    authorization_endpoint text NOT NULL DEFAULT '',
    token_endpoint text NOT NULL DEFAULT '',
    jwks_uri text NOT NULL DEFAULT '',
    client_id text NOT NULL,
    encrypted_client_secret bytea NOT NULL,
    redirect_uri text NOT NULL DEFAULT '',
    allowed_email_domains text[] NOT NULL DEFAULT ARRAY[]::text[],
    state text NOT NULL DEFAULT 'active',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS identity_providers_tenant_state_idx ON identity_providers(tenant_id, state, provider_type);

CREATE TABLE IF NOT EXISTS external_identities (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    user_id text NOT NULL REFERENCES users(id),
    identity_provider_id text NOT NULL REFERENCES identity_providers(id),
    external_subject text NOT NULL,
    email text NOT NULL DEFAULT '',
    email_verified boolean NOT NULL DEFAULT false,
    display_name text NOT NULL DEFAULT '',
    state text NOT NULL DEFAULT 'active',
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    UNIQUE (tenant_id, identity_provider_id, external_subject)
);
CREATE INDEX IF NOT EXISTS external_identities_user_idx ON external_identities(tenant_id, user_id, state);

CREATE TABLE IF NOT EXISTS oidc_login_states (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    identity_provider_id text NOT NULL REFERENCES identity_providers(id),
    state_hash text NOT NULL UNIQUE,
    nonce_hash text NOT NULL,
    encrypted_pkce_verifier bytea NOT NULL,
    redirect_after text NOT NULL DEFAULT '',
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS oidc_login_states_provider_idx ON oidc_login_states(tenant_id, identity_provider_id, expires_at);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    user_id text NOT NULL REFERENCES users(id),
    external_identity_id text REFERENCES external_identities(id),
    session_hash text NOT NULL UNIQUE,
    state text NOT NULL DEFAULT 'active',
    user_agent_hash text NOT NULL DEFAULT '',
    ip_hash text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS auth_sessions_tenant_user_state_idx ON auth_sessions(tenant_id, user_id, state, expires_at);

CREATE TABLE IF NOT EXISTS scim_tokens (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    token_hash text NOT NULL UNIQUE,
    token_prefix text NOT NULL DEFAULT '',
    token_last4 text NOT NULL DEFAULT '',
    state text NOT NULL DEFAULT 'active',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at timestamptz,
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS scim_tokens_tenant_state_idx ON scim_tokens(tenant_id, state, created_at DESC);

CREATE TABLE IF NOT EXISTS scim_users (
    tenant_id text NOT NULL REFERENCES tenants(id),
    user_id text NOT NULL REFERENCES users(id),
    external_id text NOT NULL,
    user_name text NOT NULL,
    display_name text NOT NULL DEFAULT '',
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id),
    UNIQUE (tenant_id, external_id)
);
CREATE INDEX IF NOT EXISTS scim_users_tenant_active_idx ON scim_users(tenant_id, active, user_name);
CREATE UNIQUE INDEX IF NOT EXISTS scim_users_user_name_unique ON scim_users(tenant_id, lower(user_name));

CREATE TABLE IF NOT EXISTS scim_groups (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    external_id text NOT NULL,
    display_name text NOT NULL,
    role text NOT NULL DEFAULT 'support',
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, external_id)
);
CREATE INDEX IF NOT EXISTS scim_groups_tenant_state_idx ON scim_groups(tenant_id, state, display_name);

CREATE TABLE IF NOT EXISTS scim_group_memberships (
    tenant_id text NOT NULL REFERENCES tenants(id),
    group_id text NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id text NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, group_id, user_id)
);
CREATE INDEX IF NOT EXISTS scim_group_memberships_user_idx ON scim_group_memberships(tenant_id, user_id);

CREATE TABLE IF NOT EXISTS role_bindings (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    principal_type text NOT NULL,
    principal_id text NOT NULL,
    role text NOT NULL,
    resource_family text NOT NULL DEFAULT '*',
    resource_id text NOT NULL DEFAULT '*',
    environment text NOT NULL DEFAULT '*',
    state text NOT NULL DEFAULT 'active',
    reason text NOT NULL DEFAULT '',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS role_bindings_principal_idx ON role_bindings(tenant_id, principal_type, principal_id, state);
CREATE INDEX IF NOT EXISTS role_bindings_resource_idx ON role_bindings(tenant_id, resource_family, resource_id, environment, state);

CREATE TABLE IF NOT EXISTS access_policy_rules (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    action text NOT NULL,
    effect text NOT NULL,
    resource_family text NOT NULL DEFAULT '*',
    environment text NOT NULL DEFAULT '*',
    conditions jsonb NOT NULL DEFAULT '{}'::jsonb,
    state text NOT NULL DEFAULT 'active',
    reason text NOT NULL DEFAULT '',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS access_policy_rules_tenant_state_idx ON access_policy_rules(tenant_id, state, action, resource_family);

CREATE TABLE IF NOT EXISTS authz_decision_logs (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    actor_id text NOT NULL DEFAULT '',
    action text NOT NULL,
    resource_family text NOT NULL DEFAULT '',
    resource_id text NOT NULL DEFAULT '',
    environment text NOT NULL DEFAULT '',
    allowed boolean NOT NULL,
    matched_role_binding_id text NOT NULL DEFAULT '',
    matched_policy_rule_id text NOT NULL DEFAULT '',
    reason text NOT NULL DEFAULT '',
    sampled boolean NOT NULL DEFAULT false,
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS authz_decision_logs_tenant_time_idx ON authz_decision_logs(tenant_id, occurred_at DESC);
