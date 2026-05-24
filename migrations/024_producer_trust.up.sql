CREATE TABLE IF NOT EXISTS producer_clients (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    source_id text,
    scopes text[] NOT NULL DEFAULT ARRAY['events:write']::text[],
    token_ttl_seconds integer NOT NULL DEFAULT 900,
    state text NOT NULL DEFAULT 'active',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    FOREIGN KEY (source_id) REFERENCES sources(id)
);
CREATE INDEX IF NOT EXISTS producer_clients_tenant_state_idx ON producer_clients(tenant_id, state, created_at DESC);
CREATE INDEX IF NOT EXISTS producer_clients_tenant_source_idx ON producer_clients(tenant_id, source_id) WHERE source_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS producer_client_secrets (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    client_id text NOT NULL REFERENCES producer_clients(id),
    secret_hash text NOT NULL UNIQUE,
    secret_prefix text NOT NULL DEFAULT '',
    secret_last4 text NOT NULL DEFAULT '',
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS producer_client_secrets_client_state_idx ON producer_client_secrets(tenant_id, client_id, state, created_at DESC);

CREATE TABLE IF NOT EXISTS producer_access_tokens (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    client_id text NOT NULL REFERENCES producer_clients(id),
    token_hash text NOT NULL UNIQUE,
    token_prefix text NOT NULL DEFAULT '',
    token_last4 text NOT NULL DEFAULT '',
    scopes text[] NOT NULL DEFAULT ARRAY['events:write']::text[],
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS producer_access_tokens_tenant_client_idx ON producer_access_tokens(tenant_id, client_id, state, expires_at DESC);
