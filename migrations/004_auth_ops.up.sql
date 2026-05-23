CREATE TABLE IF NOT EXISTS users (
    id text PRIMARY KEY,
    email text NOT NULL DEFAULT '',
    name text NOT NULL DEFAULT '',
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(lower(email)) WHERE email <> '';

CREATE TABLE IF NOT EXISTS memberships (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    user_id text NOT NULL REFERENCES users(id),
    role text NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id)
);
CREATE INDEX IF NOT EXISTS memberships_tenant_user_idx ON memberships(tenant_id, user_id, state);

CREATE TABLE IF NOT EXISTS api_keys (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    user_id text NOT NULL REFERENCES users(id),
    name text NOT NULL,
    key_hash text NOT NULL UNIQUE,
    key_prefix text NOT NULL DEFAULT '',
    key_last4 text NOT NULL DEFAULT '',
    scopes text[] NOT NULL,
    state text NOT NULL DEFAULT 'active',
    last_used_at timestamptz,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS api_keys_tenant_state_idx ON api_keys(tenant_id, state, created_at DESC);

CREATE TABLE IF NOT EXISTS idempotency_records (
    tenant_id text NOT NULL REFERENCES tenants(id),
    dedupe_key text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    status_code integer NOT NULL DEFAULT 202,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, dedupe_key)
);

CREATE TABLE IF NOT EXISTS config_versions (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    version integer NOT NULL,
    config_hash text NOT NULL,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS config_versions_resource_idx ON config_versions(tenant_id, resource_type, resource_id, version DESC);

ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS circuit_state text NOT NULL DEFAULT 'closed';
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS failure_count integer NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS disabled_until timestamptz;
CREATE INDEX IF NOT EXISTS endpoints_circuit_idx ON endpoints(tenant_id, circuit_state, disabled_until);

ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS total_items integer NOT NULL DEFAULT 0;
ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS processed_items integer NOT NULL DEFAULT 0;
ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS failed_items integer NOT NULL DEFAULT 0;
ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS completed_at timestamptz;
ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS canceled_at timestamptz;
ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS paused_at timestamptz;
