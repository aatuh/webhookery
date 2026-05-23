CREATE TABLE IF NOT EXISTS endpoint_secrets (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    endpoint_id text NOT NULL REFERENCES endpoints(id),
    encrypted_secret bytea NOT NULL,
    algorithm text NOT NULL DEFAULT 'hmac_sha256',
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS endpoint_secrets_endpoint_idx ON endpoint_secrets(tenant_id, endpoint_id, state);

CREATE TABLE IF NOT EXISTS subscriptions (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    endpoint_id text NOT NULL REFERENCES endpoints(id),
    event_types text[] NOT NULL,
    payload_format text NOT NULL DEFAULT 'canonical_json',
    state text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS subscriptions_tenant_state_idx ON subscriptions(tenant_id, state);
CREATE INDEX IF NOT EXISTS subscriptions_event_types_gin ON subscriptions USING gin(event_types);

CREATE TABLE IF NOT EXISTS routes (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    source_id text NOT NULL REFERENCES sources(id),
    name text NOT NULL,
    priority integer NOT NULL DEFAULT 100,
    event_types text[] NOT NULL,
    endpoint_id text NOT NULL REFERENCES endpoints(id),
    state text NOT NULL,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS routes_tenant_source_state_idx ON routes(tenant_id, source_id, state, priority);
CREATE INDEX IF NOT EXISTS routes_event_types_gin ON routes USING gin(event_types);

CREATE TABLE IF NOT EXISTS event_types (
    tenant_id text NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS event_schemas (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    event_type text NOT NULL,
    version text NOT NULL,
    schema_json text NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, event_type, version)
);

CREATE INDEX IF NOT EXISTS event_schemas_type_idx ON event_schemas(tenant_id, event_type);

ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS route_id text NOT NULL DEFAULT '';
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS subscription_id text NOT NULL DEFAULT '';
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS locked_by text;
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS lock_expires_at timestamptz;
CREATE INDEX IF NOT EXISTS deliveries_due_idx ON deliveries(tenant_id, state, next_attempt_at);
