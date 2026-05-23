ALTER TABLE config_versions ADD COLUMN IF NOT EXISTS config_json jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE UNIQUE INDEX IF NOT EXISTS config_versions_resource_version_unique
    ON config_versions(tenant_id, resource_type, resource_id, version);

CREATE TABLE IF NOT EXISTS retry_policies (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    version integer NOT NULL DEFAULT 1,
    state text NOT NULL DEFAULT 'active',
    max_attempts integer NOT NULL,
    max_duration_seconds integer NOT NULL,
    initial_delay_seconds integer NOT NULL,
    max_delay_seconds integer NOT NULL,
    rate_limit_per_minute integer NOT NULL DEFAULT 0,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name, version)
);
CREATE INDEX IF NOT EXISTS retry_policies_tenant_state_idx ON retry_policies(tenant_id, state, name, version DESC);

ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS retry_policy_id text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS route_versions (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    route_id text NOT NULL REFERENCES routes(id),
    version integer NOT NULL,
    config_hash text NOT NULL,
    source_id text NOT NULL,
    name text NOT NULL,
    priority integer NOT NULL DEFAULT 100,
    event_types text[] NOT NULL,
    endpoint_id text NOT NULL REFERENCES endpoints(id),
    retry_policy_id text NOT NULL DEFAULT '',
    state text NOT NULL,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, route_id, version)
);
CREATE INDEX IF NOT EXISTS route_versions_route_idx ON route_versions(tenant_id, route_id, version DESC);

ALTER TABLE routes ADD COLUMN IF NOT EXISTS active_version_id text NOT NULL DEFAULT '';
ALTER TABLE routes ADD COLUMN IF NOT EXISTS retry_policy_id text NOT NULL DEFAULT '';

INSERT INTO route_versions(id, tenant_id, route_id, version, config_hash, source_id, name, priority, event_types, endpoint_id, retry_policy_id, state)
SELECT 'rv_' || substr(md5(r.tenant_id || ':' || r.id || ':' || r.version::text), 1, 18),
       r.tenant_id, r.id, r.version,
       'legacy:' || md5(r.tenant_id || ':' || r.id || ':' || r.version::text || ':' || r.endpoint_id),
       r.source_id, r.name, r.priority, r.event_types, r.endpoint_id, COALESCE(r.retry_policy_id, ''), r.state
FROM routes r
ON CONFLICT (tenant_id, route_id, version) DO NOTHING;

UPDATE routes r
SET active_version_id = rv.id
FROM route_versions rv
WHERE rv.tenant_id = r.tenant_id
  AND rv.route_id = r.id
  AND rv.version = r.version
  AND r.active_version_id = '';

ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS route_version_id text NOT NULL DEFAULT '';
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS retry_policy_id text NOT NULL DEFAULT '';

ALTER TABLE delivery_attempts ADD COLUMN IF NOT EXISTS request_sha256 text NOT NULL DEFAULT '';
ALTER TABLE delivery_attempts ADD COLUMN IF NOT EXISTS response_sha256 text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS source_secret_versions (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    source_id text NOT NULL REFERENCES sources(id),
    version integer NOT NULL,
    encrypted_secret bytea NOT NULL,
    state text NOT NULL DEFAULT 'active',
    active_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    UNIQUE (tenant_id, source_id, version)
);
CREATE INDEX IF NOT EXISTS source_secret_versions_lookup_idx
    ON source_secret_versions(tenant_id, source_id, state, version DESC);

INSERT INTO source_secret_versions(id, tenant_id, source_id, version, encrypted_secret, state)
SELECT 'ssv_' || substr(md5(tenant_id || ':' || id || ':1'), 1, 18), tenant_id, id, 1, encrypted_secret, 'active'
FROM sources
ON CONFLICT (tenant_id, source_id, version) DO NOTHING;

ALTER TABLE endpoint_secrets ADD COLUMN IF NOT EXISTS version integer NOT NULL DEFAULT 1;
ALTER TABLE endpoint_secrets ADD COLUMN IF NOT EXISTS active_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE endpoint_secrets ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE endpoint_secrets ADD COLUMN IF NOT EXISTS created_by text NOT NULL DEFAULT '';
ALTER TABLE endpoint_secrets ADD COLUMN IF NOT EXISTS revoked_at timestamptz;
CREATE UNIQUE INDEX IF NOT EXISTS endpoint_secrets_version_unique ON endpoint_secrets(tenant_id, endpoint_id, version);

ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS config_mode text NOT NULL DEFAULT 'current';
ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS rate_limit_per_minute integer NOT NULL DEFAULT 0;
ALTER TABLE replay_items ADD COLUMN IF NOT EXISTS config_mode text NOT NULL DEFAULT 'current';
ALTER TABLE replay_items ADD COLUMN IF NOT EXISTS route_version_id text NOT NULL DEFAULT '';
ALTER TABLE replay_items ADD COLUMN IF NOT EXISTS retry_policy_id text NOT NULL DEFAULT '';
