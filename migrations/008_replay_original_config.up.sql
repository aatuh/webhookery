CREATE TABLE IF NOT EXISTS subscription_versions (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    subscription_id text NOT NULL REFERENCES subscriptions(id),
    version integer NOT NULL,
    config_hash text NOT NULL,
    endpoint_id text NOT NULL REFERENCES endpoints(id),
    event_types text[] NOT NULL,
    payload_format text NOT NULL DEFAULT 'canonical_json',
    state text NOT NULL,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, subscription_id, version)
);
CREATE INDEX IF NOT EXISTS subscription_versions_subscription_idx
    ON subscription_versions(tenant_id, subscription_id, version DESC);

ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS version integer NOT NULL DEFAULT 1;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS active_version_id text NOT NULL DEFAULT '';

INSERT INTO subscription_versions(id, tenant_id, subscription_id, version, config_hash, endpoint_id, event_types, payload_format, state)
SELECT 'sv_' || substr(md5(s.tenant_id || ':' || s.id || ':' || s.version::text), 1, 18),
       s.tenant_id, s.id, s.version,
       'legacy:' || md5(s.tenant_id || ':' || s.id || ':' || s.version::text || ':' || s.endpoint_id),
       s.endpoint_id, s.event_types, s.payload_format, s.state
FROM subscriptions s
ON CONFLICT (tenant_id, subscription_id, version) DO NOTHING;

UPDATE subscriptions s
SET active_version_id = sv.id
FROM subscription_versions sv
WHERE sv.tenant_id = s.tenant_id
  AND sv.subscription_id = s.id
  AND sv.version = s.version
  AND s.active_version_id = '';

INSERT INTO config_versions(id, tenant_id, resource_type, resource_id, version, config_hash, config_json)
SELECT 'cfg_' || substr(md5(s.tenant_id || ':subscription:' || s.id || ':' || s.version::text), 1, 18),
       s.tenant_id,
       'subscription',
       s.id,
       s.version,
       sv.config_hash,
       jsonb_build_object(
           'subscription_id', s.id,
           'endpoint_id', s.endpoint_id,
           'event_types', s.event_types,
           'payload_format', s.payload_format,
           'state', s.state,
           'version', s.version
       )
FROM subscriptions s
JOIN subscription_versions sv ON sv.tenant_id = s.tenant_id AND sv.subscription_id = s.id AND sv.version = s.version
ON CONFLICT (tenant_id, resource_type, resource_id, version) DO NOTHING;

ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS subscription_version_id text NOT NULL DEFAULT '';
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS replay_job_id text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS deliveries_live_priority_idx
    ON deliveries(tenant_id, state, next_attempt_at, replay_job_id);

ALTER TABLE replay_items ADD COLUMN IF NOT EXISTS subscription_version_id text NOT NULL DEFAULT '';

ALTER TABLE replay_receipts ADD COLUMN IF NOT EXISTS config_mode text NOT NULL DEFAULT 'current';
ALTER TABLE replay_receipts ADD COLUMN IF NOT EXISTS route_version_id text NOT NULL DEFAULT '';
ALTER TABLE replay_receipts ADD COLUMN IF NOT EXISTS subscription_version_id text NOT NULL DEFAULT '';
ALTER TABLE replay_receipts ADD COLUMN IF NOT EXISTS retry_policy_id text NOT NULL DEFAULT '';
ALTER TABLE replay_receipts ADD COLUMN IF NOT EXISTS schema_version_id text NOT NULL DEFAULT '';
