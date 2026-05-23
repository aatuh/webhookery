CREATE TABLE IF NOT EXISTS provider_adapters (
    id text PRIMARY KEY,
    name text NOT NULL UNIQUE,
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS adapter_versions (
    id text PRIMARY KEY,
    adapter_id text NOT NULL REFERENCES provider_adapters(id),
    name text NOT NULL,
    version text NOT NULL,
    config_hash text NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (name, version)
);
CREATE INDEX IF NOT EXISTS adapter_versions_name_state_idx ON adapter_versions(name, state, version DESC);

INSERT INTO provider_adapters(id, name, state)
VALUES
    ('pad_stripe', 'stripe', 'active'),
    ('pad_github', 'github', 'active'),
    ('pad_shopify', 'shopify', 'active'),
    ('pad_slack', 'slack', 'active'),
    ('pad_generic_hmac', 'generic-hmac', 'active'),
    ('pad_cloudevents', 'cloudevents', 'active'),
    ('pad_internal', 'internal', 'active'),
    ('pad_generic_unsafe', 'generic-unsafe', 'disabled')
ON CONFLICT (name) DO NOTHING;

INSERT INTO adapter_versions(id, adapter_id, name, version, config_hash, state)
VALUES
    ('adv_stripe_v1', 'pad_stripe', 'stripe', 'builtin-v1', 'builtin:stripe:v1', 'active'),
    ('adv_github_v1', 'pad_github', 'github', 'builtin-v1', 'builtin:github:v1', 'active'),
    ('adv_shopify_v1', 'pad_shopify', 'shopify', 'builtin-v1', 'builtin:shopify:v1', 'active'),
    ('adv_slack_v1', 'pad_slack', 'slack', 'builtin-v1', 'builtin:slack:v1', 'active'),
    ('adv_generic_hmac_v1', 'pad_generic_hmac', 'generic-hmac', 'builtin-v1', 'builtin:generic-hmac:v1', 'active'),
    ('adv_cloudevents_v1', 'pad_cloudevents', 'cloudevents', 'builtin-v1', 'builtin:cloudevents:v1', 'active'),
    ('adv_internal_v1', 'pad_internal', 'internal', 'builtin-v1', 'builtin:internal:v1', 'active'),
    ('adv_generic_unsafe_v1', 'pad_generic_unsafe', 'generic-unsafe', 'builtin-v1', 'builtin:generic-unsafe:v1', 'disabled')
ON CONFLICT (name, version) DO NOTHING;

CREATE TABLE IF NOT EXISTS normalized_envelopes (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    event_id text NOT NULL REFERENCES events(id),
    adapter_version_id text NOT NULL DEFAULT '',
    provider text NOT NULL,
    provider_event_id text NOT NULL DEFAULT '',
    type text NOT NULL,
    source text NOT NULL,
    subject text NOT NULL DEFAULT '',
    envelope_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    data_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    envelope_sha256 text NOT NULL,
    data_sha256 text NOT NULL,
    metadata_sha256 text NOT NULL,
    storage_status text NOT NULL DEFAULT 'stored',
    storage_deleted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS normalized_envelopes_tenant_event_idx ON normalized_envelopes(tenant_id, event_id);
CREATE INDEX IF NOT EXISTS normalized_envelopes_tenant_type_idx ON normalized_envelopes(tenant_id, type, created_at DESC);

INSERT INTO normalized_envelopes(
    id, tenant_id, event_id, adapter_version_id, provider, provider_event_id, type, source, subject,
    envelope_json, data_json, metadata_json, envelope_sha256, data_sha256, metadata_sha256, storage_status, created_at
)
SELECT 'nenv_' || substr(md5(e.tenant_id || ':' || e.id), 1, 18),
       e.tenant_id,
       e.id,
       COALESCE(av.id, ''),
       e.provider,
       e.provider_event_id,
       e.type,
       e.provider || ':' || e.source_id,
       '',
       jsonb_build_object(
           'specversion', '1.0',
           'id', COALESCE(NULLIF(e.provider_event_id,''), e.id),
           'type', e.type,
           'source', e.provider || ':' || e.source_id,
           'tenant_id', e.tenant_id,
           'source_id', e.source_id,
           'provider', e.provider,
           'provider_event_id', e.provider_event_id,
           'raw_payload_hash', e.raw_payload_hash,
           'signature_verified', e.signature_verified,
           'verification_reason', e.verification_reason,
           'metadata', jsonb_build_object('legacy_metadata_only', true)
       ),
       '{}'::jsonb,
       jsonb_build_object('legacy_metadata_only', true),
       'legacy:' || md5(e.tenant_id || ':' || e.id || ':envelope'),
       'legacy:' || md5(e.tenant_id || ':' || e.id || ':data'),
       'legacy:' || md5(e.tenant_id || ':' || e.id || ':metadata'),
       'metadata_only',
       e.received_at
FROM events e
LEFT JOIN adapter_versions av ON av.name = e.provider AND av.state = 'active'
WHERE e.signature_verified = true
ON CONFLICT (tenant_id, event_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS transformations (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    state text NOT NULL DEFAULT 'active',
    active_version_id text NOT NULL DEFAULT '',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS transformations_tenant_state_idx ON transformations(tenant_id, state, updated_at DESC);

CREATE TABLE IF NOT EXISTS transformation_versions (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    transformation_id text NOT NULL REFERENCES transformations(id),
    version integer NOT NULL,
    config_hash text NOT NULL,
    operations_json jsonb NOT NULL,
    state text NOT NULL DEFAULT 'draft',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, transformation_id, version)
);
CREATE INDEX IF NOT EXISTS transformation_versions_lookup_idx ON transformation_versions(tenant_id, transformation_id, version DESC);

ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS transformation_id text NOT NULL DEFAULT '';
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS transformation_version_id text NOT NULL DEFAULT '';
ALTER TABLE subscription_versions ADD COLUMN IF NOT EXISTS transformation_id text NOT NULL DEFAULT '';
ALTER TABLE subscription_versions ADD COLUMN IF NOT EXISTS transformation_version_id text NOT NULL DEFAULT '';

ALTER TABLE routes ADD COLUMN IF NOT EXISTS transformation_id text NOT NULL DEFAULT '';
ALTER TABLE routes ADD COLUMN IF NOT EXISTS transformation_version_id text NOT NULL DEFAULT '';
ALTER TABLE route_versions ADD COLUMN IF NOT EXISTS transformation_id text NOT NULL DEFAULT '';
ALTER TABLE route_versions ADD COLUMN IF NOT EXISTS transformation_version_id text NOT NULL DEFAULT '';

ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS adapter_version_id text NOT NULL DEFAULT '';
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS normalized_envelope_id text NOT NULL DEFAULT '';
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS transformation_version_id text NOT NULL DEFAULT '';
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS delivery_payload_id text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS delivery_payloads (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    delivery_id text NOT NULL REFERENCES deliveries(id),
    event_id text NOT NULL REFERENCES events(id),
    normalized_envelope_id text NOT NULL DEFAULT '',
    transformation_version_id text NOT NULL DEFAULT '',
    content_type text NOT NULL DEFAULT 'application/json',
    sha256 text NOT NULL,
    size_bytes bigint NOT NULL DEFAULT 0,
    body bytea NOT NULL DEFAULT '',
    storage_status text NOT NULL DEFAULT 'stored',
    storage_deleted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, delivery_id)
);
CREATE INDEX IF NOT EXISTS delivery_payloads_tenant_event_idx ON delivery_payloads(tenant_id, event_id);
CREATE INDEX IF NOT EXISTS delivery_payloads_storage_idx ON delivery_payloads(tenant_id, storage_status, created_at);

ALTER TABLE replay_items ADD COLUMN IF NOT EXISTS adapter_version_id text NOT NULL DEFAULT '';
ALTER TABLE replay_items ADD COLUMN IF NOT EXISTS normalized_envelope_id text NOT NULL DEFAULT '';
ALTER TABLE replay_items ADD COLUMN IF NOT EXISTS transformation_version_id text NOT NULL DEFAULT '';
ALTER TABLE replay_items ADD COLUMN IF NOT EXISTS delivery_payload_id text NOT NULL DEFAULT '';

ALTER TABLE replay_receipts ADD COLUMN IF NOT EXISTS adapter_version_id text NOT NULL DEFAULT '';
ALTER TABLE replay_receipts ADD COLUMN IF NOT EXISTS normalized_envelope_id text NOT NULL DEFAULT '';
ALTER TABLE replay_receipts ADD COLUMN IF NOT EXISTS transformation_version_id text NOT NULL DEFAULT '';
ALTER TABLE replay_receipts ADD COLUMN IF NOT EXISTS delivery_payload_id text NOT NULL DEFAULT '';

ALTER TABLE evidence_exports ADD COLUMN IF NOT EXISTS include_payload_bodies boolean NOT NULL DEFAULT false;
