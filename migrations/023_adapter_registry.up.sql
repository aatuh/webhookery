ALTER TABLE provider_adapters DROP CONSTRAINT IF EXISTS provider_adapters_name_key;
ALTER TABLE provider_adapters ADD COLUMN IF NOT EXISTS tenant_id text REFERENCES tenants(id);
ALTER TABLE provider_adapters ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'builtin';
ALTER TABLE provider_adapters ADD COLUMN IF NOT EXISTS description text NOT NULL DEFAULT '';
ALTER TABLE provider_adapters ADD COLUMN IF NOT EXISTS risk_level text NOT NULL DEFAULT 'core';
ALTER TABLE provider_adapters ADD COLUMN IF NOT EXISTS provenance_url text NOT NULL DEFAULT '';
ALTER TABLE provider_adapters ADD COLUMN IF NOT EXISTS created_by text NOT NULL DEFAULT '';
ALTER TABLE provider_adapters ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE provider_adapters ADD COLUMN IF NOT EXISTS retired_at timestamptz;
UPDATE provider_adapters SET kind='builtin', risk_level='core' WHERE kind='';
CREATE UNIQUE INDEX IF NOT EXISTS provider_adapters_scope_name_idx ON provider_adapters(COALESCE(tenant_id, ''), name);
CREATE INDEX IF NOT EXISTS provider_adapters_tenant_state_idx ON provider_adapters(tenant_id, state, name);

ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS tenant_id text REFERENCES tenants(id);
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'builtin';
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS definition_json jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS definition_sha256 text NOT NULL DEFAULT '';
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS package_sha256 text NOT NULL DEFAULT '';
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS package_signature text NOT NULL DEFAULT '';
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS sbom_sha256 text NOT NULL DEFAULT '';
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS provenance_url text NOT NULL DEFAULT '';
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS risk_level text NOT NULL DEFAULT 'core';
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS test_results_json jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS review_notes text NOT NULL DEFAULT '';
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS created_by text NOT NULL DEFAULT '';
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS reviewed_by text NOT NULL DEFAULT '';
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS activated_by text NOT NULL DEFAULT '';
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS reviewed_at timestamptz;
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS activated_at timestamptz;
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS deprecated_at timestamptz;
ALTER TABLE adapter_versions ADD COLUMN IF NOT EXISTS retired_at timestamptz;
UPDATE adapter_versions SET kind='builtin', risk_level='core' WHERE kind='';
ALTER TABLE adapter_versions DROP CONSTRAINT IF EXISTS adapter_versions_name_version_key;
CREATE UNIQUE INDEX IF NOT EXISTS adapter_versions_scope_name_version_idx ON adapter_versions(COALESCE(tenant_id, ''), name, version);
CREATE INDEX IF NOT EXISTS adapter_versions_scope_name_state_idx ON adapter_versions(COALESCE(tenant_id, ''), name, state, version DESC);

CREATE TABLE IF NOT EXISTS adapter_test_vectors (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    adapter_version_id text NOT NULL REFERENCES adapter_versions(id),
    name text NOT NULL,
    purpose text NOT NULL DEFAULT '',
    request_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    expected_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    request_sha256 text NOT NULL,
    expected_sha256 text NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (adapter_version_id, name)
);
CREATE INDEX IF NOT EXISTS adapter_test_vectors_tenant_version_idx ON adapter_test_vectors(tenant_id, adapter_version_id, name);

CREATE TABLE IF NOT EXISTS adapter_version_reviews (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    adapter_version_id text NOT NULL REFERENCES adapter_versions(id),
    action text NOT NULL,
    from_state text NOT NULL,
    to_state text NOT NULL,
    actor_id text NOT NULL,
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS adapter_version_reviews_tenant_version_idx ON adapter_version_reviews(tenant_id, adapter_version_id, created_at DESC);
