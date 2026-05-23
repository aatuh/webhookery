ALTER TABLE raw_payloads ADD COLUMN IF NOT EXISTS storage_backend text NOT NULL DEFAULT 'postgres';
ALTER TABLE raw_payloads ADD COLUMN IF NOT EXISTS object_bucket text NOT NULL DEFAULT '';
ALTER TABLE raw_payloads ADD COLUMN IF NOT EXISTS object_key text NOT NULL DEFAULT '';
ALTER TABLE raw_payloads ADD COLUMN IF NOT EXISTS storage_status text NOT NULL DEFAULT 'stored';
ALTER TABLE raw_payloads ADD COLUMN IF NOT EXISTS storage_deleted_at timestamptz;
CREATE INDEX IF NOT EXISTS raw_payloads_storage_idx ON raw_payloads(tenant_id, storage_backend, storage_status, created_at);

CREATE TABLE IF NOT EXISTS retention_policies (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    resource_type text NOT NULL,
    source_id text NOT NULL DEFAULT '',
    retention_days integer NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, resource_type, source_id)
);
CREATE INDEX IF NOT EXISTS retention_policies_tenant_state_idx ON retention_policies(tenant_id, state, resource_type);

CREATE TABLE IF NOT EXISTS retention_runs (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    policy_id text NOT NULL REFERENCES retention_policies(id),
    resource_type text NOT NULL,
    state text NOT NULL,
    matched_items integer NOT NULL DEFAULT 0,
    processed_items integer NOT NULL DEFAULT 0,
    error text NOT NULL DEFAULT '',
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS retention_runs_tenant_policy_idx ON retention_runs(tenant_id, policy_id, started_at DESC);

CREATE TABLE IF NOT EXISTS retention_run_items (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    retention_run_id text NOT NULL REFERENCES retention_runs(id),
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    action text NOT NULL,
    state text NOT NULL,
    error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS retention_run_items_run_idx ON retention_run_items(tenant_id, retention_run_id, state);

CREATE TABLE IF NOT EXISTS evidence_exports (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    state text NOT NULL,
    from_time timestamptz,
    to_time timestamptz,
    include_raw_payloads boolean NOT NULL DEFAULT false,
    include_timelines boolean NOT NULL DEFAULT false,
    format text NOT NULL DEFAULT 'tar+gzip+jsonl',
    storage_backend text NOT NULL DEFAULT 'postgres',
    object_bucket text NOT NULL DEFAULT '',
    object_key text NOT NULL DEFAULT '',
    sha256 text NOT NULL DEFAULT '',
    manifest_sha256 text NOT NULL DEFAULT '',
    size_bytes bigint NOT NULL DEFAULT 0,
    bundle bytea NOT NULL DEFAULT '',
    manifest jsonb NOT NULL DEFAULT '{}'::jsonb,
    file_hashes jsonb NOT NULL DEFAULT '[]'::jsonb,
    error text NOT NULL DEFAULT '',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS evidence_exports_tenant_created_idx ON evidence_exports(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS evidence_export_items (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    export_id text NOT NULL REFERENCES evidence_exports(id),
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    file_name text NOT NULL,
    sha256 text NOT NULL,
    size_bytes bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS evidence_export_items_export_idx ON evidence_export_items(tenant_id, export_id, resource_type);
