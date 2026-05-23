CREATE TABLE IF NOT EXISTS provider_connections (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    provider text NOT NULL,
    state text NOT NULL DEFAULT 'active',
    credential_type text NOT NULL DEFAULT 'api_key',
    credential_hint text NOT NULL DEFAULT '',
    encrypted_credential bytea NOT NULL,
    config_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    verified_at timestamptz,
    revoked_at timestamptz,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS provider_connections_tenant_provider_idx ON provider_connections(tenant_id, provider, state);

CREATE TABLE IF NOT EXISTS reconciliation_jobs (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    connection_id text NOT NULL REFERENCES provider_connections(id),
    provider text NOT NULL,
    state text NOT NULL DEFAULT 'scheduled',
    dry_run boolean NOT NULL DEFAULT false,
    capture_missing boolean NOT NULL DEFAULT false,
    route_recovered boolean NOT NULL DEFAULT false,
    redeliver_failed boolean NOT NULL DEFAULT false,
    scope_object_id text NOT NULL DEFAULT '',
    window_start timestamptz,
    window_end timestamptz,
    cursor text NOT NULL DEFAULT '',
    reason text NOT NULL DEFAULT '',
    total_items integer NOT NULL DEFAULT 0,
    matched_items integer NOT NULL DEFAULT 0,
    missing_items integer NOT NULL DEFAULT 0,
    captured_items integer NOT NULL DEFAULT 0,
    redelivered_items integer NOT NULL DEFAULT 0,
    unrecoverable_items integer NOT NULL DEFAULT 0,
    failed_items integer NOT NULL DEFAULT 0,
    error text NOT NULL DEFAULT '',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    completed_at timestamptz,
    canceled_at timestamptz
);
CREATE INDEX IF NOT EXISTS reconciliation_jobs_tenant_state_idx ON reconciliation_jobs(tenant_id, state, created_at DESC);
CREATE INDEX IF NOT EXISTS reconciliation_jobs_connection_idx ON reconciliation_jobs(tenant_id, connection_id, created_at DESC);

CREATE TABLE IF NOT EXISTS provider_api_evidence (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    job_id text NOT NULL REFERENCES reconciliation_jobs(id),
    item_id text NOT NULL DEFAULT '',
    connection_id text NOT NULL REFERENCES provider_connections(id),
    provider text NOT NULL,
    request_method text NOT NULL DEFAULT 'GET',
    request_url text NOT NULL DEFAULT '',
    response_status integer NOT NULL DEFAULT 0,
    response_sha256 text NOT NULL DEFAULT '',
    response_size_bytes bigint NOT NULL DEFAULT 0,
    response_body bytea NOT NULL DEFAULT '',
    storage_status text NOT NULL DEFAULT 'stored',
    storage_deleted_at timestamptz,
    error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS provider_api_evidence_job_idx ON provider_api_evidence(tenant_id, job_id, created_at DESC);
CREATE INDEX IF NOT EXISTS provider_api_evidence_storage_idx ON provider_api_evidence(tenant_id, storage_status, created_at);

CREATE TABLE IF NOT EXISTS reconciliation_items (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    job_id text NOT NULL REFERENCES reconciliation_jobs(id),
    provider text NOT NULL,
    provider_object_id text NOT NULL,
    provider_object_type text NOT NULL DEFAULT '',
    outcome text NOT NULL,
    local_event_id text NOT NULL DEFAULT '',
    recovered_event_id text NOT NULL DEFAULT '',
    provider_api_evidence_id text NOT NULL DEFAULT '',
    redelivery_requested boolean NOT NULL DEFAULT false,
    error text NOT NULL DEFAULT '',
    metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS reconciliation_items_job_idx ON reconciliation_items(tenant_id, job_id, created_at ASC);
CREATE INDEX IF NOT EXISTS reconciliation_items_event_idx ON reconciliation_items(tenant_id, recovered_event_id, local_event_id);
CREATE INDEX IF NOT EXISTS reconciliation_items_outcome_idx ON reconciliation_items(tenant_id, outcome);
