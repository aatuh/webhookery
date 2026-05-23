CREATE TABLE IF NOT EXISTS schema_migrations (
    version text PRIMARY KEY,
    checksum text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenants (
    id text PRIMARY KEY,
    name text NOT NULL DEFAULT '',
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sources (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    provider text NOT NULL,
    adapter text NOT NULL,
    state text NOT NULL,
    encrypted_secret bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sources_tenant_provider_idx ON sources(tenant_id, provider);
CREATE UNIQUE INDEX IF NOT EXISTS sources_provider_id_idx ON sources(provider, id);

CREATE TABLE IF NOT EXISTS endpoints (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    url text NOT NULL,
    state text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS endpoints_tenant_state_idx ON endpoints(tenant_id, state);

CREATE TABLE IF NOT EXISTS raw_payloads (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    event_id text,
    sha256 text NOT NULL,
    content_type text NOT NULL DEFAULT '',
    size_bytes bigint NOT NULL,
    body bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS raw_payloads_tenant_event_idx ON raw_payloads(tenant_id, event_id);
CREATE INDEX IF NOT EXISTS raw_payloads_sha_idx ON raw_payloads(sha256);

CREATE TABLE IF NOT EXISTS events (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    source_id text NOT NULL REFERENCES sources(id),
    provider text NOT NULL,
    type text NOT NULL DEFAULT '',
    provider_event_id text NOT NULL DEFAULT '',
    raw_payload_id text NOT NULL REFERENCES raw_payloads(id),
    raw_payload_hash text NOT NULL,
    signature_verified boolean NOT NULL,
    verification_reason text NOT NULL,
    dedupe_key text NOT NULL,
    dedupe_status text NOT NULL,
    received_at timestamptz NOT NULL,
    trace_id text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_tenant_received_idx ON events(tenant_id, received_at DESC);
CREATE INDEX IF NOT EXISTS events_tenant_type_idx ON events(tenant_id, type);
CREATE UNIQUE INDEX IF NOT EXISTS events_tenant_dedupe_key_idx ON events(tenant_id, dedupe_key);

CREATE TABLE IF NOT EXISTS provider_receipts (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    source_id text NOT NULL REFERENCES sources(id),
    event_id text,
    raw_payload_id text NOT NULL REFERENCES raw_payloads(id),
    raw_headers jsonb NOT NULL,
    remote_ip text NOT NULL DEFAULT '',
    verification_ok boolean NOT NULL,
    verification_reason text NOT NULL,
    received_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS provider_receipts_event_idx ON provider_receipts(tenant_id, event_id);

CREATE TABLE IF NOT EXISTS deliveries (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    event_id text NOT NULL REFERENCES events(id),
    endpoint_id text NOT NULL REFERENCES endpoints(id),
    state text NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS deliveries_sched_idx ON deliveries(state, next_attempt_at);
CREATE INDEX IF NOT EXISTS deliveries_tenant_event_idx ON deliveries(tenant_id, event_id);

CREATE TABLE IF NOT EXISTS delivery_attempts (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    delivery_id text NOT NULL REFERENCES deliveries(id),
    event_id text NOT NULL REFERENCES events(id),
    endpoint_id text NOT NULL REFERENCES endpoints(id),
    attempt_no integer NOT NULL,
    state text NOT NULL,
    response_status integer,
    response_body_truncated text NOT NULL DEFAULT '',
    failure_class text NOT NULL DEFAULT '',
    retryable boolean NOT NULL DEFAULT false,
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

CREATE TABLE IF NOT EXISTS replay_jobs (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    state text NOT NULL,
    scope_hash text NOT NULL,
    reason text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS replay_receipts (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    replay_job_id text NOT NULL REFERENCES replay_jobs(id),
    event_id text,
    delivery_id text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dead_letter_entries (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    delivery_id text,
    event_id text,
    reason text NOT NULL,
    state text NOT NULL DEFAULT 'open',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS quarantine_entries (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    event_id text,
    reason text NOT NULL,
    state text NOT NULL DEFAULT 'open',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    actor_id text NOT NULL DEFAULT '',
    action text NOT NULL,
    resource text NOT NULL,
    resource_id text NOT NULL,
    reason text NOT NULL DEFAULT '',
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_events_tenant_time_idx ON audit_events(tenant_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS outbox (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    kind text NOT NULL,
    resource_id text NOT NULL,
    state text NOT NULL DEFAULT 'pending',
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    available_at timestamptz NOT NULL DEFAULT now(),
    locked_by text,
    lock_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS outbox_pending_idx ON outbox(state, available_at);

CREATE TABLE IF NOT EXISTS worker_leases (
    id text PRIMARY KEY,
    worker_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
