CREATE TABLE IF NOT EXISTS siem_sinks (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    sink_type text NOT NULL DEFAULT 'webhook',
    url text NOT NULL,
    state text NOT NULL DEFAULT 'active',
    encrypted_secret bytea NOT NULL,
    secret_hint text NOT NULL DEFAULT 'configured',
    cursor_sequence bigint NOT NULL DEFAULT 0,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS siem_sinks_tenant_state_idx ON siem_sinks(tenant_id, state, cursor_sequence);

CREATE TABLE IF NOT EXISTS siem_deliveries (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    sink_id text NOT NULL REFERENCES siem_sinks(id),
    from_sequence bigint NOT NULL DEFAULT 0,
    to_sequence bigint NOT NULL DEFAULT 0,
    state text NOT NULL DEFAULT 'scheduled',
    body bytea NOT NULL,
    body_sha256 text NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_attempt_at timestamptz,
    worker_id text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS siem_deliveries_sequence_unique_idx
    ON siem_deliveries(tenant_id, sink_id, from_sequence, to_sequence)
    WHERE from_sequence > 0 OR to_sequence > 0;
CREATE INDEX IF NOT EXISTS siem_deliveries_tenant_state_due_idx ON siem_deliveries(tenant_id, state, next_attempt_at, created_at);
CREATE INDEX IF NOT EXISTS siem_deliveries_sink_sequence_idx ON siem_deliveries(tenant_id, sink_id, to_sequence DESC);

CREATE TABLE IF NOT EXISTS siem_delivery_attempts (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    delivery_id text NOT NULL REFERENCES siem_deliveries(id) ON DELETE CASCADE,
    status_code integer NOT NULL DEFAULT 0,
    failure_class text NOT NULL DEFAULT '',
    response_body bytea NOT NULL DEFAULT ''::bytea,
    response_truncated boolean NOT NULL DEFAULT false,
    error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS siem_delivery_attempts_delivery_idx ON siem_delivery_attempts(tenant_id, delivery_id, created_at DESC);
