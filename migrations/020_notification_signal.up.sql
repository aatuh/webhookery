CREATE TABLE IF NOT EXISTS notification_channels (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    channel_type text NOT NULL DEFAULT 'webhook',
    url text NOT NULL,
    state text NOT NULL DEFAULT 'active',
    encrypted_secret bytea NOT NULL,
    secret_hint text NOT NULL DEFAULT 'configured',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS notification_channels_tenant_state_idx ON notification_channels(tenant_id, state, created_at DESC);

CREATE TABLE IF NOT EXISTS alert_rule_channels (
    tenant_id text NOT NULL REFERENCES tenants(id),
    alert_rule_id text NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    channel_id text NOT NULL REFERENCES notification_channels(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, alert_rule_id, channel_id)
);
CREATE INDEX IF NOT EXISTS alert_rule_channels_channel_idx ON alert_rule_channels(tenant_id, channel_id);

CREATE TABLE IF NOT EXISTS notification_deliveries (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    channel_id text NOT NULL REFERENCES notification_channels(id),
    firing_id text NOT NULL DEFAULT '',
    transition text NOT NULL,
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
CREATE INDEX IF NOT EXISTS notification_deliveries_tenant_state_due_idx ON notification_deliveries(tenant_id, state, next_attempt_at, created_at);
CREATE INDEX IF NOT EXISTS notification_deliveries_tenant_channel_idx ON notification_deliveries(tenant_id, channel_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS notification_deliveries_transition_unique_idx
    ON notification_deliveries(tenant_id, channel_id, firing_id, transition)
    WHERE firing_id <> '';

CREATE TABLE IF NOT EXISTS notification_delivery_attempts (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    delivery_id text NOT NULL REFERENCES notification_deliveries(id) ON DELETE CASCADE,
    status_code integer NOT NULL DEFAULT 0,
    failure_class text NOT NULL DEFAULT '',
    response_body bytea NOT NULL DEFAULT ''::bytea,
    response_truncated boolean NOT NULL DEFAULT false,
    error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS notification_delivery_attempts_delivery_idx ON notification_delivery_attempts(tenant_id, delivery_id, created_at DESC);
