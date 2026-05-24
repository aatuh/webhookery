CREATE TABLE IF NOT EXISTS alert_rules (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    rule_type text NOT NULL,
    metric_name text NOT NULL,
    threshold double precision NOT NULL,
    comparator text NOT NULL DEFAULT '>=',
    window_seconds integer NOT NULL DEFAULT 300,
    dimensions jsonb NOT NULL DEFAULT '{}'::jsonb,
    state text NOT NULL DEFAULT 'active',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS alert_rules_tenant_state_idx ON alert_rules(tenant_id, state, rule_type);

CREATE TABLE IF NOT EXISTS alert_firings (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    rule_id text NOT NULL REFERENCES alert_rules(id),
    state text NOT NULL,
    observed_value double precision NOT NULL DEFAULT 0,
    threshold double precision NOT NULL DEFAULT 0,
    reason text NOT NULL DEFAULT '',
    started_at timestamptz NOT NULL DEFAULT now(),
    last_evaluated_at timestamptz NOT NULL DEFAULT now(),
    acknowledged_by text NOT NULL DEFAULT '',
    acknowledged_at timestamptz,
    resolved_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alert_firings_tenant_state_idx ON alert_firings(tenant_id, state, started_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS alert_firings_open_rule_idx ON alert_firings(tenant_id, rule_id) WHERE state IN ('open', 'acknowledged');
