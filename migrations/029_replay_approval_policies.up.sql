CREATE TABLE IF NOT EXISTS replay_approval_policies (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    scope_type text NOT NULL,
    scope_id text NOT NULL DEFAULT '',
    require_approval boolean NOT NULL DEFAULT true,
    default_expiry_seconds integer NOT NULL DEFAULT 86400,
    state text NOT NULL DEFAULT 'active',
    reason text NOT NULL DEFAULT '',
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS replay_approval_policies_active_idx
    ON replay_approval_policies(tenant_id, scope_type, scope_id)
    WHERE state = 'active' AND require_approval = true;
