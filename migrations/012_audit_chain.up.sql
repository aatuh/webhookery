CREATE TABLE IF NOT EXISTS audit_chain_heads (
    tenant_id text PRIMARY KEY REFERENCES tenants(id),
    sequence bigint NOT NULL DEFAULT 0,
    chain_hash text NOT NULL DEFAULT '',
    last_audit_event_id text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_chain_entries (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    sequence bigint NOT NULL,
    audit_event_id text NOT NULL,
    event_hash text NOT NULL,
    previous_chain_hash text NOT NULL DEFAULT '',
    chain_hash text NOT NULL,
    canonicalization_version text NOT NULL,
    source text NOT NULL DEFAULT 'live',
    state text NOT NULL DEFAULT 'active',
    audit_event_deleted_at timestamptz,
    tombstone_reason text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, sequence),
    UNIQUE (tenant_id, audit_event_id)
);
CREATE INDEX IF NOT EXISTS audit_chain_entries_tenant_event_idx ON audit_chain_entries(tenant_id, audit_event_id);
CREATE INDEX IF NOT EXISTS audit_chain_entries_tenant_state_idx ON audit_chain_entries(tenant_id, state, sequence);

CREATE TABLE IF NOT EXISTS audit_chain_anchors (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    from_sequence bigint NOT NULL,
    to_sequence bigint NOT NULL,
    chain_hash text NOT NULL,
    manifest_sha256 text NOT NULL,
    storage_backend text NOT NULL DEFAULT 'postgres',
    object_bucket text NOT NULL DEFAULT '',
    object_key text NOT NULL DEFAULT '',
    manifest jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by text NOT NULL DEFAULT '',
    reason text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_chain_anchors_tenant_created_idx ON audit_chain_anchors(tenant_id, created_at DESC);
