CREATE TABLE IF NOT EXISTS incidents (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    title text NOT NULL,
    reason text NOT NULL DEFAULT '',
    state text NOT NULL DEFAULT 'active',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS incidents_tenant_state_created_idx ON incidents(tenant_id, state, created_at DESC);

CREATE TABLE IF NOT EXISTS incident_events (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    incident_id text NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_id text NOT NULL REFERENCES events(id),
    added_by text NOT NULL DEFAULT '',
    reason text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, incident_id, event_id)
);
CREATE INDEX IF NOT EXISTS incident_events_tenant_incident_idx ON incident_events(tenant_id, incident_id, created_at ASC);
CREATE INDEX IF NOT EXISTS incident_events_tenant_event_idx ON incident_events(tenant_id, event_id, created_at DESC);

CREATE TABLE IF NOT EXISTS incident_report_snapshots (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    incident_id text NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    schema_version text NOT NULL,
    report_json jsonb NOT NULL,
    report_markdown text NOT NULL,
    generated_by text NOT NULL DEFAULT '',
    generated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS incident_report_snapshots_latest_idx ON incident_report_snapshots(tenant_id, incident_id, generated_at DESC);

CREATE TABLE IF NOT EXISTS incident_evidence_exports (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    incident_id text NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    export_id text NOT NULL REFERENCES evidence_exports(id),
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS incident_evidence_exports_tenant_incident_idx ON incident_evidence_exports(tenant_id, incident_id, created_at DESC);
