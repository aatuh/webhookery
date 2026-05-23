CREATE TABLE IF NOT EXISTS dedupe_records (
    tenant_id text NOT NULL REFERENCES tenants(id),
    source_id text NOT NULL REFERENCES sources(id),
    dedupe_key text NOT NULL,
    first_event_id text NOT NULL REFERENCES events(id),
    last_receipt_id text,
    status text NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS dedupe_records_source_idx ON dedupe_records(tenant_id, source_id, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS replay_items (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    replay_job_id text NOT NULL REFERENCES replay_jobs(id),
    event_id text REFERENCES events(id),
    original_delivery_id text,
    new_delivery_id text,
    state text NOT NULL DEFAULT 'scheduled',
    error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS replay_items_job_idx ON replay_items(tenant_id, replay_job_id, state, created_at);
