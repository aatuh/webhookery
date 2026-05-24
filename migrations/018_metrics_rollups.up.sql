CREATE TABLE IF NOT EXISTS metrics_rollups (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    metric_name text NOT NULL,
    bucket_start timestamptz NOT NULL,
    bucket_seconds integer NOT NULL,
    dimensions jsonb NOT NULL DEFAULT '{}'::jsonb,
    dimensions_hash text NOT NULL,
    value double precision NOT NULL,
    source text NOT NULL DEFAULT 'scheduler',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, metric_name, bucket_start, dimensions_hash)
);
CREATE INDEX IF NOT EXISTS metrics_rollups_tenant_metric_idx ON metrics_rollups(tenant_id, metric_name, bucket_start DESC);
