ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS retry_seed text NOT NULL DEFAULT '';
ALTER TABLE delivery_attempts ADD COLUMN IF NOT EXISTS retry_delay_ms bigint NOT NULL DEFAULT 0;
ALTER TABLE delivery_attempts ADD COLUMN IF NOT EXISTS next_retry_at timestamptz;

UPDATE deliveries
SET retry_seed = 'retryseed:v1:legacy:' || md5(tenant_id || ':' || id || ':' || event_id || ':' || endpoint_id)
WHERE retry_seed = '';

CREATE INDEX IF NOT EXISTS deliveries_retry_seed_idx ON deliveries(tenant_id, retry_seed);
