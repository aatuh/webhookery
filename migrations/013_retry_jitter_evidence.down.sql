DROP INDEX IF EXISTS deliveries_retry_seed_idx;
ALTER TABLE delivery_attempts DROP COLUMN IF EXISTS next_retry_at;
ALTER TABLE delivery_attempts DROP COLUMN IF EXISTS retry_delay_ms;
ALTER TABLE deliveries DROP COLUMN IF EXISTS retry_seed;
