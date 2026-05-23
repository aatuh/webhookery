ALTER TABLE replay_jobs DROP COLUMN IF EXISTS paused_at;
ALTER TABLE replay_jobs DROP COLUMN IF EXISTS canceled_at;
ALTER TABLE replay_jobs DROP COLUMN IF EXISTS completed_at;
ALTER TABLE replay_jobs DROP COLUMN IF EXISTS failed_items;
ALTER TABLE replay_jobs DROP COLUMN IF EXISTS processed_items;
ALTER TABLE replay_jobs DROP COLUMN IF EXISTS total_items;

DROP INDEX IF EXISTS endpoints_circuit_idx;
ALTER TABLE endpoints DROP COLUMN IF EXISTS disabled_until;
ALTER TABLE endpoints DROP COLUMN IF EXISTS failure_count;
ALTER TABLE endpoints DROP COLUMN IF EXISTS circuit_state;

DROP TABLE IF EXISTS config_versions;
DROP TABLE IF EXISTS idempotency_records;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS users;
