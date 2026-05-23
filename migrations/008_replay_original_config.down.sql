ALTER TABLE replay_receipts DROP COLUMN IF EXISTS schema_version_id;
ALTER TABLE replay_receipts DROP COLUMN IF EXISTS retry_policy_id;
ALTER TABLE replay_receipts DROP COLUMN IF EXISTS subscription_version_id;
ALTER TABLE replay_receipts DROP COLUMN IF EXISTS route_version_id;
ALTER TABLE replay_receipts DROP COLUMN IF EXISTS config_mode;

ALTER TABLE replay_items DROP COLUMN IF EXISTS subscription_version_id;

DROP INDEX IF EXISTS deliveries_live_priority_idx;
ALTER TABLE deliveries DROP COLUMN IF EXISTS replay_job_id;
ALTER TABLE deliveries DROP COLUMN IF EXISTS subscription_version_id;

ALTER TABLE subscriptions DROP COLUMN IF EXISTS active_version_id;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS version;

DROP INDEX IF EXISTS subscription_versions_subscription_idx;
DROP TABLE IF EXISTS subscription_versions;
