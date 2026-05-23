ALTER TABLE replay_items DROP COLUMN IF EXISTS retry_policy_id;
ALTER TABLE replay_items DROP COLUMN IF EXISTS route_version_id;
ALTER TABLE replay_items DROP COLUMN IF EXISTS config_mode;
ALTER TABLE replay_jobs DROP COLUMN IF EXISTS rate_limit_per_minute;
ALTER TABLE replay_jobs DROP COLUMN IF EXISTS config_mode;

DROP INDEX IF EXISTS endpoint_secrets_version_unique;
ALTER TABLE endpoint_secrets DROP COLUMN IF EXISTS revoked_at;
ALTER TABLE endpoint_secrets DROP COLUMN IF EXISTS created_by;
ALTER TABLE endpoint_secrets DROP COLUMN IF EXISTS expires_at;
ALTER TABLE endpoint_secrets DROP COLUMN IF EXISTS active_at;
ALTER TABLE endpoint_secrets DROP COLUMN IF EXISTS version;

DROP INDEX IF EXISTS source_secret_versions_lookup_idx;
DROP TABLE IF EXISTS source_secret_versions;

ALTER TABLE delivery_attempts DROP COLUMN IF EXISTS response_sha256;
ALTER TABLE delivery_attempts DROP COLUMN IF EXISTS request_sha256;
ALTER TABLE deliveries DROP COLUMN IF EXISTS retry_policy_id;
ALTER TABLE deliveries DROP COLUMN IF EXISTS route_version_id;

ALTER TABLE routes DROP COLUMN IF EXISTS retry_policy_id;
ALTER TABLE routes DROP COLUMN IF EXISTS active_version_id;
DROP INDEX IF EXISTS route_versions_route_idx;
DROP TABLE IF EXISTS route_versions;

ALTER TABLE endpoints DROP COLUMN IF EXISTS retry_policy_id;

DROP INDEX IF EXISTS retry_policies_tenant_state_idx;
DROP TABLE IF EXISTS retry_policies;

DROP INDEX IF EXISTS config_versions_resource_version_unique;
ALTER TABLE config_versions DROP COLUMN IF EXISTS config_json;
