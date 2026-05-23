DROP INDEX IF EXISTS replay_jobs_tenant_state_idx;
ALTER TABLE replay_jobs DROP COLUMN IF EXISTS scope_json;
