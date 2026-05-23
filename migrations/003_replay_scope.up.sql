ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS scope_json jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS replay_jobs_tenant_state_idx ON replay_jobs(tenant_id, state, created_at DESC);
