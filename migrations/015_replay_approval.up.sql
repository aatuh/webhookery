ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS approval_required boolean NOT NULL DEFAULT false;
ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS approved_by text NOT NULL DEFAULT '';
ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS approved_at timestamptz;
ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS approval_reason text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS replay_jobs_approval_idx ON replay_jobs(tenant_id, state, approval_required, created_at DESC);
