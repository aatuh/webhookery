ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS approval_expires_at timestamptz;

UPDATE replay_jobs
SET approval_expires_at = created_at + interval '24 hours'
WHERE approval_required = true
  AND approval_expires_at IS NULL;

CREATE INDEX IF NOT EXISTS replay_jobs_approval_expiry_idx
    ON replay_jobs(tenant_id, state, approval_expires_at)
    WHERE approval_required = true AND state = 'pending_approval';
