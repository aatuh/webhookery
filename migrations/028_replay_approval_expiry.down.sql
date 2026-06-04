DROP INDEX IF EXISTS replay_jobs_approval_expiry_idx;

ALTER TABLE replay_jobs DROP COLUMN IF EXISTS approval_expires_at;
