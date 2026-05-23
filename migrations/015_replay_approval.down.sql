DROP INDEX IF EXISTS replay_jobs_approval_idx;

ALTER TABLE replay_jobs DROP COLUMN IF EXISTS approval_reason;
ALTER TABLE replay_jobs DROP COLUMN IF EXISTS approved_at;
ALTER TABLE replay_jobs DROP COLUMN IF EXISTS approved_by;
ALTER TABLE replay_jobs DROP COLUMN IF EXISTS approval_required;
