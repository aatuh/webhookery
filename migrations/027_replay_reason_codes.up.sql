ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS reason_code text NOT NULL DEFAULT 'operator_requested';

