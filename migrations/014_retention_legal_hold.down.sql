DROP INDEX IF EXISTS retention_policies_hold_idx;
ALTER TABLE retention_policies DROP COLUMN IF EXISTS hold_reason;
ALTER TABLE retention_policies DROP COLUMN IF EXISTS legal_hold;
