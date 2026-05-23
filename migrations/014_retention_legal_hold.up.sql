ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS legal_hold boolean NOT NULL DEFAULT false;
ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS hold_reason text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS retention_policies_hold_idx ON retention_policies(tenant_id, legal_hold, state, updated_at);
