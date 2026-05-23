ALTER TABLE replay_items ADD COLUMN IF NOT EXISTS delivery_payload_sha256 text NOT NULL DEFAULT '';
ALTER TABLE replay_receipts ADD COLUMN IF NOT EXISTS delivery_payload_sha256 text NOT NULL DEFAULT '';
