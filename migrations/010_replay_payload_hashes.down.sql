ALTER TABLE replay_receipts DROP COLUMN IF EXISTS delivery_payload_sha256;
ALTER TABLE replay_items DROP COLUMN IF EXISTS delivery_payload_sha256;
