ALTER TABLE evidence_exports DROP COLUMN IF EXISTS include_payload_bodies;

ALTER TABLE replay_receipts DROP COLUMN IF EXISTS delivery_payload_id;
ALTER TABLE replay_receipts DROP COLUMN IF EXISTS transformation_version_id;
ALTER TABLE replay_receipts DROP COLUMN IF EXISTS normalized_envelope_id;
ALTER TABLE replay_receipts DROP COLUMN IF EXISTS adapter_version_id;

ALTER TABLE replay_items DROP COLUMN IF EXISTS delivery_payload_id;
ALTER TABLE replay_items DROP COLUMN IF EXISTS transformation_version_id;
ALTER TABLE replay_items DROP COLUMN IF EXISTS normalized_envelope_id;
ALTER TABLE replay_items DROP COLUMN IF EXISTS adapter_version_id;

DROP INDEX IF EXISTS delivery_payloads_storage_idx;
DROP INDEX IF EXISTS delivery_payloads_tenant_event_idx;
DROP TABLE IF EXISTS delivery_payloads;

ALTER TABLE deliveries DROP COLUMN IF EXISTS delivery_payload_id;
ALTER TABLE deliveries DROP COLUMN IF EXISTS transformation_version_id;
ALTER TABLE deliveries DROP COLUMN IF EXISTS normalized_envelope_id;
ALTER TABLE deliveries DROP COLUMN IF EXISTS adapter_version_id;

ALTER TABLE route_versions DROP COLUMN IF EXISTS transformation_version_id;
ALTER TABLE route_versions DROP COLUMN IF EXISTS transformation_id;
ALTER TABLE routes DROP COLUMN IF EXISTS transformation_version_id;
ALTER TABLE routes DROP COLUMN IF EXISTS transformation_id;

ALTER TABLE subscription_versions DROP COLUMN IF EXISTS transformation_version_id;
ALTER TABLE subscription_versions DROP COLUMN IF EXISTS transformation_id;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS transformation_version_id;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS transformation_id;

DROP INDEX IF EXISTS transformation_versions_lookup_idx;
DROP TABLE IF EXISTS transformation_versions;
DROP INDEX IF EXISTS transformations_tenant_state_idx;
DROP TABLE IF EXISTS transformations;

DROP INDEX IF EXISTS normalized_envelopes_tenant_type_idx;
DROP INDEX IF EXISTS normalized_envelopes_tenant_event_idx;
DROP TABLE IF EXISTS normalized_envelopes;

DROP INDEX IF EXISTS adapter_versions_name_state_idx;
DROP TABLE IF EXISTS adapter_versions;
DROP TABLE IF EXISTS provider_adapters;
