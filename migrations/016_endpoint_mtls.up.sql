ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS mtls_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS mtls_cert_subject text NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS encrypted_mtls_client_cert bytea;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS encrypted_mtls_client_key bytea;

CREATE INDEX IF NOT EXISTS endpoints_mtls_idx ON endpoints(tenant_id, mtls_enabled, state);
