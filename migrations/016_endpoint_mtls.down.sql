DROP INDEX IF EXISTS endpoints_mtls_idx;

ALTER TABLE endpoints DROP COLUMN IF EXISTS encrypted_mtls_client_key;
ALTER TABLE endpoints DROP COLUMN IF EXISTS encrypted_mtls_client_cert;
ALTER TABLE endpoints DROP COLUMN IF EXISTS mtls_cert_subject;
ALTER TABLE endpoints DROP COLUMN IF EXISTS mtls_enabled;
