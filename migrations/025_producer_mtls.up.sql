CREATE TABLE IF NOT EXISTS producer_mtls_identities (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    source_id text,
    certificate_fingerprint_sha256 text NOT NULL,
    cert_subject text NOT NULL DEFAULT '',
    dns_sans text[] NOT NULL DEFAULT ARRAY[]::text[],
    uri_sans text[] NOT NULL DEFAULT ARRAY[]::text[],
    email_sans text[] NOT NULL DEFAULT ARRAY[]::text[],
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    FOREIGN KEY (source_id) REFERENCES sources(id),
    UNIQUE (certificate_fingerprint_sha256)
);
CREATE INDEX IF NOT EXISTS producer_mtls_identities_tenant_state_idx ON producer_mtls_identities(tenant_id, state, created_at DESC);
CREATE INDEX IF NOT EXISTS producer_mtls_identities_fingerprint_idx ON producer_mtls_identities(certificate_fingerprint_sha256, state);
