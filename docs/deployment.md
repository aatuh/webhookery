# Deployment Posture

This is the common deployment guide for self-hosted Webhookery. Profile-specific
instructions live under `deploy/`, but production expectations belong here.

Webhookery's release-candidate deployment posture is single-region,
PostgreSQL-first, and operator-managed. It does not claim managed-service
availability, multi-region active-active operation, exactly-once delivery, or
provider-side event completeness.

## External Dependencies

Production-like deployments must provide:

- PostgreSQL for events, receipts, raw payload metadata, dedupe records,
  deliveries, audit rows, retention state, evidence export metadata, and
  durable outbox work.
- TLS-capable API ingress or direct API TLS configuration.
- Secret custody for database URLs, API bootstrap hashes, master keys, provider
  credentials, endpoint signing secrets, object-store credentials, OIDC
  secrets, SIEM secrets, and notification signing secrets.
- Optional S3-compatible object storage when `WEBHOOKERY_RAW_STORAGE_MODE=s3`.
- Backup and restore procedures for PostgreSQL and object storage when used.
- Network controls for API ingress, worker egress, object storage, Vault/AWS
  KMS, and customer-controlled outbound delivery URLs.

Deployment profiles do not install production PostgreSQL, object storage,
ingress, DNS, TLS certificates, network policies, service monitors, or external
secret managers for you.

Hardened examples are included for adaptation:

- `deploy/helm/webhookery/values-production.example.yaml`
- `deploy/kubernetes/networkpolicy.example.yaml`
- `deploy/observability/prometheus-rules.example.yaml`

They are examples only. Review selectors, namespaces, resource requests,
egress rules, and alert thresholds against your environment before use.

## TLS And Ingress

Choose one API TLS boundary and document it:

- terminate TLS in Webhookery with `WEBHOOKERY_TLS_CERT_FILE` and
  `WEBHOOKERY_TLS_KEY_FILE`; or
- terminate TLS at a trusted ingress and route only trusted internal traffic to
  the API.

If producer mTLS is required at the app process, configure
`WEBHOOKERY_PRODUCER_MTLS_CLIENT_CA_FILE` with API TLS certificate and key
files. Webhookery does not trust proxy-supplied mTLS identity headers in this
slice.

If the API sits behind a reverse proxy and session IP metadata should use
`X-Forwarded-For`, set `WEBHOOKERY_TRUSTED_PROXY_CIDRS` only to immediate
proxy CIDRs that the operator controls.

## Secret Custody

Use `docs/configuration.md` as the canonical variable reference.

Minimum secret-bearing values usually include:

- `WEBHOOKERY_DATABASE_URL`
- `WEBHOOKERY_MASTER_KEY_BASE64` for local secret-box mode
- `WEBHOOKERY_VAULT_TOKEN` for Vault Transit mode
- object-store access and secret keys for S3-compatible raw storage
- bootstrap API key hash during controlled bootstrap

Terraform module inputs intentionally do not accept secret values. Create or
rotate Kubernetes Secrets outside Terraform so credentials do not enter
Terraform state.

Do not commit real secrets, provider credentials, private keys, database URLs
with real credentials, raw signatures, raw payloads, or customer data.

## Object Storage

PostgreSQL is always the metadata and evidence authority. S3-compatible object
storage can hold raw bodies when `WEBHOOKERY_RAW_STORAGE_MODE=s3`.

In S3 mode:

- inbound success requires the object write and PostgreSQL metadata commit to
  both succeed;
- backup and restore must cover both PostgreSQL and the bucket;
- object-store TLS should remain enabled in production;
- bucket retention and lifecycle rules must match the retention posture in
  Webhookery.

PostgreSQL dumps do not include S3 object bodies.

## Network Policy And Egress

Workers deliver to customer-controlled URLs. Treat those URLs as hostile input:

- allow HTTPS egress only where possible;
- block private, loopback, link-local, multicast, reserved, and metadata
  addresses at the network layer in addition to application SSRF checks;
- re-resolve and revalidate destinations at delivery time;
- keep redirects disabled unless an audited policy says otherwise.

Also restrict egress to PostgreSQL, object storage, Vault/AWS KMS, notification
receivers, SIEM sinks, and customer endpoints according to the deployment's
network model.

## Readiness And Promotion

Before promotion:

```bash
go run ./cmd/whcp doctor production
make finalize
WEBHOOKERY_TEST_DATABASE_URL=postgres://... make live-postgres-check
WEBHOOKERY_TEST_DATABASE_URL=postgres://... make rc-check
```

Use a disposable database for live checks. Do not point test gates at
production databases or live provider accounts.

After deployment:

- `/readyz` succeeds;
- API, worker, scheduler, and migration job status is healthy;
- `whcp ops storage`, `whcp ops queues`, and `whcp ops metrics` return
  redacted operational state;
- audit-chain verification succeeds;
- bootstrap access has been removed, rotated, or restricted.

## Backup, Restore, Upgrade, And Rollback

Before upgrades that touch migrations, storage, retention, audit chain,
exports, or secret custody:

1. Back up PostgreSQL with `scripts/backup_postgres.sh`.
2. Back up object storage separately when S3 mode is enabled.
3. Restore into a disposable database with `scripts/restore_postgres.sh`.
4. Run migrations on the restored database.
5. Verify `/readyz`, event timelines, audit-chain verification, evidence bundle
   verification, storage status, and queue status.

Rollback is not only an image rollback. Check migration compatibility first.
If a migration is not safe to roll back automatically, restore from a verified
backup into a controlled target and preserve the failed state for analysis.

## Deployment Profiles

| Profile | Path | Boundary |
|---------|------|----------|
| Docker Compose | `docker-compose.yml` | Local development and evaluation. Starts PostgreSQL, migration, API, worker, and optional MinIO profile. |
| Kubernetes | `deploy/kubernetes/` | Minimal manifests for API, worker, scheduler, migration job, config, and placeholder Secret shape. |
| Helm | `deploy/helm/webhookery/` | Chart for the same workload shape with existing Secret support. |
| Terraform | `deploy/terraform/webhookery-helm/` | Wrapper around the Helm chart. Does not manage secrets or external dependencies. |
| Observability examples | `deploy/observability/` | Prometheus starter rules for aggregate metrics. Does not install Prometheus or Alertmanager. |

Use the profile README for exact commands, and use this document for shared
production posture.
