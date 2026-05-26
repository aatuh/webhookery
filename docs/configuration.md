# Configuration Reference

This is the canonical reference for Webhookery environment variables. It covers
the current Go configuration loader, local examples, deployment profiles, and
test-only variables.

Do not commit real database URLs with credentials, API keys, provider
credentials, webhook secrets, Vault tokens, AWS credentials, object-store
secrets, private keys, raw signatures, raw payload bodies, or customer data.
Values shown here are placeholders or local development values.

## Source Files

| File | Use |
|------|-----|
| `.env.example` | Docker Compose local API, worker, scheduler, and migration processes. |
| `.api.env.example` | Local API process without Compose. |
| `.test.env.example` | Optional live integration and RC test variables. |
| `deploy/kubernetes/configmap.yaml` | Non-secret Kubernetes profile defaults. |
| `deploy/kubernetes/secret.example.yaml` | Example Secret shape with placeholders only. |
| `deploy/helm/webhookery/values.yaml` | Helm values for common config and Secret data. |
| `internal/config/config.go` | Current runtime loader and validation behavior. |

The example files are not production-safe. Production operators must replace
placeholder passwords, bootstrap hashes, object-store credentials, and local
master keys through their own secret manager.

## Runtime Variables

| Variable | Applies to | Default | Secret | Production guidance |
|----------|------------|---------|--------|---------------------|
| `WEBHOOKERY_DATABASE_URL` | API, worker, scheduler, migrate, backup, restore | none, required | Yes, when it contains credentials | Use a managed secret. Require TLS to PostgreSQL where available. Do not reuse test databases. |
| `WEBHOOKERY_HTTP_ADDR` | API | `:8080` | No | Bind behind a trusted ingress or load balancer. |
| `WEBHOOKERY_TLS_CERT_FILE` | API | empty | No | Required by `doctor production` unless TLS terminates elsewhere and the deployment accepts that boundary. Configure with `WEBHOOKERY_TLS_KEY_FILE`. |
| `WEBHOOKERY_TLS_KEY_FILE` | API | empty | Yes | Store as a mounted secret. Configure with `WEBHOOKERY_TLS_CERT_FILE`. |
| `WEBHOOKERY_PRODUCER_MTLS_CLIENT_CA_FILE` | API | empty | No | Requires API TLS cert and key. Use only when producer mTLS is part of the trust model. |
| `WEBHOOKERY_ENABLE_UI` | API | `false` | No | Keep disabled unless the operator UI is required. The UI uses the same API authorization model. |
| `WEBHOOKERY_LOG_LEVEL` | API, worker, scheduler | `info` | No | Use `info` in production unless debugging a contained incident. Logs must not include secrets or raw payloads. |
| `WEBHOOKERY_ENVIRONMENT` | API, worker, scheduler, doctor | `development` | No | Set `production` before running `go run ./cmd/whcp doctor production`. |
| `WEBHOOKERY_TRUSTED_PROXY_CIDRS` | API | empty | No | Set only to CIDRs for reverse proxies that Webhookery owns or explicitly trusts. Leave empty for direct API exposure. |
| `WEBHOOKERY_SECRET_BOX_MODE` | API, worker, scheduler | `local` | No | Allowed values are `local`, `vault-transit`, and `aws-kms`. Choose one custody mode before writing production secrets. |
| `WEBHOOKERY_MASTER_KEY_BASE64` | API, worker, scheduler | empty | Yes | Required for `local` secret box mode. Must be base64-encoded 32 bytes. Replace the all-zero local example. |
| `WEBHOOKERY_VAULT_ADDR` | API, worker, scheduler | empty | No | Required for `vault-transit` mode. Use HTTPS in production. |
| `WEBHOOKERY_VAULT_TOKEN` | API, worker, scheduler | empty | Yes | Required for `vault-transit` mode. Store only in a secret manager. |
| `WEBHOOKERY_VAULT_TRANSIT_KEY` | API, worker, scheduler | empty | Usually no | Required for `vault-transit` mode. Treat key names as operational metadata. |
| `WEBHOOKERY_AWS_REGION` | API, worker, scheduler | empty | No | Required for `aws-kms` mode. |
| `WEBHOOKERY_AWS_KMS_KEY_ID` | API, worker, scheduler | empty | Sensitive metadata | Required for `aws-kms` mode. Avoid printing full key IDs in logs or support artifacts. |
| `WEBHOOKERY_AWS_KMS_ENDPOINT` | API, worker, scheduler | empty | No | Optional. Use only for LocalStack or controlled test endpoints; `doctor production` warns on HTTP endpoints. |
| `WEBHOOKERY_RAW_STORAGE_MODE` | API, worker | `postgres` | No | Allowed values are `postgres` and `s3`. PostgreSQL remains the metadata authority. |
| `WEBHOOKERY_OBJECT_STORAGE_ENDPOINT` | API, worker | empty | No | Required when raw storage mode is `s3`. Use an internal endpoint where possible. |
| `WEBHOOKERY_OBJECT_STORAGE_BUCKET` | API, worker | empty | No | Required when raw storage mode is `s3`. Use a dedicated bucket with backup and retention policy. |
| `WEBHOOKERY_OBJECT_STORAGE_ACCESS_KEY` | API, worker | empty | Yes | Required when raw storage mode is `s3`. Use a scoped credential. |
| `WEBHOOKERY_OBJECT_STORAGE_SECRET_KEY` | API, worker | empty | Yes | Required when raw storage mode is `s3`. Store only in a secret manager. |
| `WEBHOOKERY_OBJECT_STORAGE_REGION` | API, worker | empty | No | Set according to the object store. |
| `WEBHOOKERY_OBJECT_STORAGE_USE_SSL` | API, worker | `true` | No | Keep `true` in production unless the object store is reached over a controlled private channel with separate transport protection. |
| `WEBHOOKERY_BOOTSTRAP_TENANT_ID` | API | `ten_bootstrap` | No | Use a stable tenant ID only for controlled bootstrap. |
| `WEBHOOKERY_BOOTSTRAP_API_KEY_HASH` | API | empty | Sensitive | Use only for initial bootstrap. Remove or rotate after creating database-backed API keys. |
| `WEBHOOKERY_BOOTSTRAP_API_KEY_PREFIX` | API | empty | No | Display prefix only. Do not use a real API key as the prefix. |

## Test And Release Variables

| Variable | Applies to | Required when | Secret | Guidance |
|----------|------------|---------------|--------|----------|
| `WEBHOOKERY_TEST_DATABASE_URL` | `make live-postgres-check`, DB-backed `make rc-check`, integration tests | Running live PostgreSQL checks | Yes, when it contains credentials | Use a disposable database. Never point it at production. |
| `WEBHOOKERY_RC_RESTORE_DATABASE_URL` | `make rc-check` restore drill | Running the destructive restore drill | Yes, when it contains credentials | Must point to a separate disposable restore database. |
| `WEBHOOKERY_TEST_REDIS_ADDR` | `make redis-integration-test` | Running Redis integration tests | No | Redis is not an audit authority. |
| `WEBHOOKERY_TEST_MASTER_KEY_BASE64` | Test fixtures | Tests that need an explicit test key | Yes | Use only local test values. |
| `WEBHOOKERY_RESTORE_CONFIRM` | `scripts/restore_postgres.sh` | Restoring a PostgreSQL dump | No | Must be exactly `restore`; this is a destructive-action guard. |

## Secret Custody

Secret-bearing variables must be provided by the operator's secret manager or
orchestrator secret facility:

- `WEBHOOKERY_DATABASE_URL`
- `WEBHOOKERY_TLS_KEY_FILE`
- `WEBHOOKERY_MASTER_KEY_BASE64`
- `WEBHOOKERY_VAULT_TOKEN`
- `WEBHOOKERY_OBJECT_STORAGE_ACCESS_KEY`
- `WEBHOOKERY_OBJECT_STORAGE_SECRET_KEY`
- `WEBHOOKERY_BOOTSTRAP_API_KEY_HASH`
- live test database URLs when they include credentials

`WEBHOOKERY_AWS_KMS_KEY_ID` and `WEBHOOKERY_VAULT_TRANSIT_KEY` are usually
identifiers rather than secret values, but they can reveal infrastructure shape.
Avoid full values in public logs, issues, screenshots, and support requests.

## Profile Notes

Docker Compose reads `.env` from `.env.example` and starts PostgreSQL, the
migration job, API, and worker. The optional object-storage profile starts
MinIO and uses the local object-storage placeholders from `.env.example`.

Kubernetes and Helm profiles expect an externally managed PostgreSQL database
and a separately managed Secret. The checked-in Secret examples use placeholders
only. They are shape examples, not credentials.

Terraform wraps the Helm chart and intentionally does not accept secret values
as module variables. Create or rotate Kubernetes Secrets outside Terraform so
credentials do not enter Terraform state.

## Production Review

Before promoting a deployment, run:

```bash
go run ./cmd/whcp doctor production
```

Fix all blockers. The doctor reads configuration and environment values, but it
must not print database passwords, API keys, webhook secrets, Vault tokens, AWS
credentials, raw KMS key IDs, object-store credentials, raw payloads, or raw
signatures.
