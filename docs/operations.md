# Webhookery Operations

This document is the operator runbook for the implemented self-hosted release
candidate. It is not a product marketing page, API reference, CLI catalog, or
feature behavior reference.

Use these canonical references with this runbook:

- `docs/configuration.md`: environment variables, defaults, safe production
  values, and secret sensitivity.
- `docs/feature-behavior.md`: capture, auth, routing, delivery, replay,
  reconciliation, transformations, retention, identity, producer trust, and
  SSRF behavior.
- `docs/cli.md`: `whcp` command catalog.
- `openapi.yaml`: REST API contract.
- `docs/release-evidence-template.md`: release evidence checklist.
- `deploy/`: deployment profile specifics.

## Operating Promise

See `docs/security-promise.md` for the canonical durable-capture promise and
non-claims. Operationally, inbound success means Webhookery durably captured
raw request evidence and verification metadata according to the configured
storage mode. It does not mean downstream business processing succeeded.

Release evidence and deployment profile checks intentionally preserve this
phrase: no FIPS/NIST/CMVP certification.

## Deployment Posture

The release-candidate topology is single-region and PostgreSQL-first:

- API, worker, scheduler, and migration processes are Go binaries from this
  repository.
- PostgreSQL is the source of truth for events, receipts, raw payload metadata,
  dedupe records, delivery state, audit rows, retention state, evidence export
  metadata, and durable outbox work.
- Raw payload bodies default to PostgreSQL `bytea`.
- S3-compatible raw payload storage is optional. With
  `WEBHOOKERY_RAW_STORAGE_MODE=s3`, inbound success requires both the object
  write and PostgreSQL metadata transaction to succeed.
- Kubernetes, Helm, and Terraform profiles expect external PostgreSQL and
  externally managed production secrets.

Object storage can hold raw bodies, but PostgreSQL remains the evidence and
metadata authority. Back up both PostgreSQL and object storage when S3 mode is
enabled.

## Production Doctor Runbook

Run the production doctor before promotion, after configuration changes, and
before upgrades that affect storage, key custody, TLS, object storage, or
bootstrap access:

```bash
WEBHOOKERY_ENVIRONMENT=production go run ./cmd/whcp doctor production
```

The doctor reads environment and configuration only. It does not connect to
PostgreSQL, object storage, Vault, AWS KMS, webhook receivers, or live
providers. It does not replace readiness checks, RC checks, or restore drills.

Severity meanings:

| Severity | Meaning | Required action |
|----------|---------|-----------------|
| `blocker` | Unsafe or incomplete production posture. The command exits non-zero. | Fix before promotion. |
| `warning` | Operator review item. The command may exit zero. | Accept deliberately or remediate. |
| `ok` | Checked setting has production-acceptable shape. | No action. |

The doctor output must not print database passwords, API keys, webhook secrets,
OAuth tokens, Vault tokens, AWS credentials, raw KMS key IDs, object-store
credentials, private keys, raw signatures, or raw payload bodies.

Common production preflight shapes:

```bash
WEBHOOKERY_ENVIRONMENT=production
WEBHOOKERY_DATABASE_URL=postgres://webhookery:<password>@postgres.example:5432/webhookery?sslmode=require
WEBHOOKERY_TLS_CERT_FILE=/etc/webhookery/tls/tls.crt
WEBHOOKERY_TLS_KEY_FILE=/etc/webhookery/tls/tls.key
WEBHOOKERY_SECRET_BOX_MODE=local
WEBHOOKERY_MASTER_KEY_BASE64=<base64-32-byte-key>
WEBHOOKERY_BOOTSTRAP_API_KEY_HASH=<sha256-hash-or-empty-after-bootstrap>
go run ./cmd/whcp doctor production
```

```bash
WEBHOOKERY_ENVIRONMENT=production
WEBHOOKERY_SECRET_BOX_MODE=vault-transit
WEBHOOKERY_VAULT_ADDR=https://vault.internal
WEBHOOKERY_VAULT_TOKEN=<vault-token>
WEBHOOKERY_VAULT_TRANSIT_KEY=webhookery
go run ./cmd/whcp doctor production
```

```bash
WEBHOOKERY_ENVIRONMENT=production
WEBHOOKERY_SECRET_BOX_MODE=aws-kms
WEBHOOKERY_AWS_REGION=us-east-1
WEBHOOKERY_AWS_KMS_KEY_ID=<kms-key-id-or-arn>
go run ./cmd/whcp doctor production
```

```bash
WEBHOOKERY_ENVIRONMENT=production
WEBHOOKERY_RAW_STORAGE_MODE=s3
WEBHOOKERY_OBJECT_STORAGE_ENDPOINT=s3.example
WEBHOOKERY_OBJECT_STORAGE_BUCKET=webhookery-raw
WEBHOOKERY_OBJECT_STORAGE_ACCESS_KEY=<object-access-key>
WEBHOOKERY_OBJECT_STORAGE_SECRET_KEY=<object-secret-key>
WEBHOOKERY_OBJECT_STORAGE_USE_SSL=true
go run ./cmd/whcp doctor production
```

Local development should use `.env.example`,
`WEBHOOKERY_ENVIRONMENT=development`, and Docker Compose. Do not treat the
production doctor as the local development gate.

## Release-Candidate Checklist

Before promoting a release candidate:

1. Run `go run ./cmd/whcp doctor production`. Fix blockers.
2. Run `make finalize` on the release candidate commit.
3. Run `WEBHOOKERY_TEST_DATABASE_URL=postgres://... make live-postgres-check`
   against a disposable PostgreSQL database.
4. Run non-live `make rc-check`. It must not require live third-party provider,
   AWS, Vault, Slack, PagerDuty, SIEM, or customer receiver calls.
5. Run DB-backed `WEBHOOKERY_TEST_DATABASE_URL=postgres://... make rc-check`
   against a disposable database.
6. For migration, storage, retention, export, or audit-chain changes, set
   `WEBHOOKERY_RC_RESTORE_DATABASE_URL=postgres://...` to a separate disposable
   restore database before `make rc-check`.
7. Verify `/readyz`, `/v1/ops/storage`, `/v1/ops/config`, `/v1/ops/queues`,
   `/v1/ops/metrics`, alert firings, and audit-chain verification after
   deployment.
8. Remove, rotate, or restrict bootstrap API key posture after a database-
   backed owner or security key exists.

Expected local RC sequence:

```bash
docker compose up -d postgres
WEBHOOKERY_TEST_DATABASE_URL=postgres://webhookery:change-me@localhost:5432/webhookery?sslmode=disable make live-postgres-check
WEBHOOKERY_TEST_DATABASE_URL=postgres://webhookery:change-me@localhost:5432/webhookery?sslmode=disable make rc-check
```

A successful run ends with:

```text
rc-check: release-candidate acceptance checks passed
```

Restore drills require a separate disposable restore database:

```bash
WEBHOOKERY_TEST_DATABASE_URL=postgres://webhookery:change-me@localhost:5432/webhookery?sslmode=disable \
WEBHOOKERY_RC_RESTORE_DATABASE_URL=postgres://webhookery_restore:change-me@localhost:5433/webhookery_restore?sslmode=disable \
make rc-check
```

The restore target is destructive. The restore script refuses to run without
`WEBHOOKERY_RESTORE_CONFIRM=restore`.

## Backup And Restore Runbook

Back up PostgreSQL before upgrading, changing retention policies, rotating
master-key material, changing secret custody mode, or enabling object storage.

1. Stop API, worker, and scheduler processes for the restore target.
2. Create a PostgreSQL custom-format dump:

   ```bash
   WEBHOOKERY_DATABASE_URL=postgres://... scripts/backup_postgres.sh backups
   ```

   Expected result: a `backups/webhookery-<timestamp>.dump` path is printed.
   The script uses restrictive file permissions through `umask 077`.

3. Restore into a fresh disposable database:

   ```bash
   WEBHOOKERY_DATABASE_URL=postgres://... WEBHOOKERY_RESTORE_CONFIRM=restore scripts/restore_postgres.sh backups/webhookery-20260525T000000Z.dump
   ```

   Expected result: `pg_restore` exits zero.

4. Run migrations on the restored database:

   ```bash
   WEBHOOKERY_DATABASE_URL=postgres://... go run ./cmd/whcp migrate up
   ```

5. Start API and workers, then verify:

   ```bash
   curl -fsS http://localhost:8080/readyz
   go run ./cmd/whcp audit verify-chain --api-key "$WEBHOOKERY_API_KEY"
   go run ./cmd/whcp ops storage --api-key "$WEBHOOKERY_API_KEY"
   go run ./cmd/whcp ops queues --api-key "$WEBHOOKERY_API_KEY"
   ```

PostgreSQL dumps do not contain S3 object bodies. When S3-compatible raw
payload storage is enabled, restore object storage through the bucket provider
and verify that metadata still points to available objects.

Do not restore over live state until the drill succeeds. Preserve failed
restore databases for investigation when audit-chain, event, delivery, or
export evidence does not verify.

## Durable Capture Checks

Use these checks when providers receive non-2xx responses, operators suspect
loss, or storage health changes:

1. Check API readiness:

   ```bash
   curl -fsS http://localhost:8080/readyz
   ```

2. Check storage and queues:

   ```bash
   go run ./cmd/whcp ops storage --api-key "$WEBHOOKERY_API_KEY"
   go run ./cmd/whcp ops queues --api-key "$WEBHOOKERY_API_KEY"
   ```

3. Inspect a captured event:

   ```bash
   go run ./cmd/whcp events timeline --event-id evt_... --api-key "$WEBHOOKERY_API_KEY"
   ```

4. If raw payload access is required, use a scoped key and record the reason:

   ```bash
   go run ./cmd/whcp events raw-export --event-id evt_... --output payload.bin --api-key "$WEBHOOKERY_API_KEY"
   ```

Raw payload retrieval is an elevated action and emits audit evidence. Store
exported payloads with the same care as customer data, and delete local copies
when the investigation is complete.

Do not force a 2xx response while durable capture is unavailable. For S3 mode,
restore both object-write health and PostgreSQL commit health before accepting
new ingress as healthy.

## Audit Evidence Runbook

Audit events are chained per tenant with SHA-256. The chain records hashes,
previous hashes, sequence state, source, and tombstone metadata; it does not
duplicate raw payloads, credentials, or payload bodies.

Verify chain status:

```bash
go run ./cmd/whcp audit chain-head --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit verify-chain --api-key "$WEBHOOKERY_API_KEY"
```

Create an operator anchor only after verification succeeds:

```bash
go run ./cmd/whcp audit anchor --reason "daily anchor" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit anchors --api-key "$WEBHOOKERY_API_KEY"
```

Verify downloaded evidence bundles locally:

```bash
go run ./cmd/whcp audit verify-bundle --file evidence.tar.gz
```

If verification fails:

1. Stop retention, export, replay, and migration work that might modify
   evidence state.
2. Preserve the database and relevant object-storage state.
3. Compare the latest audit export, retention run records, and chain head.
4. Do not anchor a failing range.
5. Restore into a disposable database before attempting repair.

Audit retention may leave hash-only tombstones. Missing non-retained rows and
mismatched hashes are failures.

## Incident Triage

| Symptom | First checks | Required action |
|---------|--------------|-----------------|
| Provider receives non-2xx or no ack | `/readyz`, API logs, PostgreSQL availability, `WEBHOOKERY_RAW_STORAGE_MODE`, object-store health in S3 mode | Restore durable storage first. Do not force 2xx while capture is unavailable. |
| Invalid signatures or quarantine growth | Event timeline, quarantine state, source secret versions | Verify exact raw-body signing settings, timestamp windows, and secret rotation grace periods before replaying. |
| DLQ growth or receiver failures | `whcp ops queues`, alert firings, delivery attempts, endpoint circuit state | Fix receiver, SSRF, TLS, or signing errors, then release DLQ entries with a reason. |
| Replay backlog affects live traffic | Queue depth, replay job status, replay rate limits | Pause or rate-limit replay. Live delivery work should remain prioritized. |
| Audit-chain verification failure | `whcp audit verify-chain`, latest exports, retention run records | Stop evidence-mutating work, preserve state, investigate before anchoring. |
| SIEM or notification egress failures | Notification and SIEM delivery failure lists | Fix receiver availability or signature config; do not advance cursors manually. |
| Reconciliation gaps | Reconciliation job items | Distinguish captured, redelivery-requested, unrecoverable, and provider limitation evidence before claiming recovery. |
| Restore uncertainty | Disposable restore plus audit-chain and bundle verification | Do not restore over live state until the drill succeeds. |

## Recovery Notes

- Provider retries and provider APIs have provider-specific limits. Do not claim
  provider-side completeness unless current official provider docs and local
  reconciliation evidence prove it for the case.
- Replay creates new delivery work linked to existing evidence. It does not
  mutate original event history.
- Duplicate events remain visible. Dedupe may suppress processing, but it must
  not erase receipt evidence.
- Queue outage must not lose accepted events; durable outbox state remains in
  PostgreSQL.
- Object storage outage in S3 mode is an ingress durability problem, not only a
  delivery problem.

## Cryptography And Secret Handling

Inbound provider adapters use HMAC-SHA256 where provider semantics require it:
Stripe, GitHub, Shopify, Slack, and generic HMAC. Outbound delivery signing
uses the `Webhook-Signature` header with HMAC-SHA256 over:

```text
timestamp + "." + raw_delivery_body
```

Webhook/source secrets, endpoint signing secrets, provider credentials, OIDC
client secrets, SCIM tokens, producer credentials, and mTLS private keys are
stored through an envelope encryption interface. `WEBHOOKERY_SECRET_BOX_MODE`
selects local, Vault Transit, or AWS KMS custody. Switching custody modes does
not re-encrypt existing rows automatically.

Logs, errors, metrics, CLI output, UI surfaces, docs, support artifacts, and
release evidence must not include plaintext API keys, bearer tokens, webhook
secrets, source signatures, Vault tokens, AWS credentials, full KMS key IDs,
object-store secrets, private keys, raw payload bodies, provider headers, or
unnecessary PII.

Run:

```bash
go run ./cmd/whcp key-custody test
```

Expected result: the configured mode can encrypt and decrypt a marker without
printing plaintext, ciphertext, or full key IDs.
