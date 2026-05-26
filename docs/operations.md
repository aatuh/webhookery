# Webhookery Operations

This document describes implemented operational behavior, not future product
marketing.

## Deployment Profile

Use `docs/configuration.md` as the canonical environment variable and secret
handling reference. This runbook calls out only the variables that matter to a
specific operational procedure.

The MVP deployment profile is a Go API/worker binary backed by PostgreSQL.
Docker Compose starts PostgreSQL, runs migrations, starts the API, and starts a worker. PostgreSQL is the
source of truth for raw payload metadata, events, dedupe records, delivery
state, audit events, retention state, evidence export metadata, and durable
outbox work.

Raw payload body storage defaults to PostgreSQL `bytea`. Optional S3-compatible
storage is enabled with `WEBHOOKERY_RAW_STORAGE_MODE=s3` and the
`WEBHOOKERY_OBJECT_STORAGE_*` variables. In S3 mode, inbound success requires
both the object write and the PostgreSQL metadata transaction to succeed. The
database still stores the raw payload hash, size, storage backend, bucket, key,
write status, receipts, events, deliveries, and audit rows.

Kubernetes manifests live under `deploy/kubernetes`. They define separate API,
worker, scheduler, and migration-job workloads plus a service for the API. The
profile expects external PostgreSQL and optional external object storage; it
does not install ingress, TLS certificates, network policies, service monitors,
or PostgreSQL. Use `deploy/kubernetes/secret.example.yaml` only as a template,
then create the real `webhookery-secrets` Secret through the cluster's normal
secret-management workflow.

The Helm chart under `deploy/helm/webhookery` deploys the same API, worker,
scheduler, and optional migration-job shape. It also expects external
PostgreSQL and optional object storage. By default it references an existing
Kubernetes Secret for sensitive values; `secret.create=true` is intended for
operator-supplied values files, not committed secrets.

The Terraform module under `deploy/terraform/webhookery-helm` installs that
Helm chart into an existing Kubernetes cluster. It intentionally accepts only an
existing Secret name, not database URLs, master keys, object-store access keys,
or bootstrap key hashes, because Terraform state is not an appropriate secret
store.

The project makes no FIPS/NIST/CMVP certification claim.

## Production Doctor

Run the production doctor before promoting or upgrading a self-hosted
deployment:

```bash
WEBHOOKERY_ENVIRONMENT=production go run ./cmd/whcp doctor production
```

The command reads local environment/configuration only. It does not connect to
PostgreSQL, object storage, Vault, AWS KMS, or webhook receivers, and it does
not replace `make rc-check`, readiness probes, backup/restore drills, or
tenant-scoped ops APIs. Its output is deliberately redacted and must not print
database passwords, API keys, webhook secrets, OAuth tokens, Vault tokens, AWS
credentials, raw KMS key ids, object-store credentials, private keys, or raw
payload bodies.

Doctor severities are:

- `blocker`: unsafe or incomplete production posture. The command exits
  non-zero.
- `warning`: an operator must explicitly accept or remediate the risk. The
  command may exit zero when only warnings remain.
- `ok`: the checked setting has production-acceptable shape.

Local development should use `.env.example`, `WEBHOOKERY_ENVIRONMENT=development`,
and Docker Compose. The production doctor is not a local-development pass/fail
gate; use `make fast-check` and local smoke tests for development feedback.

A production-local deployment that uses local envelope encryption must provide
a non-placeholder database URL, API TLS certificate/key files, a generated
32-byte base64 `WEBHOOKERY_MASTER_KEY_BASE64`, and a non-placeholder bootstrap
key hash or no bootstrap key. Example shape:

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

Local secret-box mode can be acceptable for smaller self-hosted installations
with disciplined key custody, but the doctor reports it as a warning because
Vault Transit or AWS KMS gives stronger operational separation.

Vault Transit mode requires a TLS Vault address, token, and transit key name.
The token is consumed from the environment and is never printed:

```bash
WEBHOOKERY_ENVIRONMENT=production
WEBHOOKERY_SECRET_BOX_MODE=vault-transit
WEBHOOKERY_VAULT_ADDR=https://vault.internal
WEBHOOKERY_VAULT_TOKEN=<vault-token>
WEBHOOKERY_VAULT_TRANSIT_KEY=webhookery
go run ./cmd/whcp doctor production
```

AWS KMS mode requires region and key id. A custom endpoint is intended for
LocalStack-style testing; non-TLS endpoint overrides produce a warning:

```bash
WEBHOOKERY_ENVIRONMENT=production
WEBHOOKERY_SECRET_BOX_MODE=aws-kms
WEBHOOKERY_AWS_REGION=us-east-1
WEBHOOKERY_AWS_KMS_KEY_ID=<kms-key-id-or-arn>
go run ./cmd/whcp doctor production
```

S3-compatible raw payload storage is strict when enabled: inbound success
requires the object write plus PostgreSQL metadata commit. Production S3 mode
must define the endpoint, bucket, access key, secret key, and TLS posture:

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

## Production RC Checklist

The release-candidate target is a single-region self-hosted deployment with
PostgreSQL as the source of truth. It is production-respectable only when the
core product checks, failure drills, restore rehearsal, and operator preflight
are repeatable. It is not a certification, hosted SLA, or exactly-once claim.

Before promotion, complete this checklist:

- `go run ./cmd/whcp doctor production` exits with no `blocker` findings.
  Warnings require an explicit operator decision.
- `make finalize` passes on the release candidate commit.
- `WEBHOOKERY_TEST_DATABASE_URL=postgres://... make live-postgres-check` passes
  against a disposable PostgreSQL database. This is the canonical live
  PostgreSQL gate and uses only local/CI database resources.
- `make rc-check` passes without live third-party provider, AWS, Vault, Slack,
  PagerDuty, SIEM, or customer receiver calls.
- `WEBHOOKERY_TEST_DATABASE_URL=postgres://... make rc-check` passes against a
  disposable PostgreSQL database. This runs migrations, Postgres integration,
  and DB-backed RC E2E flows serially.
- `WEBHOOKERY_RC_RESTORE_DATABASE_URL=postgres://...` is set to a separate
  disposable restore database and the restore drill passes before upgrades that
  touch migrations, audit chain behavior, retention, exports, or storage.
- Object storage, if enabled, has its own backup/restore procedure; PostgreSQL
  dumps do not contain S3 object bodies.
- Bootstrap API key posture is reviewed: the bootstrap hash is removed,
  rotated, or restricted after a database-backed owner/security key exists.
- `/readyz`, `/v1/ops/storage`, `/v1/ops/config`, `/v1/ops/queues`,
  `/v1/ops/metrics`, alert firings, and audit-chain verification are checked
  after deployment.

Expected local RC command sequence:

```bash
docker compose up -d postgres
WEBHOOKERY_TEST_DATABASE_URL=postgres://webhookery:change-me@localhost:5432/webhookery?sslmode=disable make live-postgres-check
WEBHOOKERY_TEST_DATABASE_URL=postgres://webhookery:change-me@localhost:5432/webhookery?sslmode=disable make rc-check
```

A successful run ends with:

```text
rc-check: release-candidate acceptance checks passed
```

Restore drills require a separate disposable restore database URL. The source
and restore URLs must not point at the same database:

```bash
WEBHOOKERY_TEST_DATABASE_URL=postgres://webhookery:change-me@localhost:5432/webhookery?sslmode=disable \
WEBHOOKERY_RC_RESTORE_DATABASE_URL=postgres://webhookery_restore:change-me@localhost:5433/webhookery_restore?sslmode=disable \
make rc-check
```

Use whatever local PostgreSQL topology provides that second URL; the drill is
destructive for the restore target and the restore script refuses to run
without `WEBHOOKERY_RESTORE_CONFIRM=restore`.

## Upgrade And Restore Drill

For production upgrades, rehearse the restore path before changing live
storage, migrations, retention policies, audit-chain code, or key-custody mode.

1. Stop API, worker, and scheduler processes for the restore target.
2. Back up the source PostgreSQL database:

   ```bash
   WEBHOOKERY_DATABASE_URL=postgres://... scripts/backup_postgres.sh backups
   ```

   Expected result: a `backups/webhookery-<timestamp>.dump` path is printed.

3. Restore into a fresh disposable database:

   ```bash
   WEBHOOKERY_DATABASE_URL=postgres://... WEBHOOKERY_RESTORE_CONFIRM=restore scripts/restore_postgres.sh backups/webhookery-20260525T000000Z.dump
   ```

   Expected result: `pg_restore` exits zero.

4. Run migrations on the restored database:

   ```bash
   WEBHOOKERY_DATABASE_URL=postgres://... go run ./cmd/whcp migrate up
   ```

5. Verify restored evidence surfaces:

   ```bash
   go run ./cmd/whcp audit verify-chain --api-key "$WEBHOOKERY_API_KEY"
   go run ./cmd/whcp audit verify-bundle --file evidence.tar.gz
   ```

   Expected result: the chain verification is valid, and bundle verification
   reports valid file hashes and audit-chain continuity.

6. Start API and workers, then check:

   ```bash
   curl -fsS http://localhost:8080/readyz
   go run ./cmd/whcp ops storage --api-key "$WEBHOOKERY_API_KEY"
   go run ./cmd/whcp ops queues --api-key "$WEBHOOKERY_API_KEY"
   ```

The automated RC restore drill in `internal/e2e` creates evidence, backs up
PostgreSQL, restores to a fresh DB, migrates, and verifies event, export, and
audit-chain readability. It intentionally treats object bodies as outside the
PostgreSQL dump scope.

## Incident Triage

Use the control-plane evidence before assuming provider loss or downstream
success. Inbound 2xx only means durable capture.

| Symptom | First checks | Expected operator action |
| --- | --- | --- |
| Provider receives non-2xx or no ack | `/readyz`, API logs, PostgreSQL availability, `WEBHOOKERY_RAW_STORAGE_MODE`, object-store health in S3 mode | Restore durable storage first; do not force 2xx while capture is unavailable. |
| Invalid signatures or quarantine growth | `go run ./cmd/whcp events timeline --event-id evt_...`, quarantine list, source secret versions | Verify exact raw-body signing settings, timestamp windows, and secret rotation grace periods before replaying. |
| DLQ growth or receiver failures | `go run ./cmd/whcp ops queues`, `go run ./cmd/whcp alerts firings`, delivery attempts, endpoint circuit state | Fix receiver/SSRF/TLS errors, then release DLQ entries with a reason. |
| Replay backlog affects live traffic | `go run ./cmd/whcp ops queues`, replay job status and rate limits | Pause or rate-limit replay; live deliveries should remain prioritized. |
| Audit chain verification failure | `go run ./cmd/whcp audit verify-chain`, latest audit exports, retention run records | Stop retention/export changes, preserve database state, and investigate mismatched or missing entries before anchoring. |
| SIEM or notification egress failures | `go run ./cmd/whcp notification-deliveries list --state failed`, `go run ./cmd/whcp siem-deliveries list --state failed` | Fix receiver availability/signature config and retry; cursors must not be advanced manually. |
| Reconciliation gaps | `go run ./cmd/whcp reconciliation-jobs items --job-id rec_...` | Distinguish `captured`, `redelivery_requested`, `unrecoverable`, and provider limitation evidence before claiming recovery. |
| Restore uncertainty | Restore into a disposable DB and run audit-chain plus bundle verification | Do not restore over live state until the drill succeeds and object-storage backup scope is understood. |

## Explicit Non-Goals

The implemented core product does not claim:

- exactly-once delivery or provider-side event completeness;
- multi-region active-active coordination;
- external timestamping, HSM/PKCS#11 custody, or compliance-certified evidence
  packs;
- live Stripe/GitHub/Shopify/Slack/AWS/Vault calls in release acceptance;
- Kafka, NATS, Redis, or object storage as the authority for accepted event
  evidence;
- arbitrary code plugins, visual workflow builders, marketplace distribution,
  GraphQL, SAML assertion processing, or vendor-specific alert integrations.

## Backup And Restore

PostgreSQL is the authoritative metadata store for accepted events, receipts,
deliveries, audit rows, reconciliation evidence, retention state, and outbox
work. Back up PostgreSQL before upgrading, changing retention policies,
rotating master-key material, or enabling object storage.

Create a custom-format PostgreSQL dump with:

```bash
WEBHOOKERY_DATABASE_URL=postgres://... scripts/backup_postgres.sh backups
```

The script writes a timestamped `webhookery-*.dump` file with owner/group
permissions restricted by `umask 077`. It requires `pg_dump` on the operator
machine and does not include S3-compatible object bodies; object storage must be
backed up through the bucket provider.

Restore into an already provisioned PostgreSQL database with:

```bash
WEBHOOKERY_DATABASE_URL=postgres://... WEBHOOKERY_RESTORE_CONFIRM=restore scripts/restore_postgres.sh backups/webhookery-20260525T000000Z.dump
```

The restore script requires an explicit confirmation environment variable and
uses `pg_restore --clean --if-exists`. Stop API and worker processes before
restoring so no process writes new evidence into a partially restored database.
After restore, run `whcp migrate up`, start the API and workers, then check
`/readyz`, `/v1/ops/metrics`, and a recent event timeline.

## Cryptography And Secrets

Inbound provider adapters use HMAC-SHA256 where provider semantics require it:
Stripe, GitHub, Shopify, Slack, and generic HMAC. Outbound delivery signing
uses the `Webhook-Signature` header with HMAC-SHA256 over:

```text
timestamp + "." + raw_delivery_body
```

Receivers should verify the exact raw delivery body with
`pkg/verifier.VerifyWebhookerySignature`, a five-minute timestamp window unless
their own policy requires a smaller window, and their endpoint's active or
grace-period signing secret. `Webhook-Signature-Key-Id` and
`Webhook-Signature-Key-Version` are metadata for selecting and auditing the
receiver-side secret version; they are not a substitute for HMAC verification.

Webhook/source secrets and endpoint signing secrets are stored through an
envelope encryption interface. `WEBHOOKERY_SECRET_BOX_MODE=local` is the
default and requires `WEBHOOKERY_MASTER_KEY_BASE64` to be a base64-encoded
32-byte key at runtime. `WEBHOOKERY_SECRET_BOX_MODE=vault-transit` uses a
Vault Transit-compatible HTTP API configured with `WEBHOOKERY_VAULT_ADDR`,
`WEBHOOKERY_VAULT_TOKEN`, and `WEBHOOKERY_VAULT_TRANSIT_KEY`; Vault encrypts
and decrypts secret material while PostgreSQL stores only wrapped
`vault-transit:` ciphertext.

`WEBHOOKERY_SECRET_BOX_MODE=aws-kms` uses AWS KMS envelope encryption with
`WEBHOOKERY_AWS_REGION`, `WEBHOOKERY_AWS_KMS_KEY_ID`, and optional
`WEBHOOKERY_AWS_KMS_ENDPOINT` for LocalStack-style tests. Webhookery calls
AWS KMS `GenerateDataKey`, encrypts the secret locally with AES-GCM, stores the
encrypted data key beside the ciphertext, and calls `Decrypt` only to unwrap
that data key later. This follows the AWS KMS documented envelope pattern of
using `Plaintext` data keys outside KMS, storing `CiphertextBlob`, and erasing
plaintext data keys after use:
https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html
and https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html.
The adapter is built with AWS SDK for Go v2:
https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/getting-started.html.
Switching modes does not re-encrypt existing rows automatically, so plan a
controlled migration if moving live tenants between local, Vault-backed, and
AWS KMS-backed envelopes. `whcp key-custody test` performs a local
encrypt/decrypt smoke test for the configured mode without printing plaintext,
ciphertext, or full key ids. Example env files contain placeholders only.
Logs, errors, metrics, and UI surfaces must not print raw API keys, webhook
secrets, Vault tokens, AWS credentials, KMS key ids in full, signatures, bearer
tokens, or raw payloads by default.

Source verification secrets and endpoint signing secrets are versioned.
Rotation creates a new active version and moves the prior active version to
`previous` with a bounded grace period. Provider verification tries active and
non-expired previous source secrets against the exact raw request bytes.
Outbound deliveries sign with the current active endpoint signing secret and
include `Webhook-Signature-Key-Id` plus `Webhook-Signature-Key-Version` headers
so receivers can audit which key version signed a request. Plaintext secret
values are not returned by API, CLI, or UI responses.

Source reads, updates, and deletes are tenant-scoped. `DELETE /v1/sources/{id}`
and `whcp sources delete` disable the source instead of deleting historical
events, receipts, raw payload metadata, or audit evidence. Disabled sources are
rejected before capture and routing; re-enable by patching the source state
back to `active` with a reason.

Endpoint reads, updates, and deletes are tenant-scoped. `PATCH
/v1/endpoints/{id}` and `whcp endpoints update` can change endpoint metadata,
state, URL, and retry policy references with an operator reason. URL changes
rerun the same SSRF policy used at creation before metadata is committed.
`DELETE /v1/endpoints/{id}` and `whcp endpoints delete` disable future delivery
claims without deleting historical deliveries, attempts, payload snapshots, or
audit evidence. Endpoint signing secrets and mTLS key material are managed
through their dedicated rotation/create paths and are never returned by these
metadata APIs.

Subscription reads, updates, and deletes are tenant-scoped. Updating a
subscription can change its endpoint, event types, payload format,
transformation reference, or state, and writes a new immutable subscription
version plus audit event. Endpoint references are checked against active
endpoints in the same tenant before subscription creation or endpoint changes.
`DELETE /v1/subscriptions/{id}` and `whcp subscriptions delete` disable future
fanout without deleting historical delivery or config-version evidence.

Route reads, updates, and deletes are tenant-scoped. Route create/update checks
source and endpoint references against active resources in the same tenant,
resolves active transformation versions when configured, and writes a new
immutable route version for each mutation. `DELETE /v1/routes/{id}` and `whcp
routes delete` move the route to `inactive`; historical route decisions,
delivery rows, replay receipts, and config versions are retained.

Retry policy reads, updates, and deletes are tenant-scoped under the routes
permission family. `PATCH /v1/retry-policies/{id}` and `whcp retry-policies
update` create a new retry policy version row from the referenced policy
instead of rewriting it in place. `DELETE /v1/retry-policies/{id}` disables
future use of the referenced policy row while retaining delivery and audit
evidence that already points at it.

Event type and event schema reads are tenant-scoped under the schemas
permission family. Operators can list event types, list schemas for an event
type, and fetch a specific schema version through both API and CLI before
running validation or compatibility checks. Event type lifecycle mutations
require `schemas:write` and an operator reason; event type names are immutable,
and delete moves the event type to `disabled` without deleting historical
schema, config-version, delivery, or audit evidence. Event schema bodies and
versions are immutable after creation. Schema lifecycle updates can move a
schema through `active`, `deprecated`, and `retired`; delete moves the schema
to `retired`. Schema state changes are tenant-scoped, audited, and recorded as
new config versions so later validation and replay evidence can identify which
schema state was in force.

Endpoints may also be created with a PEM client certificate and private key for
outbound mTLS. The API accepts `mtls_client_cert_pem` and
`mtls_client_key_pem` together, validates that they form a client certificate
pair, stores both through envelope encryption, and returns only
`mtls_enabled` plus certificate subject metadata. Delivery workers decrypt the
material at claim time and fail closed with `client_certificate_error` if the
stored pair is invalid. Redirects remain disabled.

## Authentication And Authorization

Normal operation uses database-backed API keys. API key rows store only
`sha256:` token hashes, key prefixes, last four characters, scopes, state, and
membership linkage. Users and memberships are tenant-scoped, and authorization
requires both the membership role and the key scope. The bootstrap API key hash
exists only to create or recover database-backed keys; remove or rotate it for
production-style operation.

## Inbound Acknowledgement

Inbound provider endpoints may return success only after raw body bytes,
headers, request metadata, verification result, event metadata, dedupe result,
and durable outbox work are committed. A downstream delivery success is never
implied by inbound 2xx. The API rejects ingress requests above the 2 MiB body
limit with HTTP 413 and requests with more than 128 header pairs, more than
64 KiB of header name/value bytes, or any single header value above 8 KiB with
HTTP 431 before source lookup or capture work starts.

Provider-specific behavior checked on May 25, 2026:

- Slack `url_verification` requests must be authenticated and answered with the
  received `challenge` value: https://docs.slack.dev/reference/events/url_verification
- CloudEvents HTTP supports binary header attributes and structured JSON
  envelopes with `application/cloudevents+json`:
  https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/bindings/http-protocol-binding.md

The generic JWT/JWS ingress adapter is intentionally narrow. It accepts compact
JWTs from `Authorization: Bearer ...` or `Webhook-JWT`, supports only HS256
with the source verification secret, rejects `alg=none` and other algorithms,
requires `exp`, honors `nbf` and future `iat`, and requires `body_sha256` to
match the exact raw request body captured by Webhookery.

## Delivery Worker

The worker claims durable outbox rows with database leases, evaluates active
subscriptions and routes, creates delivery jobs, then claims scheduled
deliveries. It also runs bounded operational phases for retention, metrics,
alerts, audit-chain backfill, notification delivery, and SIEM delivery.
Delivery attempts are signed, recorded, retried on retryable failures, and
moved to the dead-letter table after terminal failure.
Worker leases are refreshed in PostgreSQL when outbox or delivery work is
claimed. Outbox and delivery claim batches use a tenant-fair ordering in
PostgreSQL: live route work is selected before replay and reconciliation work,
live deliveries are selected before replay deliveries, and each priority class
round-robins by tenant before taking additional work from the same tenant.

Routes are snapshotted in `route_versions`, subscriptions are snapshotted in
`subscription_versions`, and decisions attach `route_version_id` or
`subscription_version_id` to delivery evidence. Retry policies are
tenant-scoped, versioned resources; endpoints and routes can reference a
policy, and deliveries retain the selected `retry_policy_id`. If no policy is
selected, the implemented default remains 12 attempts over a 72-hour maximum
with full-jitter exponential backoff between 10 seconds and 6 hours. Each
delivery stores a `retry_seed`, and each retryable delivery attempt records the
deterministic jitter delay and `next_retry_at` chosen from that seed.

Replay jobs create new delivery work linked to the original event or delivery.
Replay never mutates the original event evidence.

Replay jobs can be created with `config_mode=current` or
`config_mode=original` and an optional `rate_limit_per_minute`. Current-mode
event replay evaluates current active subscriptions and routes. Original-mode
event replay clones the event's recorded non-replay delivery decisions and
preserves their route, subscription, and retry policy evidence. Replay-created
deliveries are marked with `replay_job_id`, scheduled according to the replay
rate limit, and ordered behind live due deliveries when workers claim delivery
work. Replay jobs can be paused, resumed, or canceled through the API/CLI.
Paused jobs keep durable outbox work uncompleted until they are resumed.
Replay jobs can also be created with `require_approval=true`; those jobs stay
in `pending_approval`, do not enqueue replay delivery work, and require
`POST /v1/replay-jobs/{replay_job_id}:approve` or
`whcp replay-jobs approve` with replay write permission and a reason before
workers can process them. The approval records approver metadata and a chained
audit event. This is a single approval gate, not a two-person approval workflow.
Dead-letter entries can be released one at a time or in bounded bulk batches.

Authenticated operators with `ops:read` can inspect runtime worker leases and
tenant-scoped queue depth through `GET /v1/ops/workers`,
`GET /v1/ops/workers/{worker_id}`, `GET /v1/ops/queues`, `GET
/v1/ops/storage`, `GET /v1/ops/config`, and `whcp ops
workers|worker|queues|rollups|storage|config`. Worker status exposes only lease metadata (`worker_id`,
active/expired state, last seen time, and expiry). Queue stats are scoped to the
actor tenant and report durable outbox kinds plus the delivery queue with
pending, in-progress, terminal/completed, due-now, oldest pending age, and next
scheduled timestamps. Storage status reports tenant-scoped payload/evidence
counts, storage backends, and stored-byte totals. Runtime config reports only
safe metadata such as environment, UI enabled state, raw storage mode, secret
box mode, and request limits. These APIs do not expose payload bodies, endpoint
URLs, database URLs, object-store credentials, API keys, webhook secrets, master
keys, Vault tokens, or tenant labels on public metrics.

The scheduler also writes derived one-minute operational rollups to
`metrics_rollups`. Operators can query them through
`GET /v1/ops/metrics/rollups` or `whcp ops rollups`, optionally filtering by
`metric_name`. Rollups cover queue depth and age, delivery/replay/reconciliation
states, open DLQ/quarantine counts, endpoint failure-rate summaries, and audit
chain status. They are dashboard and alert inputs only; the underlying event,
delivery, audit, retention, and reconciliation rows remain authoritative.

Alert rules are stored in `alert_rules` and evaluated by the scheduler against
recent rollups. Supported rule types are open DLQ, open quarantine, endpoint
failure rate, open endpoint circuit, oldest outbox age, expired worker leases,
audit-chain verification failures, and reconciliation failed/unrecoverable
items. A breached rule opens one `alert_firings` row until the condition
resolves; acknowledged firings stay unique per rule and then resolve when the
metric clears. Reads require `ops:read`; create, update, disable, and
acknowledge require `ops:write` plus an operator reason for disabling and
acknowledging. Alert APIs and UI views do not expose payload bodies, endpoint
secrets, provider credentials, or tenant labels on public `/metrics`.

## Provider Reconciliation

Provider reconciliation jobs are implemented for cases where a provider API can
show provider-side event or delivery evidence that may not exist locally.
Provider API credentials are stored in `provider_connections` through the same
envelope encryption interface used for webhook and endpoint secrets. API and
CLI responses expose only `credential_type`, a redacted `credential_hint`,
provider name, state, timestamps, and provider-specific configuration metadata.

Create and verify connections with `/v1/provider-connections` or
`whcp provider-connections`. Create reconciliation jobs with
`/v1/reconciliation-jobs` or `whcp reconciliation-jobs`. Job creation and
cancelation require replay/recovery write permission and a reason. Reads require
replay read permission. Jobs and items are tenant-scoped.

Implemented provider behavior checked on May 25, 2026:

- Stripe event reconciliation uses the Events API. Stripe documents event
  list/retrieve access for events going back up to 30 days:
  https://docs.stripe.com/api/events/list and
  https://docs.stripe.com/api/events
- GitHub repository webhook reconciliation uses repository webhook deliveries
  and redelivery attempts:
  https://docs.github.com/en/rest/repos/webhooks and
  https://docs.github.com/en/webhooks/testing-and-troubleshooting-webhooks/viewing-webhook-deliveries
- Shopify is represented as capability/gap evidence only. Shopify recommends
  reconciliation jobs by polling relevant resources with `updated_at` filters,
  but generic missed-webhook payload recovery is topic-specific:
  https://shopify.dev/docs/apps/build/webhooks
- Slack is represented as capability/gap evidence only. Slack Events API
  delivery is best-effort with bounded retries and does not provide a generic
  missed-event recovery feed in this implementation:
  https://docs.slack.dev/apis/events-api/

Reconciliation item outcomes are `matched`, `missing`, `captured`,
`redelivery_requested`, `unrecoverable`, and `failed`. Missing Stripe events
and GitHub delivery payloads are captured only when `capture_missing=true` and
the provider API returned a recoverable payload body. Recovered events use
`verification_reason=provider_api_reconciliation`; they are not marked as
signed webhook deliveries. They route only when `route_recovered=true`, and the
durable recovered event capture commits before any delivery work is created.

Provider API call evidence is stored in `provider_api_evidence` with request
method, redacted request URL, response status, response hash, size, storage
status, and optional response body. Provider API response bodies are sensitive
payload data and require `events:raw` through export body inclusion controls.
Provider tokens are not written to audit events, job items, logs, UI tables, or
export metadata.

Endpoint health is derived from recorded delivery attempts. Repeated failures
open a lightweight endpoint circuit and delay further delivery attempts for a
short cooling period; delivery-time SSRF validation still runs for every
attempt.

Endpoint test requests create a signed synthetic `webhookery.endpoint.test`
delivery and preserve the test event, dedupe row, delivery row, and audit
record.

## Reproducible Configuration

`config_versions` records immutable JSON snapshots and hashes for sources,
endpoints, subscriptions, routes, retry policies, schemas, transformation
versions, and secret-version metadata when those resources are created or
rotated through the implemented code paths. `route_versions` and
`subscription_versions` store the fields used for matching and delivery
creation, including optional `transformation_id` and
`transformation_version_id`. Retry schedule evidence is reproducible from the
stored delivery `retry_seed`, retry policy, attempt number, and recorded
attempt timestamps.

## Normalization And Transformations

Verified inbound events are normalized into `normalized_envelopes` after raw
body capture and provider verification. Raw payloads remain authoritative:
normalization does not replace raw evidence and unverified requests do not
produce routed normalized payloads by default. Normalized event metadata is
available through `GET /v1/events/{event_id}/normalized` with `events:read`;
including normalized data requires `events:raw` and emits an audit event.

Built-in adapter versions are recorded in `provider_adapters` and
`adapter_versions`. Each normalized envelope stores the selected
`adapter_version_id`, provider identifiers, stable hashes for the envelope,
data, and metadata, and retention state. Existing verified events are backfilled
as `legacy_metadata_only` envelopes so historical event metadata remains visible
without inventing payload data.

Tenant custom adapter governance is available through `/v1/adapters` and
`whcp adapters`. Custom adapter rows are tenant-scoped and have immutable
versions that move through `draft`, `automated_tests`, `security_review`,
`staging_approved`, `active`, `deprecated`, and `retired`. Active declarative
HMAC-SHA256 adapters can verify inbound requests using exact raw bytes,
configured signature/timestamp headers, and replay windows; normalization uses
the stored declarative metadata and data selectors. Declarative definitions and
plugin package metadata are stored with SHA-256 hashes, provenance fields, and
test-vector hashes; definitions that contain secret-shaped fields are rejected.
Code-plugin package metadata can be registered for review, but Webhookery does
not execute custom plugin code in this slice. Adapter state transitions require
`security:write`, a reason, and write audit events.

Transformations are tenant-scoped configuration resources managed through
`/v1/transformations` and `whcp transformations`. A transformation version is
immutable and declarative. Implemented operations are JSON Pointer based only:
`set`, `copy`, `drop`, and `redact`. Transformations cannot change provider
evidence, verification fields, tenant/source identifiers, hashes, or audit
metadata. There is no arbitrary scripting, network access, plugin marketplace,
or custom runtime in this slice.

Routes and subscriptions may reference an active transformation. New delivery
work snapshots the exact transformed outbound bytes into `delivery_payloads`
before the delivery becomes claimable. Workers deliver and sign those stored
bytes instead of rebuilding payloads at claim time. Legacy deliveries without a
payload snapshot retain the previous fallback behavior.

Replay with `config_mode=original` clones the original delivery payload and
evidence identifiers when available. Replay with `config_mode=current`
regenerates delivery payloads from the current active route, subscription, and
transformation configuration.

Event schemas support a conservative JSON Schema subset for validation:
`type`, `required`, object `properties`, and array `items`. Compatibility
checks reject newly required fields, removed existing properties, and changed
property types. Unsupported advanced JSON Schema features are intentionally not
treated as compatibility proof.

## Raw Payload Access

Raw payload retrieval is an elevated action and emits an audit event. Operators
should keep raw retention shorter than metadata retention when payloads may
contain personal data.

If a retention policy deletes a raw body or object, the body read returns HTTP
410. The event, receipt, delivery, hash, storage metadata, and audit evidence
remain queryable.

## Retention Policies

Retention policies are tenant-scoped and managed through
`/v1/admin/retention-policies` or `whcp retention`. Implemented policy resource
types are:

- `raw_payload`: deletes PostgreSQL raw bodies or S3 objects after the policy
  age, optionally scoped to a source.
- `normalized_envelope_data`: deletes normalized envelope and data JSON while
  preserving envelope ids, provider metadata, hashes, event records, receipts,
  deliveries, and audit rows.
- `delivery_payload`: deletes stored outbound delivery payload bodies while
  preserving delivery ids, hashes, transformation evidence, attempts, and audit
  rows.
- `provider_api_evidence`: deletes stored provider API response bodies while
  preserving reconciliation jobs, gap items, request metadata, hashes, sizes,
  and audit rows.
- `audit_event`: deletes audit rows after the policy age while preserving
  `audit_chain_entries` as retained tombstones with hashes and sequence
  metadata.

The worker applies active policies in bounded batches and records
`retention_runs` plus `retention_run_items`. Policy changes and completed runs
write chained audit events. Policies can be placed on `legal_hold` with a
`hold_reason`; held policies remain visible and auditable but are skipped by
the retention worker until the hold is cleared.

## Audit Evidence Exports

`POST /v1/audit-events:export` creates a tenant-scoped `tar.gz` bundle
synchronously for this implementation slice. The bundle contains
`manifest.json`, `audit_events.jsonl`, `payload_evidence.jsonl`,
`audit_chain_proof.jsonl`, and optional `timelines.jsonl` and
`raw_payloads.jsonl`. Reconciliation evidence is included in
`reconciliation_evidence.jsonl`. Payload evidence includes normalized envelope
metadata, delivery payload metadata, provider API evidence metadata, and hashes.
Raw payload bodies are included only with
`include_raw_payloads=true` when the actor has both `audit:read` and
`events:raw`. Normalized, delivery payload, and provider API response bodies are
included only with `include_payload_bodies=true` and the same permissions.
Actors without `events:raw` cannot see or download raw- or payload-body
inclusive exports.

Each export row stores the bundle SHA-256, manifest SHA-256, file hashes,
storage backend, size, creator, completion timestamp, and audit-chain range
metadata. Export creation verifies the chain proof before marking an export
ready. `whcp audit verify-bundle --file evidence.tar.gz` checks tar entry
safety, manifest/file hashes, and audit-chain continuity in the downloaded
bundle.

## Audit Chain Verification And Anchors

Every audit event written through implemented API, CLI, worker, retention,
replay, export, reconciliation, and configuration paths is appended to a
tenant-scoped SHA-256 chain in the same transaction as the audit row. Chain
entries store the audit event hash, previous chain hash, current chain hash,
canonicalization version, source, state, and tombstone metadata. They do not
duplicate raw payloads, credentials, or payload bodies.

Existing unchained audit rows are backfilled explicitly, not during API or
worker store startup. The scheduler worker runs a bounded leased backfill phase,
and operators can run the same bounded path after migrations or during
maintenance:

```bash
go run ./cmd/whcp migrate --limit 100 --worker-id audit-backfill-operator audit-chain-backfill
```

Backfill processes deterministic per-tenant batches ordered by `occurred_at, id`
and reports whether more work remains. Backfilled chains prove continuity from
the current database state; they cannot prove history from before the chain
feature existed.

Operators can inspect and verify the chain through:

```bash
go run ./cmd/whcp audit chain-head --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit verify-chain --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit anchor --reason "daily anchor" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit anchors --api-key "$WEBHOOKERY_API_KEY"
```

`GET /v1/audit-chain/head`, `POST /v1/audit-chain:verify`,
`GET /v1/audit-chain/anchors`, and
`GET /v1/audit-chain/anchors/{anchor_id}` require `audit:read`.
`POST /v1/audit-chain:anchor` requires `security:write` and a reason.
Anchor creation verifies the requested range first, then stores a manifest hash,
range, chain hash, actor, and reason. When S3-compatible object storage is
configured, the anchor manifest is also written to the object store; otherwise
the local PostgreSQL anchor row is the durable anchor record.

Audit-event retention marks chain entries as retained tombstones before
deleting audit rows. Verification treats retained entries as hash-only evidence,
while missing non-retained audit rows or mismatched hashes are reported as
failures. This implementation does not integrate external timestamping
services, KMS/HSM signing, or compliance-certified evidence packs. Generic
signed HTTPS alert notification delivery and SIEM streaming are handled by the
operational signal egress worker described below.

## Metrics And Readiness

`/readyz` checks PostgreSQL. `/metrics` exposes aggregate Prometheus text
metrics without tenant labels. `/v1/ops/metrics` exposes tenant-scoped JSON
metrics for authenticated operators, including pending outbox count, oldest
outbox age, delivery states, replay states, open DLQ count, quarantine count,
open endpoint circuits, reconciliation job states, reconciliation item outcomes,
unchained audit-event count, audit-chain verification failure count, and newest
anchor age. `/v1/ops/storage` and `/v1/ops/config` provide redacted operational
status for storage and runtime configuration. `/v1/ops/metrics/rollups` exposes
tenant-scoped derived rollup buckets for authenticated operators. `/v1/alerts`
and `/v1/alert-firings` expose alert rule and firing state for authenticated
operators.

## Operational Signal Egress

Alert notification channels are generic HTTPS webhook receivers managed through
`/v1/notification-channels` and `whcp notification-channels`. Creation and
updates require `ops:write`; reads require `ops:read`. Channel signing secrets
are accepted only on create/update, encrypted at rest, and returned only as
non-sensitive metadata. Channel URLs use the same SSRF protections as customer
webhook endpoints: HTTPS, no embedded credentials, no redirects during sender
delivery, and delivery-time DNS/IP revalidation.

Alert rules may include `channel_ids`. When a firing is opened, acknowledged,
or resolved, Webhookery stores one durable notification delivery per configured
active channel and transition. Notification payloads contain alert metadata
only: tenant id, firing id, alert rule id, transition, state, observed value,
threshold, reason, and timestamp. They do not include raw webhook payload
bodies, provider headers, endpoint credentials, or channel secrets.

Notification deliveries are inspected through `/v1/notification-deliveries`;
attempts and manual retry controls are available through
`/v1/notification-deliveries/{delivery_id}/attempts`,
`/v1/notification-deliveries/{delivery_id}:retry`, and the matching
`whcp notification-deliveries` commands. The sender signs exact bytes as:

```text
Webhookery-Signal-Timestamp: <unix seconds>
Webhookery-Signal-Signature: t=<timestamp>,v1=<hmac_sha256_hex(timestamp + "." + body)>
```

Failed notification sends retry from PostgreSQL state and eventually become
terminal `failed` deliveries. Public `/metrics` remains aggregate-only and does
not expose tenant labels.

SIEM sinks are generic signed HTTPS receivers managed through `/v1/siem-sinks`
and `whcp siem-sinks`. Sink reads require `audit:read`; create, update,
disable, test, and delivery retry require `security:write`. Sink secrets are
encrypted at rest and returned only as non-sensitive metadata.

The SIEM scheduler builds bounded JSONL batches from `audit_chain_entries`
joined with non-sensitive `audit_events` metadata when rows are still retained.
Each line includes sequence, audit event id, event hash, previous hash, chain
hash, canonicalization version, chain entry state/source, actor id, action,
resource, resource id, reason, and timestamp. Raw payload bodies, provider
headers, API keys, bearer tokens, and egress secrets are not included.

Each sink stores a `cursor_sequence`. The worker may create a scheduled
delivery for entries after that cursor, but it advances the cursor only after
the signed HTTPS delivery succeeds. Failed deliveries retry from PostgreSQL
state and leave the cursor unchanged, making the stream resumable without
skipping audit-chain entries.

## Enterprise Identity And Access

Management API and UI access can use API keys or OIDC-backed sessions. API keys
remain the bootstrap and break-glass path. OIDC identity providers are
tenant-scoped resources managed through `/v1/identity-providers` and
`whcp identity-providers`; reads require `security:read`, and create, update,
test, or disable require `security:write`. Only Authorization Code + PKCE is
implemented. Client secrets are encrypted at rest and never returned by API,
CLI, or UI responses.

The OIDC login flow starts at `/v1/auth/oidc/login?tenant_id=...&provider_id=...`
and completes at `/v1/auth/oidc/callback`. The callback validates state, nonce,
issuer, audience/client id, expiry, and the signed ID token before creating a
hashed `webhookery_session` cookie. Session cookies are HttpOnly, SameSite=Lax,
and marked Secure. Logout revokes the server-side session hash.
Disabling an identity provider revokes active sessions created through that
provider. Security operators can list and revoke tenant sessions through
`/v1/auth/sessions`; session token hashes are never returned. SAML assertion
processing is not implemented in this slice.

OIDC session IP metadata defaults to the direct `RemoteAddr` peer. If the API
is behind a trusted reverse proxy, set `WEBHOOKERY_TRUSTED_PROXY_CIDRS` to a
comma-separated CIDR allowlist for the immediate proxy peers; only then is the
first `X-Forwarded-For` address used for session metadata. Invalid or untrusted
forwarded values fall back to `RemoteAddr`.

SCIM provisioning is available at `/v1/scim/v2/Users` and
`/v1/scim/v2/Groups`. SCIM bearer tokens are created through
`/v1/scim-tokens` or `whcp scim-tokens create`, returned exactly once, and
stored only as SHA-256 hashes with prefix/last4 metadata. SCIM delete requests
deactivate users or groups instead of hard-deleting them. User deactivation
disables memberships and active sessions while preserving historical users,
memberships, audit events, and actor references.

Resource-aware role bindings and access policy rules are available through
`/v1/role-bindings`, `/v1/access-policies`, `whcp role-bindings`, and
`whcp access-policies`. Existing fixed roles and scoped API keys remain the
compatibility baseline. Role bindings can scope roles by principal, resource
family, resource id, and environment. Access policy rules can explicitly allow
or deny actions for resource families/environments; deny rules take precedence
in explain output. `POST /v1/authz:explain` and `whcp authz explain` return a
redacted policy decision containing matched role, role binding, policy rule,
and reason without exposing sessions, provider tokens, secrets, or payload
bodies.

Emergency recovery remains API-key based: keep a tightly controlled owner or
security-capable bootstrap/recovery key, rotate it after use, and audit every
identity or access-control change. Production operators should rotate OIDC
client secrets and SCIM tokens through the control API rather than editing
database rows.

## Enterprise Producer Trust

Product-event ingestion at `POST /v1/events` accepts three producer trust
mechanisms: API keys with `events:write`, OAuth client-credentials bearer
tokens, and verified producer mTLS identities. Producer credentials can be
source-bound; when `source_id` is set on the credential, the submitted event
body must contain the same `source_id` or ingestion is denied before the event
service is called.

Producer OAuth clients are tenant-scoped resources managed through
`/v1/producer-clients` and `whcp producer-clients`. Reads require
`security:read`; create, update, disable, and secret rotation require
`security:write`. Client secrets are generated once, returned only in the
create/rotate response, and stored as SHA-256 hashes. Access tokens are opaque
bearer values, stored hashed, have no refresh tokens, default to a 15-minute
TTL, and may not exceed one hour. The public token endpoint is
`POST /v1/oauth/token` with `application/x-www-form-urlencoded`
`grant_type=client_credentials` and HTTP Basic client authentication only.
This matches the OAuth 2.0 client credentials grant shape in RFC 6749 section
4.4: https://www.rfc-editor.org/rfc/rfc6749#section-4.4.

Producer mTLS identities are managed through `/v1/producer-mtls-identities`
and `whcp producer-mtls-identities`. They store public certificate metadata
only: SHA-256 fingerprint, subject/SAN metadata, validity timestamps, state,
and optional source binding. Private keys are never submitted or persisted.
To require app-side certificate verification, configure
`WEBHOOKERY_TLS_CERT_FILE`, `WEBHOOKERY_TLS_KEY_FILE`, and
`WEBHOOKERY_PRODUCER_MTLS_CLIENT_CA_FILE`. The server verifies peer
certificates against that CA before matching the fingerprint. This slice does
not trust proxy-supplied mTLS or authentication identity headers; deployments
that terminate producer mTLS before the API process must use API-key or OAuth
producer credentials.

## SSRF Protection

Customer endpoint URLs are treated as hostile input. Production endpoint
delivery requires HTTPS by default, rejects embedded credentials and private or
reserved IP destinations, re-resolves hostnames at delivery time, and does not
follow redirects unless an explicit audited policy allows it.
