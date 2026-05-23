# Webhookery Operations

This document describes implemented operational behavior, not future product
marketing.

## Deployment Profile

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

The project makes no FIPS/NIST/CMVP certification claim.

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
envelope encryption interface. Example env files contain placeholders only.
Logs, errors, metrics, and UI surfaces must not print raw API keys, webhook
secrets, signatures, bearer tokens, or raw payloads by default.

Source verification secrets and endpoint signing secrets are versioned.
Rotation creates a new active version and moves the prior active version to
`previous` with a bounded grace period. Provider verification tries active and
non-expired previous source secrets against the exact raw request bytes.
Outbound deliveries sign with the current active endpoint signing secret and
include `Webhook-Signature-Key-Id` plus `Webhook-Signature-Key-Version` headers
so receivers can audit which key version signed a request. Plaintext secret
values are not returned by API, CLI, or UI responses.

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
implied by inbound 2xx.

Provider-specific behavior checked on May 25, 2026:

- Slack `url_verification` requests must be authenticated and answered with the
  received `challenge` value: https://docs.slack.dev/reference/events/url_verification
- CloudEvents HTTP supports binary header attributes and structured JSON
  envelopes with `application/cloudevents+json`:
  https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/bindings/http-protocol-binding.md

## Delivery Worker

The worker claims durable outbox rows with database leases, evaluates active
subscriptions and routes, creates delivery jobs, then claims scheduled
deliveries. Delivery attempts are signed, recorded, retried on retryable
failures, and moved to the dead-letter table after terminal failure.
Worker leases are refreshed in PostgreSQL when outbox or delivery work is
claimed.

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
Dead-letter entries can be released one at a time or in bounded bulk batches.

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
write chained audit events.

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

Existing audit rows are backfilled into deterministic per-tenant chains ordered
by `occurred_at, id` during store startup. Backfilled chains prove continuity
from the current database state; they cannot prove history from before the
chain feature existed.

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
services, SIEM streaming, KMS/HSM signing, or compliance-certified evidence
packs.

## Metrics And Readiness

`/readyz` checks PostgreSQL. `/metrics` exposes aggregate Prometheus text
metrics without tenant labels. `/v1/ops/metrics` exposes tenant-scoped JSON
metrics for authenticated operators, including pending outbox count, oldest
outbox age, delivery states, replay states, open DLQ count, quarantine count,
open endpoint circuits, reconciliation job states, reconciliation item outcomes,
unchained audit-event count, audit-chain verification failure count, and newest
anchor age.

## SSRF Protection

Customer endpoint URLs are treated as hostile input. Production endpoint
delivery requires HTTPS by default, rejects embedded credentials and private or
reserved IP destinations, re-resolves hostnames at delivery time, and does not
follow redirects unless an explicit audited policy allows it.
