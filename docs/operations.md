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

The project makes no FIPS/NIST/CMVP certification claim.

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
with full-jitter exponential backoff between 10 seconds and 6 hours.

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

Endpoint health is derived from recorded delivery attempts. Repeated failures
open a lightweight endpoint circuit and delay further delivery attempts for a
short cooling period; delivery-time SSRF validation still runs for every
attempt.

Endpoint test requests create a signed synthetic `webhookery.endpoint.test`
delivery and preserve the test event, dedupe row, delivery row, and audit
record.

## Reproducible Configuration

`config_versions` records immutable JSON snapshots and hashes for sources,
endpoints, subscriptions, routes, retry policies, schemas, and secret-version
metadata when those resources are created or rotated through the implemented
code paths. `route_versions` and `subscription_versions` store the fields used
for matching and delivery creation. This is a reproducibility foundation; it
does not yet implement full adapter/transformation versioning, deterministic
jitter seeds, or a hash-chained audit log.

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
- `audit_event`: deletes audit rows after the policy age.

The worker applies active policies in bounded batches and records
`retention_runs` plus `retention_run_items`. Policy changes and completed runs
write audit events.

## Audit Evidence Exports

`POST /v1/audit-events:export` creates a tenant-scoped `tar.gz` bundle
synchronously for this implementation slice. The bundle contains
`manifest.json`, `audit_events.jsonl`, and optional `timelines.jsonl` and
`raw_payloads.jsonl`. Raw payload bodies are included only when the actor has
both `audit:read` and `events:raw`; actors without `events:raw` cannot see or
download raw-inclusive exports.

Each export row stores the bundle SHA-256, manifest SHA-256, file hashes,
storage backend, size, creator, and completion timestamp. This is a
tamper-evidence foundation, not a full hash-chained audit log. Hash-chain fields
and verification workflows remain a later v2 feature.

## Metrics And Readiness

`/readyz` checks PostgreSQL. `/metrics` exposes aggregate Prometheus text
metrics without tenant labels. `/v1/ops/metrics` exposes tenant-scoped JSON
metrics for authenticated operators, including pending outbox count, oldest
outbox age, delivery states, replay states, open DLQ count, quarantine count,
and open endpoint circuits.

## SSRF Protection

Customer endpoint URLs are treated as hostile input. Production endpoint
delivery requires HTTPS by default, rejects embedded credentials and private or
reserved IP destinations, re-resolves hostnames at delivery time, and does not
follow redirects unless an explicit audited policy allows it.
