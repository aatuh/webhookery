# Feature Behavior Reference

This reference summarizes implemented platform behavior that is too dense for
the operations runbook. It is for maintainers, API reviewers, security
reviewers, and operators who need to understand behavior boundaries before
changing code, contracts, migrations, or runbooks.

Canonical sources still win for exact behavior:

- `openapi.yaml` for API routes, schemas, auth, examples, and status codes.
- `migrations/` for persistence shape.
- `cmd/`, `internal/`, and `pkg/` for implementation.
- `docs/operations.md` for incident and recovery runbooks.
- `docs/configuration.md` for environment variables and secret handling.

Provider-specific behavior changes over time. Before changing provider
semantics for Stripe, GitHub, Shopify, Slack, CloudEvents, or SSRF guidance,
check current official upstream documentation and record the freshness context
using `docs/documentation-maintenance.md`.

## Inbound Capture And Acknowledgement

Inbound provider endpoints may return success only after these records are
durably committed:

- raw body bytes or raw body object metadata
- raw headers and request metadata
- source identity
- verification result
- event metadata
- dedupe result
- durable outbox work

Inbound 2xx never means downstream business processing succeeded. Unverified
events may be retained as evidence, but they must not route to side-effecting
destinations unless an explicit unsafe policy is implemented and audited.

Request guardrails are enforced before capture:

- body limit: 2 MiB
- maximum header pairs: 128
- maximum total header name/value bytes: 64 KiB
- maximum single header value: 8 KiB

Provider adapters verify exact raw bytes. Provider IP allowlists are not a
substitute for cryptographic verification.

## Authentication And Authorization

Normal management access uses database-backed API keys. Rows store token
hashes, key prefixes, last four characters, scopes, state, and membership
linkage, not plaintext keys.

Authorization requires both:

- tenant membership and role
- API key scope or session permission for the requested action

The bootstrap API key hash is a recovery and initial setup mechanism. Remove,
rotate, or restrict it after creating database-backed owner or security keys.

Every primary resource is tenant-scoped. List, read, update, delete, replay,
export, and admin-scope paths must include tenant-aware authorization checks.

## Sources, Endpoints, Routes, And Subscriptions

Sources, endpoints, subscriptions, routes, retry policies, event types, schemas,
transformations, and adapter versions retain reproducibility evidence when
their configuration affects routing or replay.

Important lifecycle behavior:

| Resource | Mutation behavior | Evidence preserved |
|----------|-------------------|--------------------|
| Source | Disable instead of hard-deleting historical receipts. Secret rotation creates active and previous versions with bounded grace. | Events, receipts, raw payload metadata, source versions, audit rows. |
| Endpoint | URL updates rerun SSRF policy before commit. Delete disables future delivery. | Historical deliveries, attempts, payload snapshots, signing metadata, audit rows. |
| Subscription | Updates write immutable subscription versions. Delete disables future fanout. | Subscription versions, delivery decisions, audit rows. |
| Route | Updates check source and endpoint references in the same tenant and write immutable route versions. | Route versions, delivery decisions, replay receipts, audit rows. |
| Retry policy | Updates create new policy versions. Delete disables future use. | Delivery references, retry evidence, audit rows. |
| Event schema | Schema bodies and versions are immutable. State changes are versioned and audited. | Schema versions, validation evidence, replay evidence, audit rows. |

Deletes are generally disabling operations. They must not erase evidence needed
to understand prior capture, routing, delivery, replay, or audit decisions.

## Delivery, Retry, Replay, And DLQ

The worker claims durable outbox rows with PostgreSQL leases, evaluates active
subscriptions and routes, creates delivery jobs, then claims scheduled
deliveries. Delivery attempts are signed, recorded, retried on retryable
failures, and moved to dead letter after terminal failure.

Fairness rules are implemented in PostgreSQL claim ordering:

- live route work before replay and reconciliation work
- live due deliveries before replay deliveries
- tenant round-robin within priority classes

Routes and subscriptions are snapshotted through `route_versions` and
`subscription_versions`. Delivery evidence records the selected version IDs.

Default retry behavior remains 12 attempts over a 72-hour maximum with
full-jitter exponential backoff between 10 seconds and 6 hours when no retry
policy is selected. Deliveries store `retry_seed`; retryable attempts record
the deterministic jitter delay and `next_retry_at`.

Replay creates new delivery work linked to the original event or delivery. It
does not mutate original receipt or delivery history.

Replay modes:

- `config_mode=current`: evaluate current active subscriptions and routes.
- `config_mode=original`: clone recorded non-replay delivery decisions and
  preserve route, subscription, retry policy, and payload evidence where
  available.

Replay jobs may be paused, resumed, canceled, rate-limited, or created with
`require_approval=true`. Approval records approver metadata and a chained audit
event. This is a single approval gate, not a two-person approval workflow.
Replay creation and dry-run requests require both a structured `reason_code`
and a free-text `reason`. Implemented reason codes are `receiver_fixed`,
`provider_reconciliation`, `operator_requested`, `support_investigation`,
`customer_dispute`, `test_drill`, and `incident_recovery`. Replay job rows,
scope JSON, audit evidence, event timelines, and incident reports preserve the
reason code, free-text reason, replay mode, actor, and selected event or
delivery scope.

Dead-letter entries can be released individually or in bounded batches with an
operator reason code and reason because release creates replay work.

## Provider Reconciliation

Provider reconciliation jobs compare provider-side API evidence to local
Webhookery evidence when provider APIs permit it.

Provider API credentials are stored through the same envelope encryption
interface used for webhook and endpoint secrets. API and CLI responses expose
only redacted credential metadata.

Implemented reconciliation outcomes include:

- `matched`
- `missing`
- `captured`
- `redelivery_requested`
- `unrecoverable`
- `failed`

Recovered events use `verification_reason=provider_api_reconciliation`. They
are not marked as signed webhook deliveries and route only when
`route_recovered=true`.

Provider API call evidence records request method, redacted request URL,
response status, response hash, response size, storage status, and optional
response body. Provider API response bodies are sensitive payload data and
require raw payload permissions when included in exports. Provider tokens must
not appear in logs, UI tables, audit metadata, or export metadata.

## Normalization, Transformations, And Schemas

Verified inbound events are normalized after raw body capture and provider
verification. Raw payloads remain authoritative. Unverified requests do not
produce routed normalized payloads by default.

Normalized metadata is available with `events:read`; normalized body data and
raw payload body access require elevated raw-payload permission and emit audit
events.

Custom adapter governance is tenant-scoped. Adapter definitions and versions
are hashed, versioned, audited, and moved through approval states before
activation. Active declarative HMAC-SHA256 adapters can verify inbound requests
using exact raw bytes, configured signature/timestamp headers, and replay
windows. Webhookery records code-plugin package metadata for review, but it
does not execute custom plugin code in this slice.

Transformations are immutable, declarative, tenant-scoped versions. Implemented
operations are JSON Pointer based only:

- `set`
- `copy`
- `drop`
- `redact`

Transformations cannot change provider evidence, verification fields,
tenant/source identifiers, hashes, or audit metadata. There is no arbitrary
scripting, network access, plugin marketplace, or custom runtime.

New delivery work snapshots exact outbound bytes into `delivery_payloads`
before delivery becomes claimable. Workers deliver and sign stored bytes.

Event schemas support a conservative JSON Schema subset:

- `type`
- `required`
- object `properties`
- array `items`

Compatibility checks reject newly required fields, removed existing properties,
and changed property types. Unsupported advanced JSON Schema features are not
treated as compatibility proof.

## Incident Packets And Reports

Incidents are tenant-scoped investigation records. Operators can create an
incident, attach captured events, generate a report snapshot, and create an
incident evidence export. Event attachment validates the incident and event in
the actor tenant before writing the link.

Incident report snapshots are generated from existing event metadata and event
timeline entries. The report includes:

- incident title, reason, state, creator, and timestamps
- event identity, provider, event type, provider event ID, source ID, and
  received time
- provider verification result, verification reason, and dedupe status
- raw payload ID and raw payload hash
- route, subscription, delivery, retry, DLQ, replay, retention, and audit
  timeline references when those entries exist
- explicit non-claims that inbound capture is not downstream business success,
  delivery is at-least-once, and local evidence is not provider-side
  completeness

Reports and incident evidence exports omit raw payload bodies, webhook secrets,
signatures, bearer tokens, private keys, and provider credentials by default.
Generated reports are auditable through `incident_report.generated`; incident
evidence exports write `incident_evidence_export.created` and include
`incident_report.json`, `incident_report.md`, timeline evidence, and bundle
hashes.

## Retention, Raw Payloads, And Exports

Raw payload retrieval is elevated and audited. Operators should keep raw
retention shorter than metadata retention when payloads may contain personal
data.

If retention deletes a raw body or object, body reads return HTTP 410. Event,
receipt, delivery, hash, storage metadata, and audit evidence remain queryable.

Retention policy resource types:

- `raw_payload`
- `normalized_envelope_data`
- `delivery_payload`
- `provider_api_evidence`
- `audit_event`

The worker applies retention in bounded batches and records `retention_runs`
and `retention_run_items`. Policy changes and completed runs write chained
audit events. Legal hold pauses policy execution while preserving visibility
and auditability.

Evidence exports are tenant-scoped `tar.gz` bundles. They include:

- `manifest.json`
- `audit_events.jsonl`
- `payload_evidence.jsonl`
- `audit_chain_proof.jsonl`
- optional `timelines.jsonl`
- optional `raw_payloads.jsonl`
- `reconciliation_evidence.jsonl`

`manifest.json` is versioned as `webhookery.evidence_bundle.v1`. It includes
the generated time, bundle ID, tenant ID hash, included event IDs, included
incident IDs when applicable, file hashes, audit-chain references where
available, redaction policy, and explicit non-claims. It does not serialize the
raw tenant ID.

Raw payload bodies and payload-body exports require both audit read permission
and raw payload permission. Export creation verifies chain proof before marking
the export ready. `whcp audit verify-bundle --file evidence.tar.gz` checks tar
entry safety, manifest schema version, file hashes, manifest hash references,
and audit-chain continuity.

## Audit Chain

Implemented API, CLI, worker, retention, replay, export, reconciliation, and
configuration paths append audit events to a tenant-scoped SHA-256 chain in the
same transaction as the audit row.

Chain entries store:

- audit event hash
- previous chain hash
- current chain hash
- canonicalization version
- source
- state
- tombstone metadata

Backfill is explicit and bounded. It processes deterministic per-tenant batches
ordered by `occurred_at, id`. Backfilled chains prove continuity from the
current database state; they cannot prove history from before the chain feature
existed.

Audit-event retention marks chain entries as retained tombstones before
deleting audit rows. Verification treats retained entries as hash-only
evidence. Missing non-retained audit rows or mismatched hashes are failures.

## Metrics, Readiness, Alerts, And Signal Egress

`/readyz` checks PostgreSQL. `/metrics` exposes aggregate Prometheus text
metrics without tenant labels.

Authenticated tenant-scoped operations APIs expose:

- `/v1/ops/metrics`
- `/v1/ops/metrics/rollups`
- `/v1/ops/storage`
- `/v1/ops/config`
- `/v1/ops/workers`
- `/v1/ops/queues`
- `/v1/alerts`
- `/v1/alert-firings`

Runtime config responses expose only safe metadata such as environment, UI
state, raw storage mode, secret box mode, and request limits. They must not
expose payload bodies, endpoint URLs, database URLs, object-store credentials,
API keys, webhook secrets, master keys, Vault tokens, or tenant labels on
public metrics.

Alert notification channels and SIEM sinks are generic signed HTTPS receivers.
Their URLs use the same SSRF protections as customer webhook endpoints.

Notification payloads contain alert metadata only. SIEM payloads contain
chained audit-event metadata only. Neither includes raw webhook bodies,
provider headers, API keys, bearer tokens, endpoint credentials, channel
secrets, sink secrets, or egress secrets.

SIEM cursors advance only after signed HTTPS delivery succeeds. Failed
deliveries retry from PostgreSQL state and leave the cursor unchanged.

## Enterprise Identity And Access

Management API and UI access can use API keys or OIDC-backed sessions. API keys
remain the bootstrap and break-glass path.

OIDC identity providers are tenant-scoped and support Authorization Code +
PKCE. The callback validates state, nonce, issuer, audience/client ID, expiry,
and signed ID token before creating a hashed session cookie. Session cookies
are HttpOnly, SameSite=Lax, and marked Secure. Logout revokes the server-side
session hash.

Disabling an identity provider revokes active sessions created through that
provider. Session token hashes are never returned.

When the API is behind a trusted reverse proxy, set
`WEBHOOKERY_TRUSTED_PROXY_CIDRS` to a comma-separated CIDR allowlist for the
immediate proxy peers. Only then is the first `X-Forwarded-For` address used
for session metadata. Invalid or untrusted forwarded values fall back to
`RemoteAddr`.

SCIM bearer tokens are returned exactly once and stored only as SHA-256 hashes
with prefix and last-four metadata. SCIM delete deactivates users or groups
instead of hard-deleting them.

Resource-aware role bindings and access policy rules can scope decisions by
principal, resource family, resource ID, and environment. Deny rules take
precedence in explain output.

Emergency recovery remains API-key based. Keep a tightly controlled owner or
security-capable bootstrap/recovery key, rotate it after use, and audit every
identity or access-control change.

## Enterprise Producer Trust

Product-event ingestion at `POST /v1/events` accepts:

- API keys with `events:write`
- OAuth client-credentials bearer tokens
- verified producer mTLS identities

Producer credentials can be source-bound. When a credential has `source_id`,
the submitted event body must contain the same `source_id` or ingestion is
denied before the event service is called.

Producer OAuth client secrets are generated once, returned only in create or
rotate responses, and stored as SHA-256 hashes. Access tokens are opaque bearer
values, stored hashed, have no refresh tokens, default to 15 minutes, and may
not exceed one hour.

Producer mTLS identities store public certificate metadata only: SHA-256
fingerprint, subject/SAN metadata, validity timestamps, state, and optional
source binding. Private keys are never submitted or persisted. This slice does
not trust proxy-supplied mTLS or authentication identity headers.

## SSRF Protection

Customer endpoint URLs are hostile input. Endpoint creation, endpoint updates,
endpoint test sends, delivery attempts, alert notification channels, and SIEM
sinks must use SSRF-safe URL handling.

Default production policy:

- require HTTPS
- reject embedded credentials
- reject private, loopback, link-local, multicast, reserved, and cloud metadata
  destinations
- resolve hostnames at validation time and delivery time
- revalidate redirects when redirects are ever explicitly allowed
- fail closed on invalid URL, DNS, TLS, or destination checks

Do not validate endpoint URLs with ad hoc regular expressions. Use the
implemented SSRF package and its tests.
