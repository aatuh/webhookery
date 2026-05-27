# Changelog

All notable public release changes for Webhookery are recorded here.

Webhookery follows the stability policy in `docs/stability.md`. Release notes
must distinguish implemented behavior from future intent and must preserve the
canonical non-claims in `docs/security-promise.md`.

## v0.1.0-rc1 - 2026-05-27

Release status: release candidate for controlled, single-region, self-hosted
evaluation.

### Added

- Durable webhook evidence and delivery control plane implemented in Go with
  API, worker, scheduler, migration, admin, and CLI entrypoints.
- PostgreSQL-first persistence with migrations, raw payload evidence, delivery
  attempts, replay, DLQ, quarantine, retention, evidence exports, and audit
  chain verification.
- Provider-aware ingestion for Stripe, GitHub, Shopify, Slack, generic HMAC/JWT,
  CloudEvents, and internal producer events, backed by local conformance vectors.
- Versioned routes, subscriptions, retry policies, schemas, adapter evidence,
  normalized envelopes, deterministic transformations, and delivery payload
  snapshots.
- Provider reconciliation evidence for supported fake/local test paths and
  explicit unsupported/unrecoverable provider gap evidence.
- Operational readiness surfaces: production doctor, release-candidate checks,
  performance smoke, provider conformance checks, backup/restore scripts,
  observability examples, alerts, notifications, SIEM signal egress, and
  deployment profiles.
- Enterprise/self-hosting support foundations: API keys, OIDC/SCIM identity
  lifecycle, scoped RBAC/ABAC, producer OAuth, producer mTLS metadata, endpoint
  mTLS delivery, local/Vault/AWS-KMS-style secret custody interfaces, and
  commercial governance docs.

### Release Evidence

- Local release evidence is generated with `make release-acceptance`.
- Core release-candidate checks are generated with `make rc-check`.
- DB-backed checks run when `WEBHOOKERY_TEST_DATABASE_URL` points at a
  disposable PostgreSQL database.
- Release workflow artifacts include source/image SBOMs, image digest, Trivy
  HIGH/CRITICAL scan result, provider conformance output, performance smoke
  output, and release evidence summary.

### Known Limits

- This release candidate is not a hosted service.
- It is not a compliance certification, legal evidence certification, or
  external audit attestation.
- Local acceptance checks use fake/local providers and receivers only.
- Provider reconciliation remains limited by provider API capabilities and
  configured credentials.
- Operators remain responsible for production PostgreSQL, object storage,
  network policy, TLS, backups, monitoring, and incident response.

### Non-Claims

- No exactly-once delivery claim.
- No provider-side event completeness guarantee.
- No guarantee that downstream business processing succeeded.
- No multi-region active-active guarantee.
- No live-provider acceptance claim.
