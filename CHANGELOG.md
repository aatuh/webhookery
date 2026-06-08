# Changelog

All notable public release changes for Webhookery are recorded here.

Webhookery follows the stability policy in `docs/stability.md`. Release notes
must distinguish implemented behavior from future intent and must preserve the
canonical non-claims in `docs/security-promise.md`.

## v0.2.0-pilot - 2026-06-08

Release status: pilot prerelease for controlled, single-region, self-hosted
evaluation.

### Added

- Incident report APIs, CLI commands, persistence, OpenAPI contract coverage,
  and deterministic local evidence packet flows.
- Versioned evidence bundle manifests and an offline bundle viewer for
  evaluator review without a running service.
- Forensic event search filters, stable event timeline output, and stable API
  problem codes for support workflows.
- Replay reason codes, replay approval expiry, and replay approval policies.
- Pilot readiness doctor checks, local failure-drill tooling, restore-drill
  contract checks, and richer release-candidate evidence paths.
- Stripe, GitHub, and Shopify live-provider proof guides with redacted public
  samples and proof freshness metadata.
- Public repository trust metadata: README badges, CodeQL, OpenSSF Scorecard,
  Dependabot configuration, GitHub Pages, issue/PR templates, CODEOWNERS, and
  Code of Conduct.
- Release asset packaging for installable archives, checksums, OpenAPI and
  migration hashes, manifest, provenance metadata, SBOM carry-through, and
  release evidence.

### Changed

- Raw payload access now requires a reason and remains elevated/audited.
- GitHub-facing release evidence and OpenAPI reference surfaces are generated
  and checked by project-owned commands.
- The Go toolchain metadata is aligned on Go 1.25.11 or newer.

### Fixed

- Copied outbound delivery clients no longer inherit unintended redirect
  behavior, preserving SSRF validation boundaries.
- Release generator directory permissions and security annotations are aligned
  with `gosec`.

### Known Limits

- This pilot prerelease is not broad production-readiness certification.
- Branch protection is not currently enabled on `master`; this is accepted only
  for the pilot prerelease and blocks stronger production positioning.
- External security or production-readiness review is not complete.
- Local and workflow release gates do not prove live-provider acceptance or
  provider-side event completeness.

### Non-Claims

- No exactly-once delivery claim.
- No provider-side event completeness guarantee.
- No downstream business success guarantee.
- No compliance certification, legal evidence certification, or external
  timestamping claim.
- No hosted-service availability or multi-region active-active guarantee.

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
