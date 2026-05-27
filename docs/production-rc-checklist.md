# Production RC Checklist

Use this checklist before treating a Webhookery tag as a controlled
self-hosted release candidate. This checklist routes to canonical docs instead
of duplicating every command.

Webhookery release-candidate readiness does not mean exactly-once delivery,
provider-side completeness, compliance certification, or managed-service
availability.

## 1. Release Identity

- Tag is created and points to the intended commit.
- Release notes exist under `docs/releases/`.
- Changelog includes the release.
- Image digest is recorded.
- Source and image SBOMs are attached or linked.
- Release evidence artifact is attached or linked.

## 2. Local Gates

Run:

```bash
make docs-check
make release-acceptance
make rc-check
make finalize
```

Expected result: all commands exit zero. If a command is skipped or blocked,
record it in the release evidence packet with owner, expiry, and mitigation.

## 3. Disposable Database Gates

Run against a disposable database, not production:

```bash
WEBHOOKERY_TEST_DATABASE_URL=postgres://... make live-postgres-check
WEBHOOKERY_TEST_DATABASE_URL=postgres://... make rc-check
```

Expected result: migrations, DB-backed evidence checks, and RC drills pass.

## 4. Release Workflow

Confirm the release workflow passed:

- release acceptance
- provider conformance
- performance smoke
- `rc-check` with the local Postgres service
- Docker build and push
- cosign keyless signing
- source and image SBOM generation
- Trivy HIGH/CRITICAL image scan
- evidence artifact upload

## 5. Security And Evidence Review

Review:

- `docs/security-promise.md`
- `docs/security-review-package.md`
- `docs/articles/webhook-security-review-checklist.md`
- `docs/provider-conformance.md`
- `docs/release-evidence-template.md`
- `docs/release-evidence-sample.md`

Expected result: non-claims are preserved and sensitive data is absent from
docs, logs, release notes, and artifacts.

## 6. Operations Readiness

Review:

- `docs/configuration.md`
- `docs/operations.md`
- `docs/day-2-operations.md`
- `docs/deployment.md`
- `docs/schema-migrations.md`
- `docs/observability.md`

Expected result: production doctor, backup/restore, retention, audit-chain
verification, alert handling, and restore drills have an owner.

## 7. Accepted Risks

Record unresolved items in `docs/external-review-accepted-risks.md` or the
release evidence packet. Each accepted risk needs:

- owner
- expiry date
- mitigation
- release decision

Do not call a release broadly production-ready when release-blocking risks are
open without accepted-risk records.
