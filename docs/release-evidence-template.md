# Webhookery Release Evidence Template

This is the canonical release evidence template. Root `RELEASE_EVIDENCE.md`
points here and should not grow a parallel checklist.

Use one completed copy per tagged release. Keep generated SBOM and scan
artifacts with that copy, and record skipped checks as failures or explicit
accepted-risk exceptions. Store evidence outside source control unless it is
sanitized for public review.

Do not include real API keys, webhook secrets, bearer tokens, session tokens,
private keys, provider credentials, database URLs with real credentials, raw
signatures, raw payload bodies, or customer data.

## Result Rules

- `pass`: command or review completed and evidence is attached or linked.
- `fail`: command or review failed; release is blocked unless an accepted-risk
  exception below has owner, expiry, and mitigation.
- `blocked`: required environment, dependency, or permission is unavailable.
- `skipped`: only allowed with an accepted-risk exception.

Local release-candidate gates use fake providers and receivers. They must not
require live Stripe, GitHub, Shopify, Slack, AWS, Vault, SIEM, PagerDuty, or
customer receiver credentials unless a separate commercial engagement records
the live third-party provider scope and risk.

## Release Identity

- Tag:
- Commit:
- OpenAPI version:
- Image:
- Image digest:
- Source SBOM:
- Image SBOM:
- OpenAPI checksum:
- SDK OpenAPI checksum:
- Migration checksum summary:
- Stability policy reviewed:
- Performance smoke output:
- Provider conformance output:
- Failure drill output:
- External review status:
- Accepted risk status:
- Branch protection status:
- Release workflow URL:
- CI workflow URL:
- Integration workflow URL:
- Security workflow URL:

## Required Gates

| Gate | Result | Evidence |
| --- | --- | --- |
| `make docs-check` |  |  |
| `make fast-check` |  |  |
| `make finalize` |  |  |
| `make release-acceptance` |  |  |
| `make rc-check` |  |  |
| stability policy compatibility review |  |  |
| `make provider-conformance-check` |  |  |
| `make perf-smoke` with `WEBHOOKERY_TEST_DATABASE_URL` |  |  |
| `make live-postgres-check` with `WEBHOOKERY_TEST_DATABASE_URL` |  |  |
| DB-backed `make rc-check` with `WEBHOOKERY_TEST_DATABASE_URL` |  |  |
| backup/restore drill with explicit restore database |  |  |
| `docker build -t webhookery:local .` |  |  |
| `docker compose up --build -d` |  |  |
| `/readyz` readiness smoke |  |  |
| `/openapi.yaml` or `/openapi.json` contract smoke |  |  |
| `whcp doctor production` redacted production preflight |  |  |
| provider ingest to signed delivery smoke with fake receiver |  |  |
| invalid provider signature rejection/quarantine smoke |  |  |
| replay original/current config smoke |  |  |
| retention, audit export, and bundle verification smoke |  |  |
| audit-chain verification smoke |  |  |
| reconciliation gap evidence smoke with fake providers |  |  |
| alert notification and SIEM egress smoke with fake receivers |  |  |
| receiver timeout storm drill |  |  |
| object-store read/write failure drill |  |  |
| migration checksum failure drill |  |  |
| audit-chain/export tamper detection drill |  |  |
| log and metrics secret scan |  |  |
| `govulncheck` |  |  |
| `gosec` |  |  |
| Trivy high/critical image scan |  |  |
| source/container SBOM generation |  |  |
| image signing/provenance |  |  |

## Vulnerability And Risk Exceptions

List every critical/high vulnerability, skipped check, unsigned artifact,
incomplete restore drill, or environment limitation. Releases are blocked on
critical/high vulnerabilities unless an owner, expiry date, and mitigation are
recorded here.

| Exception | Owner | Expiry | Mitigation |
| --- | --- | --- | --- |

## Branch Protection

Record the state of `master` branch protection or equivalent ruleset
enforcement. Broad production readiness requires CI, integration, and security
checks to be required before merge. If GitHub account or repository settings
block private branch protection, record that as a release blocker.

Status:

- Required checks:
- Required reviews:
- Force-push protection:
- Admin bypass:
- Evidence URL:

## External Review

Use `docs/external-review-scope.md`,
`docs/external-review-findings-template.md`, and
`docs/external-review-accepted-risks.md`.

| Item | Status | Evidence |
|------|--------|----------|
| external review scope approved |  |  |
| external review completed |  |  |
| critical/high findings fixed |  |  |
| accepted risks copied with owner/expiry/mitigation |  |  |
| production-maturity language reviewed against findings |  |  |

Broad production-maturity language is blocked unless external review findings
are fixed or explicitly accepted with owner, expiry, mitigation, and release
decision.

## Smoke Outputs

Attach or link sanitized artifacts:

- `openapi.yaml` or `openapi.json`,
- readiness response,
- production doctor response with secrets redacted,
- provider conformance output and manifest,
- performance smoke JSON/Markdown output,
- failure drill output,
- provider ingest response with raw payload omitted,
- outbound delivery attempt metadata with request body omitted unless the
  evidence package is explicitly body-inclusive,
- replay response,
- audit-chain verification response,
- audit export manifest and bundle verification response,
- reconciliation gap evidence response,
- alert notification and SIEM delivery status,
- metrics sample,
- API and worker log samples after secret scan.

## Non-Claims

The canonical non-claims are in `docs/security-promise.md`. For this release
evidence: no exactly-once delivery, no provider-side event completeness,
no recovery of every provider-side event, no compliance certification, no legal
evidentiary certification, no external timestamping, no managed-service
availability, and no live third-party provider acceptance. Acceptance tests
must use local fake providers and receivers unless a separate commercial
engagement explicitly records live-provider scope and risk.
