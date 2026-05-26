# Webhookery Release Evidence Template

Use this template for each tagged release. Keep one evidence file per
tag/commit, attach generated SBOM and scan artifacts, and record skipped checks
as failures or explicit accepted-risk exceptions.

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
| `make postgres-integration-test` with `WEBHOOKERY_TEST_DATABASE_URL` |  |  |
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

## Smoke Outputs

Attach or link sanitized artifacts:

- `openapi.yaml` or `openapi.json`,
- readiness response,
- production doctor response with secrets redacted,
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

This release evidence does not claim exactly-once delivery, provider-side event
completeness, recovery of every provider-side event, compliance certification,
legal evidentiary certification, external timestamping, managed-service
availability, or live third-party provider acceptance. Acceptance tests must
use local fake providers and receivers unless a separate commercial engagement
explicitly records live-provider scope and risk.
