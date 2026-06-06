# Webhookery

[![CI](https://github.com/aatuh/webhookery/actions/workflows/ci.yml/badge.svg)](https://github.com/aatuh/webhookery/actions/workflows/ci.yml)
[![Security](https://github.com/aatuh/webhookery/actions/workflows/security.yml/badge.svg)](https://github.com/aatuh/webhookery/actions/workflows/security.yml)
[![Integration](https://github.com/aatuh/webhookery/actions/workflows/integration.yml/badge.svg)](https://github.com/aatuh/webhookery/actions/workflows/integration.yml)
[![Fuzz](https://github.com/aatuh/webhookery/actions/workflows/fuzz.yml/badge.svg)](https://github.com/aatuh/webhookery/actions/workflows/fuzz.yml)
[![CodeQL](https://github.com/aatuh/webhookery/actions/workflows/codeql.yml/badge.svg)](https://github.com/aatuh/webhookery/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://github.com/aatuh/webhookery/actions/workflows/scorecard.yml/badge.svg)](https://github.com/aatuh/webhookery/actions/workflows/scorecard.yml)
[![Release](https://github.com/aatuh/webhookery/actions/workflows/release.yml/badge.svg)](https://github.com/aatuh/webhookery/actions/workflows/release.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)
![Go Version](https://img.shields.io/badge/go-1.25.11+-00ADD8.svg)
![OpenAPI](https://img.shields.io/badge/OpenAPI-214%20operations-brightgreen.svg)
![Coverage Gate](https://img.shields.io/badge/local%20coverage-50%25+-yellow.svg)
![DB Coverage Gate](https://img.shields.io/badge/db%20coverage-68%25+-yellowgreen.svg)

Audit-grade webhook capture, replay, and evidence -- self-hosted.

Webhookery durably captures provider webhooks before acknowledging them,
verifies signatures, records delivery attempts, supports governed replay, and
exports verifiable evidence when integrations fail.

Website: <https://aatuh.github.io/webhookery/>

The product promise is narrow by design: Webhookery must not return inbound
success before durable capture, loss boundaries must be explicit, and replay,
recovery, and audit evidence must be first-class. It is built for teams that
need to prove what arrived, what failed, what was replayed, and what evidence
remains without pretending that delivery can be exactly once.

Start here if you are evaluating Webhookery:

- Why Webhookery: `docs/why-webhookery.md`
- Evaluator walkthrough: `docs/evaluator-quickstart.md`
- Local evidence demo: `examples/webhook-evidence-demo/`
- Stripe proof guide: `docs/live-provider-proof/stripe.md`
- GitHub proof guide: `docs/live-provider-proof/github.md`
- Shopify proof guide: `docs/live-provider-proof/shopify.md`
- Static product page: `site/index.html`
- Rendered OpenAPI reference: `docs/openapi/index.html`
- API contract matrix: `docs/reference/api-contract-matrix.md`
- Release notes: `docs/releases/v0.2.0-pilot.md`
- Release evidence index: `docs/reference/release-evidence-index.md`
- Current public release metadata: `release/current.json`
- Previous release notes: `docs/releases/v0.1.0-rc1.md`
- Pilot topology: `docs/pilot-topology.md`
- Commercial evaluation: `docs/commercial-evaluation.md`

## Implementation Status

This repository is implementation-bearing. The current codebase includes:

- Go API, worker, scheduler, and `whcp` CLI entrypoints under `cmd/`.
- Domain, application, HTTP, persistence, provider, delivery, audit-chain,
  SSRF, retry, transformation, and configuration code under `internal/`.
- Public helper packages under `pkg/client` and `pkg/verifier`.
- `openapi.yaml` as the canonical REST contract, with `sdk/openapi.yaml` as
  the committed SDK-ready copy and `docs/openapi/index.html` as the rendered
  reference artifact.
- PostgreSQL migrations under `migrations/`.
- Docker Compose, Kubernetes, Helm, and Terraform deployment profiles.
- SDK artifacts, Postman and Bruno smoke collections, and CI workflows.

`.initial_design.md` is historical design input and architecture rationale. It
does not prove implemented behavior. Use code, OpenAPI, migrations, deployment
profiles, and canonical docs as the source of truth for current behavior.

## Local Quickstart

Prerequisites: Go, Docker, and Docker Compose.

For the evidence-first path, run the failed-payment demo:

```bash
docker compose up -d postgres
export WEBHOOKERY_TEST_DATABASE_URL='postgres://webhookery:change-me@localhost:5432/webhookery?sslmode=disable'
examples/webhook-evidence-demo/run.sh
```

Expected result: `examples/webhook-evidence-demo/output/` contains a sanitized
incident report, evidence manifest, verification output, and local evidence
bundle for a failed downstream delivery followed by replay.

For a short API smoke path:

```bash
cp .env.example .env
docker compose up --build
```

In another shell:

```bash
curl -fsS http://localhost:8080/readyz
export WEBHOOKERY_API_KEY=dev-bootstrap-key
go run ./cmd/whcp events list --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit verify-chain --api-key "$WEBHOOKERY_API_KEY"
```

Expected result: readiness returns success, the CLI can authenticate with the
local bootstrap key, and audit-chain verification returns a JSON result.

The local bootstrap key is for development only. Create a database-backed API
key immediately and remove or rotate the bootstrap hash before any
production-style use.

Use `docs/evaluator-quickstart.md` for the guided evidence-loop walkthrough,
expected output, troubleshooting, and non-claims.

## Short Smoke Paths

- Local API and worker: `docker compose up --build`, then `/readyz`.
- Non-mutating docs and contract gate: `make docs-check`.
- Provider conformance matrix and local vectors: `make provider-conformance-check`.
- Manual provider-proof metadata: `make provider-proof-check`.
- Full repository gate: `make finalize`.
- Redacted production preflight:
  `WEBHOOKERY_ENVIRONMENT=production go run ./cmd/whcp doctor production`.
- Redacted pilot preflight:
  `go run ./cmd/whcp doctor pilot --no-network`.
- Disposable live database gate:
  `WEBHOOKERY_TEST_DATABASE_URL=postgres://... make live-postgres-check`.
- Release-candidate acceptance:
  `WEBHOOKERY_TEST_DATABASE_URL=postgres://... make rc-check`.
- Postman and Bruno smoke collections: see `collections/`.

## Production RC Readiness

Use `docs/operations.md`, `docs/day-2-operations.md`, `docs/stability.md`, and
`docs/release-evidence-template.md` as the canonical release-candidate
readiness path. The short version is: run the production doctor, `make
finalize`, live PostgreSQL checks against a disposable database, `make
rc-check`, and restore drills when migrations or evidence storage are touched.
Use `docs/observability.md` for starter Prometheus rules and dashboards. Do
not use live provider or customer credentials for local acceptance gates.

Pilot release details live in `docs/releases/v0.2.0-pilot.md`. Release
evidence requirements live in `docs/release-evidence-template.md`, with a
reader-facing example in `docs/release-evidence-sample.md`, the current public
artifact map in `docs/reference/release-evidence-index.md`, and a concise
operator checklist in `docs/production-rc-checklist.md`.

## Security Promise And Non-Claims

See `docs/security-promise.md` for the canonical promise and non-claims.
In short: inbound success means durable capture and verification metadata were
recorded; it does not mean downstream business processing succeeded.

Examples in this repository use placeholders or local development values. Do
not put real API keys, provider credentials, webhook secrets, bearer tokens,
private keys, raw signatures, raw payload bodies, or customer data into docs,
commits, issues, support requests, or audit artifacts.

Commercial license exceptions, evaluation packages, production-readiness
reviews, and support package boundaries are described in `COMMERCIAL.md`,
`docs/commercial-evaluation.md`, `docs/production-readiness-review.md`, and
`docs/support-packages.md`.

## Primary Docs

- `docs/index.md`: canonical documentation map by audience, purpose, and
  source-of-truth boundary.
- `docs/why-webhookery.md`: product wedge and fit/non-fit explanation.
- `docs/configuration.md`: canonical environment variable and secret handling
  reference.
- `docs/reference/source-of-truth.md`: public source-of-truth map for release,
  API, workflow, deployment, and documentation artifacts.
- `docs/reference/openapi.md`: rendered OpenAPI and API contract matrix
  reference.
- `docs/reference/api-contract-matrix.md`: generated operation matrix from
  `openapi.yaml`.
- `docs/reference/release-evidence-index.md`: public release artifact map and
  verification notes.
- `docs/reference/release-validation.md`: release validation and evidence
  workflow.
- `docs/evaluator-quickstart.md`: guided local evaluator walkthrough.
- `examples/webhook-evidence-demo/`: deterministic local fake-provider and
  fake-receiver evidence demo.
- `site/index.html`: static product landing page.
- `docs/operations.md`: operator runbooks and production RC procedures.
- `docs/failure-drills.md`: local and pilot failure-drill plan, script usage,
  and restore-drill evidence rules.
- `docs/feature-behavior.md`: behavior reference for capture, routing,
  delivery, replay, reconciliation, retention, identity, producer trust, and
  SSRF.
- `docs/security-promise.md`: canonical durable-capture promise and
  non-claims.
- `docs/error-codes.md`: stable API/CLI error-code reference.
- `docs/stability.md`: compatibility, support-window, migration, and
  deprecation policy.
- `docs/performance-envelope.md`: performance smoke usage, capacity inputs,
  storage growth, and sizing caveats.
- `docs/documentation-maintenance.md`: provider freshness and documentation
  review checklist.
- `docs/provider-conformance.md`: provider matrix, local vector evidence, and
  links to manual live-provider proof guides.
- `docs/providers/stripe.md` and `docs/providers/github.md`: operator guides
  for the first flagship providers.
- `docs/providers/shopify.md`: operator guide for the first ecommerce
  follow-up provider.
- `docs/live-provider-proof/stripe.md` and
  `docs/live-provider-proof/github.md`: manual sanitized proof guides.
- `docs/live-provider-proof/shopify.md`: manual sanitized Shopify proof guide.
- `docs/deployment.md`: common self-hosted deployment posture.
- `docs/pilot-topology.md`: narrow supported topology for initial pilots.
- `docs/pilot-evidence-template.md`: sanitized pilot evidence packet template.
- `docs/evidence-bundle-profiles.md`: safe bundle profile policy for support,
  security review, commercial evaluation, and internal forensics.
- `docs/use-cases/stripe-payment-investigation.md`,
  `docs/use-cases/github-automation-webhooks.md`,
  `docs/use-cases/shopify-order-webhooks.md`, and
  `docs/use-cases/internal-integration-replay.md`: story-led evaluation
  workflows tied to incident packets.
- `docs/schema-migrations.md`: schema review, migration ordering, and restore
  compatibility guidance.
- `docs/security-review-package.md`: security reviewer artifact map.
- `docs/external-review-package.md`: external review package index.
- `docs/release-evidence-template.md`: canonical release evidence template.
- `docs/production-rc-checklist.md`: release-candidate readiness checklist.
- `docs/releases/v0.2.0-pilot.md`: pilot prerelease notes.
- `docs/releases/v0.1.0-rc1.md`: first release-candidate notes.
- `docs/demo-media-checklist.md`: safe screenshots/video checklist.
- `docs/customer-discovery-notes-template.md`,
  `docs/pilot-feedback-template.md`, `docs/roadmap-intake-policy.md`, and
  `docs/pilot-review-checklist.md`: evaluator and pilot feedback discipline.
- `.github/ISSUE_TEMPLATE/evaluator-feedback.yml`: public sanitized feedback
  issue form.
- `docs/commercial-evaluation.md`, `docs/production-readiness-review.md`, and
  `docs/support-packages.md`: commercial evaluation and support boundaries.
- `docs/cli.md`: CLI command reference and moved command catalog.
- `sdk/README.md`: committed SDK artifact guidance.
- `collections/README.md`: Postman and Bruno smoke request usage.
- `deploy/kubernetes/README.md`, `deploy/helm/webhookery/README.md`, and
  `deploy/terraform/webhookery-helm/README.md`: deployment profile notes.
- `SECURITY.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `SUPPORT.md`,
  `CODE_OF_CONDUCT.md`, `CODEOWNERS`, `COMMERCIAL.md`, and `TRADEMARKS.md`:
  project policy docs.

Run `make help` for the project-owned command list. Keep README examples short;
put detailed command workflows in the relevant canonical docs.
