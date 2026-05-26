# Webhookery

Webhookery is a self-hosted webhook evidence and delivery control plane. It is
built for receiving, verifying, storing, routing, delivering, replaying,
auditing, and debugging webhooks without pretending that delivery can be
exactly once.

The product promise is narrow by design: Webhookery must not return inbound
success before durable capture, loss boundaries must be explicit, and replay,
recovery, and audit evidence must be first-class.

## Implementation Status

This repository is implementation-bearing. The current codebase includes:

- Go API, worker, scheduler, and `whcp` CLI entrypoints under `cmd/`.
- Domain, application, HTTP, persistence, provider, delivery, audit-chain,
  SSRF, retry, transformation, and configuration code under `internal/`.
- Public helper packages under `pkg/client` and `pkg/verifier`.
- `openapi.yaml` as the canonical REST contract, with `sdk/openapi.yaml` as
  the committed SDK-ready copy.
- PostgreSQL migrations under `migrations/`.
- Docker Compose, Kubernetes, Helm, and Terraform deployment profiles.
- SDK artifacts, Postman and Bruno smoke collections, and CI workflows.

`.initial_design.md` is historical design input and architecture rationale. It
does not prove implemented behavior. Use code, OpenAPI, migrations, deployment
profiles, and canonical docs as the source of truth for current behavior.

## Local Quickstart

Prerequisites: Go, Docker, and Docker Compose.

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

## Short Smoke Paths

- Local API and worker: `docker compose up --build`, then `/readyz`.
- Non-mutating docs and contract gate: `make docs-check`.
- Full repository gate: `make finalize`.
- Disposable live database gate:
  `WEBHOOKERY_TEST_DATABASE_URL=postgres://... make live-postgres-check`.
- Release-candidate acceptance:
  `WEBHOOKERY_TEST_DATABASE_URL=postgres://... make rc-check`.
- Postman and Bruno smoke collections: see `collections/`.

## Security Promise And Non-Claims

Inbound success means Webhookery durably captured raw request evidence and
verification metadata according to the configured storage mode. It does not
mean downstream business processing succeeded.

Webhookery does not claim:

- exactly-once delivery
- provider-side event completeness
- multi-region active-active operation
- external timestamping
- compliance certification
- live third-party provider recovery guarantees

Examples in this repository use placeholders or local development values. Do
not put real API keys, provider credentials, webhook secrets, bearer tokens,
private keys, raw signatures, raw payload bodies, or customer data into docs,
commits, issues, support requests, or audit artifacts.

## Primary Docs

- `docs/index.md`: canonical documentation map by audience, purpose, and
  source-of-truth boundary.
- `docs/configuration.md`: canonical environment variable and secret handling
  reference.
- `docs/operations.md`: operator runbooks and production RC procedures.
- `docs/security-review-package.md`: security reviewer artifact map.
- `docs/release-evidence-template.md`: canonical release evidence template.
- `docs/cli.md`: CLI command reference and moved command catalog.
- `sdk/README.md`: committed SDK artifact guidance.
- `deploy/kubernetes/README.md`, `deploy/helm/webhookery/README.md`, and
  `deploy/terraform/webhookery-helm/README.md`: deployment profile notes.
- `SECURITY.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `SUPPORT.md`,
  `COMMERCIAL.md`, and `TRADEMARKS.md`: project policy docs.

Run `make help` for the project-owned command list. Keep README examples short;
put detailed command workflows in the relevant canonical docs.
