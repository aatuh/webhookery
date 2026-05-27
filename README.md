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
- Provider conformance matrix and local vectors: `make provider-conformance-check`.
- Full repository gate: `make finalize`.
- Redacted production preflight:
  `WEBHOOKERY_ENVIRONMENT=production go run ./cmd/whcp doctor production`.
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

## Security Promise And Non-Claims

See `docs/security-promise.md` for the canonical promise and non-claims.
In short: inbound success means durable capture and verification metadata were
recorded; it does not mean downstream business processing succeeded.

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
- `docs/feature-behavior.md`: behavior reference for capture, routing,
  delivery, replay, reconciliation, retention, identity, producer trust, and
  SSRF.
- `docs/security-promise.md`: canonical durable-capture promise and
  non-claims.
- `docs/stability.md`: compatibility, support-window, migration, and
  deprecation policy.
- `docs/performance-envelope.md`: performance smoke usage, capacity inputs,
  storage growth, and sizing caveats.
- `docs/documentation-maintenance.md`: provider freshness and documentation
  review checklist.
- `docs/deployment.md`: common self-hosted deployment posture.
- `docs/schema-migrations.md`: schema review, migration ordering, and restore
  compatibility guidance.
- `docs/security-review-package.md`: security reviewer artifact map.
- `docs/release-evidence-template.md`: canonical release evidence template.
- `docs/cli.md`: CLI command reference and moved command catalog.
- `sdk/README.md`: committed SDK artifact guidance.
- `collections/README.md`: Postman and Bruno smoke request usage.
- `deploy/kubernetes/README.md`, `deploy/helm/webhookery/README.md`, and
  `deploy/terraform/webhookery-helm/README.md`: deployment profile notes.
- `SECURITY.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `SUPPORT.md`,
  `COMMERCIAL.md`, and `TRADEMARKS.md`: project policy docs.

Run `make help` for the project-owned command list. Keep README examples short;
put detailed command workflows in the relevant canonical docs.
