# Evaluator Quickstart

This guide takes a new evaluator from a clean checkout to local evidence that
Webhookery can capture, verify, deliver, replay, and audit webhook events.

The flow is local-only. It uses synthetic provider payloads and fake receivers.
Do not use live provider credentials, customer endpoints, real webhook secrets,
or production databases.

## Prerequisites

- Go matching `go.mod`
- Docker and Docker Compose
- `make`
- a clean checkout of this repository

## 1. Start PostgreSQL

```bash
docker compose up -d postgres
export WEBHOOKERY_TEST_DATABASE_URL='postgres://webhookery:webhookery@localhost:5432/webhookery?sslmode=disable'
```

Expected result:

```text
Container webhookery-postgres-1  Running
```

The exact container name may differ by Compose version.

## 2. Run The Evidence Demo

```bash
examples/webhook-evidence-demo/run.sh
```

Expected result:

```text
demo: running local webhook evidence demo
demo: provider ingest to signed delivery
ok  	webhookery/internal/e2e
demo: invalid signature quarantine
ok  	webhookery/internal/e2e
demo: retry, DLQ release, and replay modes
ok  	webhookery/internal/e2e
demo: retention, export, and audit-chain permission gates
ok  	webhookery/internal/e2e
demo: completed
```

What this proves:

- Webhookery accepts a valid Stripe-style event only after durable evidence
  writes.
- It signs outbound delivery payloads and records attempt hashes.
- It quarantines invalid signatures without routing them.
- It can retry to DLQ, release DLQ work, and replay original/current config
  modes.
- Retention and export paths preserve metadata and permission boundaries.
- Audit-chain verification succeeds after the local evidence flow.

## 3. Run Release-Candidate Acceptance

```bash
make rc-check
```

Expected result:

```text
rc-check: release-candidate acceptance checks passed
```

When `WEBHOOKERY_TEST_DATABASE_URL` is set, `make rc-check` includes the
DB-backed release-candidate E2E checks. If the variable is not set, the script
prints that those DB-backed checks were skipped.

## 4. Optional Local API Smoke

Start the local API stack:

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

Expected result:

- `/readyz` returns success.
- `whcp events list` returns JSON.
- `whcp audit verify-chain` returns a JSON verification result.

The bootstrap key is for local development only. Do not use it for production
or production-like evaluation.

## 5. Review Evidence And Boundaries

Read these docs before making a production decision:

- `docs/security-promise.md`
- `docs/provider-conformance.md`
- `docs/release-evidence-template.md`
- `docs/stability.md`
- `docs/operations.md`
- `docs/day-2-operations.md`
- `COMMERCIAL.md`

Key boundaries:

- inbound success means durable capture, not downstream business success
- delivery is at-least-once, not exactly once
- provider reconciliation cannot prove provider-side event completeness
- local acceptance does not call live providers
- release evidence is not compliance certification

## Troubleshooting

If the demo says `WEBHOOKERY_TEST_DATABASE_URL is required`, start PostgreSQL
with Docker Compose and export the variable exactly as shown above.

If PostgreSQL is already running on another port, update the URL before running
the demo:

```bash
export WEBHOOKERY_TEST_DATABASE_URL='postgres://USER:PASSWORD@HOST:PORT/DATABASE?sslmode=disable'
```

Do not paste production database URLs into issues, support requests, release
evidence, screenshots, or demo recordings.

## Cleanup

```bash
docker compose down --remove-orphans
```

If you created a disposable database outside Docker Compose, drop that database
using your normal local PostgreSQL tooling after the evaluation.
