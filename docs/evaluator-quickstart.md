# Evaluator Quickstart

This guide takes a new evaluator from a clean checkout to a local incident
packet that shows the Webhookery evidence loop:

> A Stripe-style payment webhook is captured, downstream delivery fails, the
> event reaches DLQ, replay succeeds after receiver recovery, and Webhookery
> writes a verifiable incident evidence packet.

The flow is local-only. It uses synthetic provider payloads, a fake receiver,
and a disposable PostgreSQL database. Do not use live provider credentials,
customer endpoints, real webhook secrets, raw customer payloads, or production
databases.

## Prerequisites

- Go matching `go.mod`
- Docker and Docker Compose
- `make`
- a clean checkout of this repository

## 1. Start PostgreSQL

```bash
docker compose up -d postgres
export WEBHOOKERY_TEST_DATABASE_URL='postgres://webhookery:change-me@localhost:5432/webhookery?sslmode=disable'
```

Expected result:

```text
Container webhookery-postgres-1  Running
```

The exact container name and status text may differ by Compose version. The URL
above matches the default `docker-compose.yml` values.

## 2. Run The Evidence Demo

```bash
examples/webhook-evidence-demo/run.sh
```

Expected result:

```text
demo: running local webhook evidence demo
demo: failed payment webhook incident packet
ok  	webhookery/internal/e2e
demo: provider ingest to signed delivery
ok  	webhookery/internal/e2e
demo: invalid signature quarantine
ok  	webhookery/internal/e2e
demo: retry, DLQ release, and replay modes
ok  	webhookery/internal/e2e
demo: retention, export, and audit-chain permission gates
ok  	webhookery/internal/e2e
demo: scenario result: downstream failure recorded before replay
demo: scenario result: replay delivery succeeded after receiver recovery
demo: output: .../examples/webhook-evidence-demo/output
demo: completed
```

Durations after the `ok` lines vary by machine.

## 3. Inspect The Incident Packet

The demo writes sanitized output to
`examples/webhook-evidence-demo/output/`:

```text
incident-report.md
incident-report.json
evidence-manifest.json
verify-output.json
README.md
evidence.tar.gz
```

Read the Markdown report first:

```bash
sed -n '1,180p' examples/webhook-evidence-demo/output/incident-report.md
```

Expected result: the report includes summary, event identity, provider
verification, raw capture evidence, route/configuration snapshot, delivery
attempt timeline, retry/DLQ state, replay history, retention state,
audit-chain references, and known gaps/non-claims.

Verify the generated bundle:

```bash
go run ./cmd/whcp audit verify-bundle --file examples/webhook-evidence-demo/output/evidence.tar.gz
```

Expected result:

```json
{"valid":true,"manifest_sha256":"sha256:...","checked_files":4,"checked_chain_entries":0,"failures":null}
```

`verify-output.json` records the same local verification result from the demo
run. A successful run has `result.valid: true`.

## 4. What This Proves

- Webhookery accepts the synthetic Stripe-style event only after durable local
  evidence writes.
- Raw capture evidence is represented by IDs and hashes instead of raw payload
  bodies in the incident packet.
- Invalid signatures are persisted as evidence and not routed.
- Delivery failure, DLQ transition, endpoint recovery, replay work, and
  successful replay delivery are visible in the incident report.
- The local evidence bundle verifies by manifest and file hashes.
- Retention and export checks preserve metadata and permission boundaries.

## 5. What This Does Not Prove

- It does not prove downstream business processing succeeded.
- It does not claim exactly-once delivery or global ordering.
- It does not prove provider-side event completeness.
- It does not certify live Stripe, GitHub, Shopify, Slack, AWS, Vault, or
  customer receiver behavior.
- It is not compliance certification, legal evidentiary certification, a
  restore drill, or a production deployment review.

See `docs/security-promise.md` for the canonical promise and non-claims.

## 6. Optional Live-Provider Proof Guides

The local evaluator path above uses synthetic provider vectors. For manual
sanitized proof against real provider test flows, use:

- `docs/live-provider-proof/stripe.md`
- `docs/live-provider-proof/github.md`
- `docs/providers/stripe.md`
- `docs/providers/github.md`

These guides are external/manual proof procedures. They are not provider
certification, do not require committed secrets, and do not replace the local
release gates.

## 7. Run Release-Candidate Acceptance

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

## 8. Optional Local API Smoke

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

## 9. Review Before Production Decisions

- `docs/security-promise.md`
- `docs/provider-conformance.md`
- `docs/provider-proof-manifest.json`
- `docs/release-evidence-template.md`
- `docs/stability.md`
- `docs/operations.md`
- `docs/day-2-operations.md`
- `COMMERCIAL.md`

## Troubleshooting

If the demo says `WEBHOOKERY_TEST_DATABASE_URL is required`, start PostgreSQL
with Docker Compose and export the variable exactly as shown above.

If the demo cannot connect to `localhost:5432`, confirm that your Compose
PostgreSQL service publishes port `5432`:

```bash
docker compose ps postgres
```

If PostgreSQL is already running on another port, update the URL before running
the demo:

```bash
export WEBHOOKERY_TEST_DATABASE_URL='postgres://USER:PASSWORD@HOST:PORT/DATABASE?sslmode=disable'
```

If the output directory check fails, make sure `WEBHOOKERY_DEMO_OUTPUT_DIR`
points inside the repository and does not resolve through a symlink outside the
repository.

Do not paste production database URLs, provider secrets, raw payload bodies, or
generated evidence bundles into issues, support requests, screenshots, or demo
recordings.

## Cleanup

```bash
docker compose down --remove-orphans
```

If you created a disposable database outside Docker Compose, drop that database
using your normal local PostgreSQL tooling after the evaluation.
