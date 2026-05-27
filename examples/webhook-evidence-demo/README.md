# Webhook Evidence Demo

This example is a deterministic local evidence demo for evaluators. It uses the
same fake-provider and fake-receiver paths as the release-candidate E2E tests.
It does not call Stripe, GitHub, Shopify, Slack, AWS, Vault, or customer
receivers.

The demo proves the core Webhookery story:

1. A Stripe-style event is accepted only after durable capture.
2. The exact raw bytes are verified and preserved.
3. A route creates signed outbound delivery work.
4. Delivery attempts record request and response hashes.
5. Invalid signatures are quarantined and never routed.
6. Retry exhaustion creates DLQ evidence.
7. Replay creates new work without mutating the original event.
8. Retention, audit export, and audit-chain verification preserve evidence.

## Prerequisites

- Go matching `go.mod`
- PostgreSQL reachable through `WEBHOOKERY_TEST_DATABASE_URL`
- A disposable database; the tests create and clean their own records but should
  not be run against production data

Example local database:

```bash
docker compose up -d postgres
export WEBHOOKERY_TEST_DATABASE_URL='postgres://webhookery:webhookery@localhost:5432/webhookery?sslmode=disable'
```

## Run

From the repository root:

```bash
examples/webhook-evidence-demo/run.sh
```

Expected result:

```text
demo: running local webhook evidence demo
demo: provider ingest to signed delivery
demo: invalid signature quarantine
demo: retry, DLQ release, and replay modes
demo: retention, export, and audit-chain permission gates
demo: completed
```

If `WEBHOOKERY_TEST_DATABASE_URL` is not set, the script exits with setup
instructions instead of silently skipping the evidence path.

## Fixtures

- `fixtures/stripe-invoice-paid.json` is the synthetic provider payload used in
  examples and screenshots.
- `fixtures/invalid-stripe-signature-notes.md` explains the invalid-signature
  scenario without storing real provider secrets.

## Safety

Do not replace the fixture data with real customer events. Demo output,
screenshots, videos, release evidence, support requests, and issues must not
include API keys, bearer tokens, webhook secrets, raw provider signatures,
private keys, database URLs with passwords, raw customer payloads, or customer
PII.
