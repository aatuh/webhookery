# Webhook Evidence Demo

This example is a deterministic local evidence demo for evaluators. It uses the
same fake-provider and fake-receiver paths as the release-candidate E2E tests.
It does not call Stripe, GitHub, Shopify, Slack, AWS, Vault, or customer
receivers.

The demo proves the core Webhookery story:

1. A Stripe-style event is accepted only after durable capture.
2. The exact raw bytes are verified and preserved.
3. A route creates signed outbound delivery work.
4. A downstream receiver failure records delivery-attempt and DLQ evidence.
5. Replay creates new work after receiver recovery without mutating the
   original event.
6. A first-class incident links the failed event to a human-readable report.
7. The demo exports and verifies an incident evidence bundle locally.
8. Invalid signatures are quarantined and never routed.
9. Retention, audit export, and audit-chain verification preserve evidence.

## Prerequisites

- Go matching `go.mod`
- PostgreSQL reachable through `WEBHOOKERY_TEST_DATABASE_URL`
- A disposable database; the tests create and clean their own records but should
  not be run against production data

Example local database:

```bash
docker compose up -d postgres
export WEBHOOKERY_TEST_DATABASE_URL='postgres://webhookery:change-me@localhost:5432/webhookery?sslmode=disable'
```

## Run

From the repository root:

```bash
examples/webhook-evidence-demo/run.sh
```

Expected result:

```text
demo: running local webhook evidence demo
demo: failed payment webhook incident packet
demo: provider ingest to signed delivery
demo: invalid signature quarantine
demo: retry, DLQ release, and replay modes
demo: retention, export, and audit-chain permission gates
demo: scenario result: downstream failure recorded before replay
demo: scenario result: replay delivery succeeded after receiver recovery
demo: output: .../examples/webhook-evidence-demo/output
demo: completed
```

If `WEBHOOKERY_TEST_DATABASE_URL` is not set, the script exits with setup
instructions instead of silently skipping the evidence path.

The script writes a sanitized local packet to
`examples/webhook-evidence-demo/output/` by default:

```text
incident-report.md
incident-report.json
evidence-manifest.json
verify-output.json
README.md
evidence.tar.gz
```

`verify-output.json` contains the local bundle verification result. A successful
demo has `result.valid: true`. To choose a different output directory, set
`WEBHOOKERY_DEMO_OUTPUT_DIR`; the path must stay inside the repository so the
script cannot overwrite arbitrary operator files.

## Fixtures

- `fixtures/stripe-invoice-paid.json` is the synthetic provider payload used in
  examples and screenshots.
- `fixtures/invalid-stripe-signature-notes.md` explains the invalid-signature
  scenario without storing real provider secrets.

## Safety

Do not replace the fixture data with real customer events. Demo output is
generated with synthetic IDs and redaction checks for the human-readable files,
but screenshots, videos, release evidence, support requests, and issues must
still be reviewed before sharing. They must not include API keys, bearer tokens,
webhook secrets, raw provider signatures, private keys, database URLs with
passwords, raw customer payloads, or customer PII.
