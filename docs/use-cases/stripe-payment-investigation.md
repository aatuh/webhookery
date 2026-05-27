# Stripe Payment Investigation

Audience: support engineers, SREs, and platform teams investigating a payment
webhook that arrived but did not produce the expected downstream business
result.

## Problem

A customer or internal team says payment-related state is wrong. The operator
needs to answer whether Webhookery received the event, verified it, stored
evidence, attempted downstream delivery, moved it to DLQ, replayed it, and
generated a support-safe report.

## Workflow

Start with the local evidence demo:

```bash
docker compose up -d postgres
export WEBHOOKERY_TEST_DATABASE_URL='postgres://webhookery:change-me@localhost:5432/webhookery?sslmode=disable'
examples/webhook-evidence-demo/run.sh
```

For an already-running environment, use the investigation surfaces:

```bash
whcp events search --provider stripe --external-id evt_... --api-key "$WEBHOOKERY_API_KEY"
whcp events timeline --event-id evt_... --format markdown --api-key "$WEBHOOKERY_API_KEY"
whcp incidents create --title "Stripe payment webhook failed" --reason "support investigation" --api-key "$WEBHOOKERY_API_KEY"
whcp incidents add-event --incident-id inc_... --event-id evt_... --reason "failed downstream delivery" --api-key "$WEBHOOKERY_API_KEY"
whcp incidents generate-report --incident-id inc_... --reason "support handoff" --api-key "$WEBHOOKERY_API_KEY"
```

## Evidence Output

Expected evidence includes:

- event identity and provider metadata;
- verification result and raw payload hash;
- delivery attempt timeline;
- DLQ or retry state when present;
- replay reason and replay result when replay is used;
- incident report snapshot; and
- evidence bundle manifest and verification command.

For live test-mode proof, use `docs/live-provider-proof/stripe.md`. For setup
and operator context, use `docs/providers/stripe.md`.

## Non-Claims

This workflow does not prove downstream business processing succeeded, does
not prove provider-side event completeness, and does not claim exactly-once
delivery.
