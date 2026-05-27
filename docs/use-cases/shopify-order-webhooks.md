# Shopify Order Webhooks

Audience: ecommerce platform teams investigating order-related webhooks in a
development store or controlled pilot.

## Problem

An order-related webhook was expected to update internal systems, but the
receiver failed or the result is unclear. The operator needs topic metadata,
verification evidence, delivery history, replay governance, and a sanitized
evidence packet.

## Workflow

For a local walkthrough, run the evidence demo. For development-store proof,
follow `docs/live-provider-proof/shopify.md`.

```bash
whcp events search --provider shopify --route-id rte_... --since 24h --api-key "$WEBHOOKERY_API_KEY"
whcp events timeline --event-id evt_... --format markdown --api-key "$WEBHOOKERY_API_KEY"
whcp replay-jobs create --event-id evt_... --config-mode original --reason-code support_investigation --reason "review order webhook replay" --api-key "$WEBHOOKERY_API_KEY"
whcp incidents create --title "Shopify order webhook investigation" --reason "support investigation" --api-key "$WEBHOOKERY_API_KEY"
whcp incidents add-event --incident-id inc_... --event-id evt_... --reason "order receiver failure" --api-key "$WEBHOOKERY_API_KEY"
whcp incidents generate-report --incident-id inc_... --reason "support handoff" --api-key "$WEBHOOKERY_API_KEY"
```

## Evidence Output

Expected evidence includes:

- provider metadata and event type or topic when captured;
- HMAC verification result;
- route and delivery attempt evidence;
- replay reason and mode;
- retention/raw-payload access state; and
- incident report references and non-claims.

Use `docs/providers/shopify.md` for setup and operator context.

## Non-Claims

This workflow does not claim universal topic-specific recovery, provider-side
completeness, exactly-once delivery, or compliance certification.
