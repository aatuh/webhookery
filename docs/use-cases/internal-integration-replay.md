# Internal Integration Replay

Audience: platform teams using Webhookery for controlled internal producers
and receivers where replay must be governed and auditable.

## Problem

An internal producer sent an event to Webhookery, but a downstream receiver
failed. The operator needs to prove durable capture, inspect delivery
attempts, preview or run replay with a reason, and preserve evidence for an
incident review.

## Workflow

Find affected events first:

```bash
whcp events search --status dlq --since 24h --api-key "$WEBHOOKERY_API_KEY"
whcp events timeline --event-id evt_... --format json --api-key "$WEBHOOKERY_API_KEY"
```

Run replay only after confirming receiver readiness and idempotency:

```bash
whcp replay-jobs create --event-id evt_... --config-mode original --rate-limit-per-minute 30 --reason-code receiver_fixed --reason "receiver restored after outage" --api-key "$WEBHOOKERY_API_KEY"
```

Create the incident packet:

```bash
whcp incidents create --title "Internal integration replay" --reason "receiver outage investigation" --api-key "$WEBHOOKERY_API_KEY"
whcp incidents add-event --incident-id inc_... --event-id evt_... --reason "DLQ replay candidate" --api-key "$WEBHOOKERY_API_KEY"
whcp incidents export --incident-id inc_... --reason "internal incident review" --output internal-replay-evidence.tar.gz --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit verify-bundle --file internal-replay-evidence.tar.gz
```

## Evidence Output

Expected evidence includes:

- durable capture metadata and hashes;
- delivery attempts and failure classes;
- DLQ state;
- replay reason code, free-text reason, and mode;
- audit-chain references; and
- evidence bundle verification result.

## Non-Claims

Replay is at-least-once work and can duplicate side effects. Webhookery records
the reason and evidence trail; receiver idempotency remains the operator's
responsibility.
