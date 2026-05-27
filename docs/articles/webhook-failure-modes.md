# Webhook Failure Modes

Webhook reliability work starts with admitting where failure can happen.
Webhookery is designed to preserve evidence after receipt, not to claim control
over every provider or network boundary.

## Common Failure Modes

| Failure mode | Evidence-oriented response |
| --- | --- |
| Provider never sends the event | Reconciliation may detect gaps only where provider APIs allow it. |
| Webhook reaches Webhookery but storage is down | Do not return inbound success. |
| Signature is invalid | Store rejection/quarantine evidence where feasible and do not route by default. |
| Duplicate event arrives | Preserve duplicate evidence and use dedupe to suppress processing where configured. |
| Receiver times out | Record attempt evidence and retry according to policy. |
| Receiver succeeds after timeout | Receiver-side idempotency must handle duplicate business effects. |
| Retries exhaust | Move to DLQ with evidence and operator recovery path. |
| Operator replays event | Create new delivery work with reason and audit evidence. |
| Raw body is retained/deleted | Preserve metadata, hashes, receipts, and audit records. |

## What Webhookery Controls

- durable capture before inbound success
- provider verification evidence
- routing and delivery decisions
- retry and DLQ state
- replay authorization and reason capture
- retention metadata
- audit-chain verification
- evidence export contents

## What Webhookery Does Not Control

- provider-side event existence
- DNS or network failures before receipt
- downstream business processing
- customer receiver idempotency
- operator-managed backup quality
- external compliance certification

## Operator Checks

Use:

```bash
make provider-conformance-check
make rc-check
make release-acceptance
```

For production-style evaluation with a disposable database:

```bash
WEBHOOKERY_TEST_DATABASE_URL=postgres://... make rc-check
```

Review `docs/operations.md` and `docs/day-2-operations.md` before relying on a
self-hosted deployment.
