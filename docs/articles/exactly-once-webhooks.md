# Exactly-Once Webhooks Are The Wrong Goal

Webhook systems should not promise exactly-once delivery. Networks retry,
providers send duplicates, receivers time out after doing work, and operators
eventually replay events during incidents.

The production goal should be evidence, idempotency, and explicit recovery.

## Better Promise

Webhookery uses this narrower promise:

> If Webhookery returns inbound success, the configured durable capture path has
> recorded evidence. Loss boundaries remain explicit, and recovery/replay
> actions are auditable.

This is stronger than a vague "never lose a webhook" claim because it states
what the system can and cannot prove.

## Failure Modes That Break Exactly-Once Claims

- provider retries after network or timeout failures
- receiver completes work but returns a timeout
- duplicate provider event IDs
- manual provider redelivery
- operator replay
- route or transformation changes between original delivery and replay
- retention deleting raw bodies while preserving metadata and hashes
- provider-side gaps that can only be reconciled when provider APIs allow it

## What To Build Instead

Use:

- durable capture before inbound success
- exact raw body preservation
- provider-specific signature verification
- idempotency keys and dedupe evidence
- delivery attempt history
- DLQ and replay with reason capture
- audit-chain verification
- provider reconciliation where possible
- receiver-side idempotency for business effects

## Webhookery Evaluation

Run:

```bash
examples/webhook-evidence-demo/run.sh
make rc-check
```

Then review:

- `docs/security-promise.md`
- `docs/provider-conformance.md`
- `docs/release-evidence-template.md`

Webhookery does not claim exactly-once delivery. It is designed to make
duplicates, retries, replay, and loss boundaries visible.
