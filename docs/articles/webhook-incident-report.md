# Building A Webhook Incident Report

A useful webhook incident report should answer what happened, what was proven,
what could not be proven, and which recovery actions were taken.

Webhookery is designed to make that report easier to assemble from durable
evidence.

## Minimum Questions

- Did Webhookery receive the event?
- Which tenant, source, provider, and event ID were involved?
- Was the provider signature valid?
- What raw payload hash was stored?
- Which route and route version matched?
- Which endpoint was targeted?
- Was the delivery payload snapshotted?
- Which attempts were made?
- What response status and truncated response body were recorded?
- Did the event enter DLQ or quarantine?
- Was replay requested, by whom, and for what reason?
- Did retention delete bodies while preserving metadata and hashes?
- Does audit-chain verification still pass?

## Evidence Sources

Use:

- event detail and timeline APIs
- delivery attempts
- replay receipts
- DLQ and quarantine records
- retention run items
- audit events and audit-chain verification
- provider reconciliation jobs
- evidence exports
- release evidence for the deployed Webhookery version

## Report Shape

Recommended sections:

1. Summary.
2. Timeline.
3. Impacted provider/source/endpoints.
4. Evidence that was durably captured.
5. Delivery and retry outcome.
6. Replay or reconciliation actions.
7. What could not be proven.
8. Follow-up actions.

## Sensitive Data Boundary

Incident reports must not include API keys, bearer tokens, webhook secrets, raw
signatures, private keys, provider credentials, raw customer payloads, customer
PII, or database URLs with passwords unless the report is stored in a controlled
private incident system with explicit approval.

Public reports should use hashes, IDs, redacted metadata, and links to internal
evidence systems.
