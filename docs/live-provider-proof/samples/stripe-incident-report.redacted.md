# Stripe Incident Report Sample

Sample status: redacted public shape only.

Provider proof status: manual Stripe test-mode proof, not provider
certification. This is not provider certification.

## Summary

| Field | Value |
|-------|-------|
| Provider | Stripe |
| Event type | `payment_intent.succeeded` |
| Provider event ID | `evt_redacted` |
| Source ID | `src_redacted` |
| Incident ID | `inc_redacted` |
| Report schema | `webhookery.incident_report.v1` |

## Verification

| Field | Value |
|-------|-------|
| Signature result | `valid` |
| Signature header | omitted |
| Timestamp window | five minutes |
| Raw payload | omitted |
| Raw payload SHA-256 | `sha256:redacted` |

## Delivery Timeline

| Sequence | State | Evidence |
|----------|-------|----------|
| 1 | captured | durable receipt and raw payload metadata stored |
| 2 | verified | Stripe signature accepted |
| 3 | routed | route version `rtv_redacted` matched |
| 4 | failed | receiver returned a test `500` |
| 5 | dead_lettered | retry policy exhausted in proof environment |
| 6 | redelivery_requested | operator replay reason `receiver_fixed` |
| 7 | succeeded | replay delivery returned test `204` |

## Replay Evidence

| Field | Value |
|-------|-------|
| Replay job | `rpl_redacted` |
| Reason code | `receiver_fixed` |
| Reason | receiver fixed in Stripe proof environment |
| Config mode | `original` |
| Original event mutation | none |

## Evidence Bundle

| Field | Value |
|-------|-------|
| Bundle ID | `exp_redacted` |
| Manifest schema | `webhookery.evidence_bundle.v1` |
| Manifest SHA-256 | `sha256:redacted` |
| Audit-chain verification | valid in private proof |

## Non-Claims

- Raw payload bodies, webhook secrets, provider signatures, tenant IDs, and
  customer data are omitted.
- This sample is not provider certification.
- This sample does not prove provider-side event completeness.
- This sample does not claim exactly-once delivery.
