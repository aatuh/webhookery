# GitHub Incident Report Sample

Sample status: redacted public shape only.

Provider proof status: manual test-repository proof, not provider
certification. This is not provider certification.

## Summary

| Field | Value |
|-------|-------|
| Provider | GitHub |
| Event type | `push` |
| Delivery GUID | `00000000-0000-0000-0000-000000000000` |
| Source ID | `src_redacted` |
| Incident ID | `inc_redacted` |
| Report schema | `webhookery.incident_report.v1` |

## Verification

| Field | Value |
|-------|-------|
| Signature header | `X-Hub-Signature-256` present, value omitted |
| Signature result | `valid` |
| Raw payload | omitted |
| Raw payload SHA-256 | `sha256:redacted` |
| Event header | `X-GitHub-Event: push` |

## Delivery And Dedupe Timeline

| Sequence | State | Evidence |
|----------|-------|----------|
| 1 | captured | durable receipt and raw payload metadata stored |
| 2 | verified | GitHub signature accepted |
| 3 | routed | route version `rtv_redacted` matched |
| 4 | failed | receiver returned a test `500` |
| 5 | duplicate_visible | manual GitHub redelivery reused delivery GUID |
| 6 | redelivery_requested | operator replay reason `receiver_fixed` |
| 7 | succeeded | Webhookery replay delivery returned test `204` |

## Replay Evidence

| Field | Value |
|-------|-------|
| Replay job | `rpl_redacted` |
| Reason code | `receiver_fixed` |
| Reason | receiver fixed in GitHub proof environment |
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
  repository-private data are omitted.
- This sample is not provider certification.
- This sample does not prove provider-side event completeness.
- This sample does not claim exactly-once delivery.
