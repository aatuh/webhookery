# Pilot Evidence Template

Use this template to record sanitized evidence from each Webhookery pilot.
Every completed pilot should produce one comparable packet that can be reviewed
without exposing secrets, raw payload bodies, provider signatures, customer
data, or production database URLs.

Do not store completed sensitive pilot evidence in the public repository unless
it has been explicitly redacted and reviewed.

## Summary

- Pilot name:
- Owner:
- Date range:
- Webhookery version / commit:
- Commercial scope or agreement reference:
- Pilot topology accepted: `yes | no`
- Link to `docs/pilot-topology.md` review:

## Deployment Topology

- Deployment mode: `Docker Compose | Helm | other`
- Region:
- PostgreSQL provider / responsibility:
- Raw payload storage mode: `postgres | s3`
- Object storage drill completed: `yes | no | not applicable`
- TLS / ingress owner:
- Backup owner:
- Alert / incident owner:
- Known topology gaps:

## Provider Connected

List provider families and event types without real payload data.

| Provider | Event families | Verification status | Live proof status | Notes |
| --- | --- | --- | --- | --- |
| Stripe | | | | |
| GitHub | | | | |
| Shopify | | | | |

## Event Volume Range

- Expected daily volume:
- Peak test volume:
- Retention target:
- Raw payload storage growth estimate:
- Explicit volume limits accepted:

## Failure Scenario Tested

- Scenario name:
- Event ID or incident ID:
- Downstream receiver behavior:
- Delivery attempts observed:
- DLQ state:
- Evidence path:

## Replay Scenario Tested

- Replay mode:
- Replay reason:
- Actor / role:
- Approval requirement, if any:
- Replay result:
- Evidence path:

## Evidence Packet

- Incident ID:
- Incident report generated: `yes | no`
- Evidence bundle generated: `yes | no`
- Bundle verification command:
- Verification result:
- Raw payload bodies included: `no | yes with elevated approval`
- Redaction review owner:

## Audit Chain

- `whcp audit verify-chain` result:
- `whcp audit verify-bundle` result:
- Audit-chain gaps:
- Evidence export ID:

## Restore Drill

- Restore drill status: `passed | failed | skipped`
- Database backup artifact:
- Restore target:
- Audit-chain verification after restore:
- Object storage caveat, if any:

## Known Gaps

| Severity | Gap | Owner | Mitigation | Expiry |
| --- | --- | --- | --- | --- |
| blocker / warning / note | | | | |

## Accepted Risks

- Risk:
- Owner:
- Expiry:
- Mitigation:
- Link to accepted-risk record:

## Commercial Follow-Up

- Fit recommendation:
- Production-readiness review needed: `yes | no`
- Commercial license exception needed: `yes | no`
- Support package recommendation:
- Custom integration work:
- Next action:

## Review

- Reviewed by:
- Review date:
- Linked `docs/pilot-review-checklist.md` decision:
- Sanitized issue or private tracker link:
