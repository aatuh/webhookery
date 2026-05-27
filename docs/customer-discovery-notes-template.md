# Customer Discovery Notes Template

Use this template for early Webhookery discovery calls before a formal pilot.
For pilot execution feedback, use `docs/pilot-feedback-template.md`.

Do not record secrets, raw payloads, provider credentials, customer data,
private keys, bearer tokens, raw signatures, session cookies, exploit payloads,
or database URLs with passwords.

## Call Metadata

- Date:
- Interviewer:
- Organization / team:
- Contact:
- Segment:
- Permission to follow up: `yes | no`
- Public reference permission: `yes | no | later`

## Current Webhook Surface

- Providers used:
- Internal producers:
- Approximate monthly event volume:
- Critical event types:
- Existing webhook tooling:
- Existing self-hosting requirements:

## Pain And Incidents

- Recent webhook incident:
- Hardest question to answer during incidents:
- Current replay process:
- Current audit/evidence process:
- Current provider reconciliation process:
- Cost of a missed, duplicated, or late event:

## Security And Procurement

- Required deployment model:
- Data residency requirements:
- Security review requirements:
- License constraints:
- Support or SLA expectations:
- Budget owner:

## Fit Assessment

| Signal | Notes |
| --- | --- |
| Needs durable capture evidence | |
| Needs replay/DLQ/retry control | |
| Needs provider-aware verification | |
| Needs self-hosting | |
| Needs commercial license exception | |
| Needs production-readiness review | |
| Hosted vendor is a better fit | |
| Simpler internal tool is enough | |

## Next Step

- Suggested next action:
- Owner:
- Due date:
- Discovery classification: `docs gap | bug | evaluator friction | pilot candidate | paid custom integration | roadmap candidate | out of scope`
- Evidence required before engineering work:

## Sanitization Check

Before storing or sharing these notes, confirm:

- no secrets
- no raw payloads
- no customer data
- no provider credentials
- no exploit payloads
- no database credentials
