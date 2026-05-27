# Pilot Feedback Template

Use this template for sanitized Webhookery evaluator and pilot feedback.

Do not include secrets, raw payloads, customer data, provider credentials,
database URLs with passwords, private keys, raw signatures, bearer tokens,
session cookies, or exploit payloads.

## Summary

- Organization / team:
- Contact owner:
- Date:
- Webhookery version / commit:
- Deployment mode:
- Evaluation status: `not_started | running | blocked | completed | abandoned`

## Environment

- Hosting environment:
- PostgreSQL responsibility:
- Object storage mode:
- Secret-box mode:
- TLS / mTLS requirements:
- Expected event volume range:
- Retention requirements:

## Provider Mix

List providers and event types without real payload data.

| Provider | Event families | Verification requirement | Reconciliation need |
| --- | --- | --- | --- |
| Stripe | | | |
| GitHub | | | |
| Shopify | | | |
| Slack | | | |
| Internal producers | | | |

## Current Pain

- Incident or failure mode:
- Existing replay process:
- Existing audit/evidence process:
- Existing self-hosting or procurement constraint:
- Why current tooling is insufficient:

## Evaluation Results

- Evaluator quickstart completed: `yes | no`
- Evidence demo completed: `yes | no`
- `make rc-check` completed: `yes | no`
- Production doctor completed: `yes | no`
- Provider conformance reviewed: `yes | no`
- Release evidence reviewed: `yes | no`

## Blockers

| Severity | Blocker | Evidence path | Desired outcome |
| --- | --- | --- | --- |
| blocker / warning / note | | | |

## Security And Review Requirements

- Required security review artifacts:
- Required deployment evidence:
- Required support or SLA expectations:
- Required commercial license scope:
- Data residency or retention constraints:

## Commercial Intent

- Need commercial license exception: `yes | no | unknown`
- Need paid support: `yes | no | unknown`
- Need production-readiness review: `yes | no | unknown`
- Need custom provider adapter/integration: `yes | no | unknown`
- Timeline:

## Follow-Up Classification

Classify each follow-up as one of:

- docs gap
- bug
- evaluator friction
- missing provider compatibility
- paid custom integration
- general roadmap candidate
- out of scope

## Decision

- Owner:
- Next action:
- Due date:
- Accepted risk, if any:
- Link to sanitized issue or backlog item:
