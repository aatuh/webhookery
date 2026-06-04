# Live-Provider Proof Run Record Template

Use this template for private Stripe, GitHub, or Shopify proof runs. Store the
completed record with private release or pilot evidence, not in public source
control.

Do not commit completed run records, raw payloads, provider signatures,
webhook secrets, bearer tokens, customer data, private repository data,
development-store customer data, database URLs, or private evidence bundles.

## Run Metadata

| Field | Value |
|-------|-------|
| Provider | `stripe | github | shopify` |
| Proof guide version / commit | |
| Run date | |
| Operator | |
| Environment | `local | pilot | disposable test` |
| Provider account/repository/store | private reference only |
| Webhookery version / commit | |
| Webhookery deployment profile | |

## Scope And Non-Claims

- Proof scope:
- Provider event type or topic:
- Downstream receiver behavior:
- Replay path tested:
- Evidence bundle generated: `yes | no`

Confirm before using this run as release or pilot evidence:

- not provider certification;
- no provider-side completeness guarantee;
- no exactly-once delivery claim;
- no downstream business-success claim; and
- no compliance certification claim.

## Setup Evidence

| Check | Result | Evidence location |
|-------|--------|-------------------|
| Provider proof guide followed | `pass | fail | skipped` | |
| Provider secret created only for test proof | `pass | fail | skipped` | |
| Webhookery source configured | `pass | fail | skipped` | |
| Receiver route configured | `pass | fail | skipped` | |
| Receiver starts in failing mode | `pass | fail | skipped` | |
| Private proof output directory created | `pass | fail | skipped` | |

## Capture And Verification

| Check | Result | Evidence location |
|-------|--------|-------------------|
| Provider delivered event to Webhookery | `pass | fail | skipped` | |
| Inbound response returned only after durable capture | `pass | fail | skipped` | |
| Provider signature verified as valid | `pass | fail | skipped` | |
| Raw payload body omitted from shared artifacts | `pass | fail | skipped` | |
| Event timeline includes capture and verification | `pass | fail | skipped` | |
| Provider delivery identity captured when available | `pass | fail | skipped` | |

## Failure, Replay, And Incident Evidence

| Check | Result | Evidence location |
|-------|--------|-------------------|
| Downstream failure recorded | `pass | fail | skipped` | |
| Retry or DLQ state visible | `pass | fail | skipped` | |
| Replay dry-run completed | `pass | fail | skipped` | |
| Replay or DLQ release completed with reason code | `pass | fail | skipped` | |
| Original event remained immutable | `pass | fail | skipped` | |
| Incident created and event attached | `pass | fail | skipped` | |
| Markdown incident report generated | `pass | fail | skipped` | |
| Evidence bundle generated | `pass | fail | skipped` | |
| `whcp audit verify-bundle` passed | `pass | fail | skipped` | |

## Sanitization Review

Use `docs/live-provider-proof/stripe-redaction-policy.md` before sharing any
sample outside the private evidence location.

| Check | Result | Evidence location |
|-------|--------|-------------------|
| Secret-shaped strings removed | `pass | fail | skipped` | |
| Raw signatures removed | `pass | fail | skipped` | |
| Raw payload bodies removed | `pass | fail | skipped` | |
| Provider/customer/private repository data removed | `pass | fail | skipped` | |
| Public sample states required non-claims | `pass | fail | skipped` | |
| `make provider-proof-check` passed after sample edits | `pass | fail | skipped` | |

## Outcome

- Run status: `passed | failed | partial | abandoned`
- External evidence location:
- Public sample updated: `yes | no`
- Follow-up issue or private tracker link:
- Release or pilot decision:
- Accepted risk, if any:
