# Production Readiness Review

The production readiness review is a paid engagement for organizations
evaluating Webhookery in controlled self-hosted environments.

It is not a compliance certification, legal evidence certification, penetration
test, hosted-service SLA, or guarantee of provider-side event completeness.

## Review Scope

Typical review areas:

- deployment topology and network boundaries
- PostgreSQL backup, restore, migration, and retention posture
- object-storage configuration for raw payload evidence
- secret-box mode and key-custody responsibilities
- provider conformance and provider-specific limitations
- raw payload and PII exposure controls
- replay, DLQ, retention, evidence export, and audit-chain operations
- production doctor output
- performance smoke output and sizing assumptions
- observability, alerts, notification, and SIEM signal paths
- incident triage and restore drills

## Inputs

The customer provides sanitized evidence:

- completed evaluator quickstart result
- `make rc-check` output against a disposable environment
- production doctor output with secrets redacted
- deployment diagram without private credentials
- backup/restore procedure summary
- provider list and expected event volume range
- support and incident expectations

Do not provide secrets, customer payloads, private keys, raw signatures, bearer
tokens, session cookies, provider credentials, or database URLs with passwords.

## Outputs

Expected outputs:

- readiness summary
- release/evidence gap list
- blocker/warning classification
- accepted-risk recommendations
- operational runbook improvements
- support or custom-work recommendation

Findings are scoped to the reviewed deployment and date. They do not certify
all future releases, all provider behavior, all cloud environments, or all
customer integrations.

## Starting Range

Production Readiness Review starts at EUR 7,500-12,500, depending on scope,
deployment complexity, provider mix, and expected support follow-up.
