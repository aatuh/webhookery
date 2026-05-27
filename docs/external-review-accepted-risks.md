# External Review Accepted Risks

This file tracks accepted risks that affect production-maturity claims. It is a
template and current registry. Do not include exploit payloads, raw payload
bodies, secrets, private keys, bearer/session tokens, provider credentials, raw
signatures, customer data, or database URLs with real credentials.

Release evidence must copy relevant rows into the release-specific evidence
package. A risk with missing owner, expiry, mitigation, or release decision is
not accepted.

## Current Registry

| ID | Source | Severity | Risk | Owner | Expiry | Mitigation | Release decision |
|----|--------|----------|------|-------|--------|------------|------------------|
| _none_ |  |  |  |  |  |  |  |

## Status Values

- `pass`: reviewed and closed.
- `fail`: unresolved and release-blocking.
- `blocked`: review cannot complete because evidence or access is missing.
- `skipped`: only allowed when copied into release evidence as accepted risk.
- `accepted_risk`: owner, expiry, mitigation, and decision are recorded.

## Non-Certification Boundary

Accepted risk tracking does not make Webhookery compliance-certified, legally
evidentiary-certified, or externally timestamped. It only records release
decisions for controlled self-hosted adoption.
