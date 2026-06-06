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
| AR-2026-06-08-001 | `v0.2.0-pilot` release evidence | Medium | `master` branch protection is not enabled and no repository ruleset is configured. | Maintainer | 2026-07-31 | Keep `v0.2.0-pilot` positioned as a pilot prerelease only; require public CI/security/release workflow evidence; use `CODEOWNERS` for review routing; enable branch protection or equivalent ruleset before broader production positioning. | accepted_risk for `v0.2.0-pilot`; blocks broad production-readiness language |
| AR-2026-06-08-002 | `v0.2.0-pilot` release evidence | Medium | External security or production-readiness review is not completed. | Maintainer | 2026-07-31 | Keep release language limited to controlled self-hosted pilot evaluation; use public checks, provider conformance, proof guides, and release evidence; complete or explicitly scope external review before broader production positioning. | accepted_risk for `v0.2.0-pilot`; blocks broad production-readiness language |

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
