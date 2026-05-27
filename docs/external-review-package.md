# External Review Package

This document is the public index for external review material. It does not
replace a paid or private security review, and it must not contain secrets,
raw payloads, exploit payloads, customer data, provider credentials, private
keys, bearer tokens, session cookies, or database URLs with passwords.

## Review Inputs

| Artifact | Purpose |
| --- | --- |
| `README.md` | Product summary and evaluator routing. |
| `docs/security-promise.md` | Core promise, security invariants, and non-claims. |
| `docs/feature-behavior.md` | Implemented behavior summary. |
| `docs/provider-conformance.md` | Dated provider support and limitations. |
| `docs/release-evidence-template.md` | Required release evidence fields and gates. |
| `docs/release-evidence-sample.md` | Public example of a completed release packet. |
| `docs/external-review-scope.md` | Scope template for independent review. |
| `docs/external-review-findings-template.md` | Finding tracker template. |
| `docs/external-review-accepted-risks.md` | Public sanitized accepted-risk registry. |
| `docs/articles/webhook-security-review-checklist.md` | Security-review checklist for SaaS reviewers. |

## Review Questions

- Does Webhookery preserve raw evidence before trust?
- Can the reviewer reproduce durable capture and invalid-signature rejection
  with local fakes?
- Are tenant boundaries explicit in code, API, docs, and tests?
- Are secrets redacted from logs, errors, CLI output, UI, docs, and release
  artifacts?
- Are replay, retention, audit export, audit-chain verification, reconciliation,
  and signal egress claims supported by repository evidence?
- Are non-claims preserved in public docs and release notes?

## Review Outputs

External review output should be tracked in a sanitized package:

- review scope
- reviewed commit/tag
- findings
- fixed findings
- accepted risks with owner, expiry, and mitigation
- release-blocking decision
- production-maturity language review

Private exploit details, credentials, customer evidence, and raw payloads should
remain outside public source control.

## Release Impact

Broad production-maturity language is blocked unless critical/high findings are
fixed or explicitly accepted with owner, expiry, mitigation, and release
decision.
