# Governance

Webhookery is currently maintainer-led.

## Maintainer

The project maintainer is Aatu Harju.

Commercial, support, trademark, security, or governance questions can be routed
through LinkedIn:

<https://www.linkedin.com/in/aatu-harju>

## Decision Model

The maintainer has final decision authority over:

- roadmap and release scope,
- license and commercial terms,
- security response,
- contribution acceptance,
- release evidence requirements,
- trademark and naming permission,
- claims and non-claims, with `docs/security-promise.md` as the canonical
  reference,
- provider support boundaries.

Large changes should preserve the project’s core invariants:

- inbound success means durable capture, not downstream business success,
- raw request bytes and headers are preserved before parsing or trust,
- provider verification uses exact raw bytes and provider-specific rules,
- delivery remains at-least-once and is not described as exactly once,
- duplicates stay visible as evidence,
- replay creates new work and never mutates original history,
- every primary resource is tenant-scoped,
- customer endpoint URLs are hostile input until validated and revalidated,
- secrets, raw payloads, bearer/session tokens, provider credentials, private
  keys, and unnecessary PII are not logged or exported,
- compliance and legal-evidence language stays conservative and aligned with
  `docs/security-promise.md`.

## Commercial Boundary

The public repository remains available under AGPL. Separate commercial license
exceptions, support agreements, release evidence packages, and self-hosted
support packages are handled outside the public issue tracker unless the
maintainer explicitly chooses otherwise.

Commercial work does not broaden the canonical non-claims in
`docs/security-promise.md` unless a signed agreement explicitly narrows scope
for that engagement.
