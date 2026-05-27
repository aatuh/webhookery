# Commercial Evaluation

Webhookery is publicly available under `AGPL-3.0-only`. Commercial license
exceptions and paid evaluation packages are available for organizations that
need proprietary use rights, deployment review, release evidence, or contracted
support.

This page is business guidance, not legal advice. Have counsel review AGPL and
any commercial agreement before relying on it.

## Evaluation Path

1. Run `docs/evaluator-quickstart.md`.
2. Review `docs/security-promise.md`, `docs/provider-conformance.md`, and
   `docs/release-evidence-template.md`.
3. Identify provider mix, deployment topology, data sensitivity, and support
   expectations.
4. Request a commercial evaluation through the contact path in `COMMERCIAL.md`.
5. Agree scope, deliverables, support boundary, license exception, and
   non-claims in writing.

## Starting Ranges

These are starting ranges for planning. Final pricing depends on scope,
deployment risk, support expectations, and written agreement.

| Offer | Starting range | Typical outcome |
| --- | ---: | --- |
| Commercial Evaluation | EUR 490-1,000 | Fit review, self-hosting path, license discussion, and next-step recommendation. |
| Release Evidence Package | EUR 2,500-5,000 | Release artifact review, SBOM/check evidence, known limits, and accepted-risk summary. |
| Production Readiness Review | EUR 7,500-12,500 | Deployment, backup/restore, security, retention, observability, and incident-readiness review. |
| Commercial License + Support | EUR 9,900-24,900 per year | Written license exception plus agreed support and update channel. |
| Custom Integration / Provider Adapter | Fixed scope or EUR 150-250/hour | Provider adapter, evidence workflow, deployment hardening, or receiver integration work. |

No SLA, compliance certification, legal evidence certification, hosted service,
or provider-side completeness guarantee is included unless a written agreement
explicitly says so.

## Required Inputs

Provide only sanitized information:

- expected provider list and event volume range
- self-hosting environment summary
- PostgreSQL and object-storage responsibility model
- security review requirements
- required support window
- desired license exception scope
- blocker list from local evaluation

Do not send API keys, bearer tokens, webhook secrets, raw signatures, private
keys, provider credentials, raw customer payloads, customer data, database URLs
with passwords, or exploit payloads.

## Evaluation Output

A commercial evaluation can produce:

- fit/non-fit recommendation
- deployment-risk notes
- evidence-package recommendation
- production-readiness review scope
- commercial license exception proposal
- support package proposal
- implementation backlog for agreed custom work

The evaluation does not change Webhookery's canonical non-claims in
`docs/security-promise.md`.
