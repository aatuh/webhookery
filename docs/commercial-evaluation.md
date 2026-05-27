# Commercial Evaluation

Webhookery is publicly available under `AGPL-3.0-only`. Commercial license
exceptions and paid evaluation packages are available for organizations that
need proprietary use rights, deployment review, release evidence, or contracted
support.

This page is business guidance, not legal advice. Have counsel review AGPL and
any commercial agreement before relying on it.

## Evaluation Path

1. Run `docs/evaluator-quickstart.md`.
2. Review `docs/pilot-topology.md`, `docs/security-promise.md`,
   `docs/provider-conformance.md`, and `docs/release-evidence-template.md`.
3. Identify provider mix, deployment topology, data sensitivity, evidence
   packet needs, and support expectations.
4. Request a commercial evaluation through the contact path in `COMMERCIAL.md`.
5. Agree scope, deliverables, support boundary, license exception, and
   non-claims in writing.

## Webhookery Evidence Pilot

The recommended paid pilot shape is:

```text
Webhookery Evidence Pilot -- 14 days
Connect one provider, one downstream receiver, one failure scenario,
one replay workflow, and one evidence export.
```

Pilot deliverables:

- deployment topology review against `docs/pilot-topology.md`;
- provider setup and verification review for the agreed provider;
- failure/replay drill using a synthetic or sanitized event;
- generated incident evidence packet;
- evidence bundle verification result;
- production-readiness gap report;
- accepted-risk and non-claim review; and
- commercial license/support recommendation.

Out of scope unless agreed in writing:

- live provider certification;
- compliance or legal evidentiary certification;
- managed-service availability;
- multi-region active-active operation;
- broad marketplace/plugin work;
- provider-side completeness guarantees; and
- exactly-once delivery claims.

## Starting Ranges

These are starting ranges for planning. Final pricing depends on scope,
deployment risk, support expectations, and written agreement.

| Offer | Starting range | Typical outcome |
| --- | ---: | --- |
| Commercial Evaluation | EUR 490-1,000 | Fit review, self-hosting path, license discussion, and next-step recommendation. |
| Webhookery Evidence Pilot | Fixed scope | One provider, one receiver, one failure/replay drill, one incident evidence packet, and a production-readiness gap report. |
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
- accepted or requested changes to `docs/pilot-topology.md`
- PostgreSQL and object-storage responsibility model
- security review requirements
- failure/replay scenario to test
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
- completed `docs/pilot-evidence-template.md` for a scoped pilot
- production-readiness review scope
- commercial license exception proposal
- support package proposal
- implementation backlog for agreed custom work

The evaluation does not change Webhookery's canonical non-claims in
`docs/security-promise.md`.
