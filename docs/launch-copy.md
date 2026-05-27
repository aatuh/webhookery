# Launch Copy Templates

These drafts are prepared copy only. Do not post them externally until the
`v0.1.0-rc1` release, release evidence, static landing page, and evaluator
quickstart are live and verified.

## GitHub Release Announcement

Title:

```text
Webhookery v0.1.0-rc1: self-hosted webhook evidence infrastructure
```

Body:

```text
Webhookery v0.1.0-rc1 is a release candidate for teams evaluating self-hosted
webhook evidence infrastructure.

It focuses on durable capture before inbound success, provider-aware
verification, signed delivery, retry/DLQ/replay evidence, retention, evidence
exports, provider conformance checks, audit-chain verification, and
release-candidate acceptance gates.

Start here:
- Evaluator quickstart: docs/evaluator-quickstart.md
- Local evidence demo: examples/webhook-evidence-demo/
- Release evidence template: docs/release-evidence-template.md
- Provider conformance: docs/provider-conformance.md
- Commercial evaluation: docs/commercial-evaluation.md

Non-claims:
- no exactly-once delivery
- no provider-side event completeness guarantee
- no compliance certification
- no hosted-service availability

This release uses local/fake provider acceptance tests. It does not call live
providers or customer receivers.
```

## Self-Hosted Community Post

```text
I released Webhookery v0.1.0-rc1, a self-hosted webhook evidence and delivery
control plane.

The angle is not "another webhook gateway." It is evidence: durable capture
before success, provider signature verification, delivery attempts, replay,
DLQ, retention, audit-chain verification, and release evidence.

It is for teams that need to prove what happened to webhook events and prefer
self-hosting over a managed platform.

Good fit:
- regulated or security-reviewed SaaS/platform teams
- internal platform teams receiving provider webhooks
- teams that need replay/audit evidence and commercial license exceptions

Not a fit:
- teams wanting a hosted managed service
- teams expecting exactly-once delivery
- teams expecting provider-side completeness guarantees

Quickstart: docs/evaluator-quickstart.md
Demo: examples/webhook-evidence-demo/
Commercial path: docs/commercial-evaluation.md
```

## Direct Outreach

```text
Subject: Self-hosted webhook evidence/replay control plane

Hi {name},

I am looking for teams with webhook incident, replay, audit, or self-hosting
requirements to evaluate Webhookery.

Webhookery is a self-hosted webhook evidence and delivery control plane. It is
designed around durable capture before inbound success, provider verification,
delivery evidence, replay, retention, and audit-chain verification.

The first release candidate includes a local fake-provider demo and release
evidence package so your team can inspect the trust boundaries before any
commercial discussion.

Useful links:
- quickstart: docs/evaluator-quickstart.md
- release notes: docs/releases/v0.1.0-rc1.md
- security promise: docs/security-promise.md
- commercial evaluation: docs/commercial-evaluation.md

This is not a hosted service and does not claim exactly-once delivery or
provider-side completeness. It is for teams that need self-hosted evidence and
operational control.

Would it be useful to compare this against your current webhook incident and
replay workflow?
```

## Product Launch Channel

```text
Webhookery is self-hosted webhook evidence infrastructure.

It helps teams receive, verify, store, route, deliver, replay, audit, and debug
webhooks while keeping the loss boundaries explicit.

What it proves:
- whether Webhookery durably captured an event
- whether provider verification passed
- which route matched
- which delivery attempts happened
- whether retry, DLQ, replay, retention, and audit evidence exists

What it does not claim:
- exactly-once delivery
- provider-side event completeness
- downstream business success
- compliance certification

Try the local release-candidate demo: docs/evaluator-quickstart.md
```

## Posting Checklist

- [ ] `v0.1.0-rc1` release exists.
- [ ] Release evidence artifacts are attached or linked.
- [ ] Static landing page is linked.
- [ ] Evaluator quickstart works from a clean checkout.
- [ ] No secrets, raw payloads, provider credentials, or customer data appear.
- [ ] Non-claims are present.
- [ ] Commercial CTA is direct but not spammy.
