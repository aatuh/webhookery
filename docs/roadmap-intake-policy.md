# Roadmap Intake Policy

Webhookery roadmap decisions should come from repeated evidence, product fit,
security risk, and commercial value. Do not add broad platform features simply
because they appear in a single pilot conversation.

## Intake Categories

Classify each request as one of:

- docs gap
- bug
- evaluator friction
- missing provider compatibility
- production hardening
- paid custom integration
- commercial packaging
- general roadmap candidate
- enterprise/future
- out of scope

## Decision Rules

### Docs Gap

Use when behavior exists but the evaluator could not find or trust it.

Action: update the canonical doc and link secondary docs.

### Bug

Use when implemented behavior fails its documented promise.

Action: reproduce, add a regression test, fix, run `make finalize`, and create
a Conventional Commit.

### Evaluator Friction

Use when the product works but setup, quickstart, demo, release evidence, or
commercial path is unclear.

Action: improve the evaluator path before adding features.

### Missing Provider Compatibility

Use when a provider-specific behavior is needed for a real evaluation.

Action: verify official provider docs, define test vectors, and avoid claiming
generic provider completeness.

### Paid Custom Integration

Use when the request is valuable for one customer but not yet general product
scope.

Action: define a written scope, acceptance criteria, support boundary, and
commercial terms before implementation.

### General Roadmap Candidate

Use when the request appears across multiple evaluators or closes a clear
production-respectable core gap.

Action: create a focused backlog with evidence, non-goals, tests, and release
impact.

### Enterprise/Future

Use for broader capabilities such as marketplace plugins, hosted service,
multi-region coordination, SAML, HSM/PKCS#11, vendor-specific notification
apps, or compliance certification.

Action: keep labeled as future unless repeated paid demand and architecture
evidence justify a separate phase.

## Required Evidence

Before promoting an item to general roadmap, capture:

- affected buyer segment
- repeated user evidence or signed customer scope
- current workaround
- failure or opportunity cost
- security and tenant-isolation impact
- documentation impact
- release evidence impact

## Non-Negotiable Boundaries

Roadmap items must not weaken:

- durable capture before inbound success
- at-least-once delivery language
- tenant isolation
- provider-specific verification
- raw payload permission gates
- SSRF-safe endpoint handling
- audit/replay evidence
- secret and PII redaction
- no exactly-once claim
- no provider-side completeness guarantee
- no compliance certification claim
