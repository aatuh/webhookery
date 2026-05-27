# Webhookery Documentation Map

Use this map to find the canonical document for a task. Prefer editing the
owner document for a topic and linking to it from secondary docs.

| Document | Audience | Purpose | Source-of-truth boundary |
|----------|----------|---------|--------------------------|
| `README.md` | New readers, evaluators, developers | Product framing, current implementation status, local quickstart, and first smoke paths. | Entry point only. Do not maintain long command catalogs, route catalogs, or deployment runbooks here. |
| `site/index.html` | Evaluators, commercial buyers | Static product landing page for Webhookery positioning, quickstart CTA, commercial path, and non-goals. | Public landing surface. Keep operational detail in docs. |
| `AGENTS.md` | Coding agents and maintainers | Repository operating rules, implementation loop, security classification, and validation expectations. | Agent guidance only. It must reflect current repo evidence. |
| `.initial_design.md` | Maintainers, architects, agents | Historical design input, product framing, architecture rationale, and intended direction. | Not proof of implemented behavior. Current code, contracts, migrations, and maintained docs override it. |
| `openapi.yaml` | API consumers, SDK maintainers, reviewers | Canonical REST API contract. | API paths, schemas, status codes, auth schemes, and examples. |
| `sdk/openapi.yaml` | SDK maintainers | SDK-ready OpenAPI copy. | Derived from `openapi.yaml`; keep aligned with `make sdk-generate` and `make sdk-check`. |
| `cmd/`, `internal/`, `pkg/` | Developers, reviewers | Go implementation for processes, app logic, adapters, and public helpers. | Implemented behavior. Docs must not claim behavior not supported by these files. |
| `migrations/` | DB reviewers, operators, developers | PostgreSQL schema evolution. | Database schema history and migration ordering. |
| `docs/schema-migrations.md` | DB reviewers, operators, release managers | Migration runner behavior, ordering, evidence-authority tables, rollback stance, and restore compatibility review. | Human operations guide for schema changes. Exact DDL remains in `migrations/`. |
| `Makefile` | Contributors, CI maintainers, release operators | Project-owned commands and validation gates. | Command names and check composition. Confirm with `make help`. |
| `docs/configuration.md` | Operators, deployment maintainers, contributors | Environment variables, defaults, safe production values, secret sensitivity, and process applicability. | Canonical configuration reference. Keep env examples and deployment profile references aligned here. |
| `docs/operations.md` | Self-hosted operators and SREs | Production doctor, RC checks, backup/restore, incident triage, audit verification, and recovery guidance. | Operator runbooks. Avoid moving API reference or command catalogs back into this file. |
| `docs/evaluator-quickstart.md` | Evaluators | Guided local path from checkout to failed-payment incident packet, bundle verification, and RC checks. | Tutorial. Do not turn it into a full operations guide. |
| `examples/webhook-evidence-demo/` | Evaluators, demo authors | Deterministic local evidence demo and synthetic fixtures. | Demo fixtures only. Do not store real provider/customer data here. |
| `docs/demo-media-checklist.md` | Maintainers, marketers, demo authors | Safety checklist for screenshots, GIFs, short videos, and slide material. | Media safety checklist. It is not product behavior documentation. |
| `docs/day-2-operations.md` | Self-hosted operators and SREs | Post-install backup cadence, restore drills, upgrades, incident triage, alert handling, key rotation, retention review, and audit evidence handoff. | Day-2 operating guide. Link to command references instead of duplicating them. |
| `docs/feature-behavior.md` | Maintainers, API reviewers, security reviewers, operators | Implemented behavior reference for capture, auth, routing, delivery, replay, reconciliation, transformations, retention, identity, producer trust, and SSRF. | Behavior summary. Code, OpenAPI, and migrations remain exact. |
| `docs/security-promise.md` | All readers | Durable-capture promise, security invariants, and canonical non-claims. | Canonical non-claims reference. Link here instead of repeating caveat lists. |
| `docs/stability.md` | Release managers, operators, API consumers | Semver, API/CLI compatibility, migration compatibility, support windows, and deprecation rules. | Stability and compatibility policy. Keep release evidence and versioning claims aligned here. |
| `docs/performance-envelope.md` | Operators, release managers, platform teams | Local performance smoke usage, capacity inputs, storage growth, and sizing caveats. | Performance evidence interpretation. It is not an SLA or benchmark certification. |
| `docs/provider-conformance.md` | Release managers, provider-adapter reviewers, security reviewers | Dated provider support matrix, local vector evidence, official-doc source list, and unsupported recovery limits. | Provider conformance evidence. It does not prove live provider completeness. |
| `docs/observability.md` | Self-hosted operators and platform teams | Public metric names, Prometheus scrape example, alert rule examples, and dashboard starter panels. | Observability examples. Public metrics remain aggregate-only. |
| `docs/documentation-maintenance.md` | Contributors, maintainers, agents | Provider-claim freshness rules, official source registry, and documentation maintenance discipline. | Documentation maintenance policy. |
| `docs/cli.md` | Operators and developers using `whcp` | CLI command reference and moved README command catalog. | Human CLI reference. `cmd/whcp` remains exact behavior. |
| `sdk/README.md` | SDK users and maintainers | Committed SDK artifact guidance. | SDK usage and artifact expectations. |
| `collections/README.md` and `collections/` | API evaluators, operators | Postman and Bruno smoke request usage, local variables, placeholder signatures, and expected smoke responses. | Smoke examples, not full API coverage. |
| `docker-compose.yml` | Local developers, evaluators | Local API, worker, migration, PostgreSQL, and optional MinIO topology. | Local runtime example. Not production deployment guidance. |
| `docs/deployment.md` | Self-hosted operators, platform teams | Common deployment posture for dependencies, TLS/ingress, secret custody, object storage, network policy, readiness, backup/restore, upgrades, and rollback. | Shared production expectations. Profile READMEs own exact profile commands. |
| `deploy/kubernetes/`, `deploy/helm/`, `deploy/terraform/` | Platform operators | Profile-specific deployment manifests, chart, and Terraform module. | Deployment profile specifics. Common production posture belongs in shared deployment docs. |
| `docs/security-review-package.md` | Security reviewers | Artifact map, trust boundaries, review controls, and exit criteria. | Security review packet. It should route to canonical implementation and operations docs. |
| `docs/external-review-package.md` | External reviewers, maintainers, release managers | Public index for external review inputs, questions, outputs, and release impact. | External review router. Sensitive review evidence stays outside public source. |
| `docs/external-review-scope.md` | External reviewers, maintainers, release managers | Scope, exclusions, review questions, required evidence, and exit criteria for external maturity review. | Review planning template. Store completed sensitive evidence outside public source. |
| `docs/external-review-findings-template.md` | External reviewers, maintainers, release managers | Finding tracker template with severity, ownership, release-blocking decision, and closure fields. | Finding tracking template. Do not store exploit material or secrets. |
| `docs/external-review-accepted-risks.md` | Maintainers, release managers | Accepted-risk registry and status vocabulary for release decisions. | Public sanitized registry. Release-specific evidence owns exact decision copies. |
| `docs/release-evidence-template.md` | Release managers, security reviewers | Canonical release evidence checklist and template. | Release evidence requirements. Other docs should link here instead of duplicating gates. |
| `docs/release-evidence-sample.md` | Release managers, evaluators, security reviewers | Public example of a completed release evidence packet. | Reader aid only. Keep required fields in `docs/release-evidence-template.md`. |
| `docs/production-rc-checklist.md` | Release managers, operators | Ordered release-candidate readiness checklist for controlled self-hosted adoption. | RC checklist. Link to canonical operations docs instead of duplicating runbooks. |
| `docs/releases/v0.1.0-rc1.md` | Evaluators, release managers, commercial reviewers | First release-candidate notes, implemented behavior, limitations, and validation commands. | Release-specific narrative. Keep canonical release gates in `docs/release-evidence-template.md`. |
| `RELEASE_EVIDENCE.md` | Release readers | Short router to the release evidence template. | Current release evidence pointer, not a parallel checklist. |
| `SECURITY.md` | Security researchers | Vulnerability reporting policy and sensitive-data handling. | Reporting process. Keep project architecture details elsewhere. |
| `CONTRIBUTING.md` | Contributors | Contribution policy, checks, and sensitive-data rules. | Contribution entry point. Link to canonical docs for details. |
| `GOVERNANCE.md` | Maintainers, contributors, commercial users | Decision model, maintainer role, and invariant governance. | Governance policy, not operations reference. |
| `SUPPORT.md` | Users and customers | Public and private support paths. | Support policy and sensitive-data warning. |
| `COMMERCIAL.md` | Commercial users | AGPL and commercial licensing boundary. | Business and licensing information. |
| `docs/commercial-evaluation.md` | Commercial evaluators | Evaluation path, starting ranges, required inputs, and safe information boundaries. | Commercial evaluation guide. It is not legal advice. |
| `docs/production-readiness-review.md` | Commercial evaluators, operators | Paid production-readiness review scope, inputs, outputs, and limits. | Review-offer guide. It is not certification. |
| `docs/support-packages.md` | Users and customers | Support options, starting ranges, request quality, and non-claims. | Support package guide. Contract terms override public examples. |
| `docs/comparisons/build-vs-buy.md` | Evaluators, buyers | Decision guide for self-hosting Webhookery vs hosted vendors or simpler internal tools. | Buyer-fit comparison. Not a benchmark or legal recommendation. |
| `docs/comparisons/hookdeck.md` | Evaluators, buyers | Factual buyer-fit comparison against Hookdeck based on dated official-source review. | Comparison page. Re-check official sources before publishing externally. |
| `docs/comparisons/svix.md` | Evaluators, buyers | Factual buyer-fit comparison against Svix based on dated official-source review. | Comparison page. Re-check official sources before publishing externally. |
| `docs/comparisons/convoy.md` | Evaluators, buyers | Factual buyer-fit comparison against Convoy based on dated official-source review. | Comparison page. Re-check official sources before publishing externally. |
| `docs/articles/exactly-once-webhooks.md` | Evaluators, practitioners | Educational article explaining why Webhookery designs for evidence, replay, and idempotency instead of exactly-once claims. | Educational content. Keep aligned with `docs/security-promise.md`. |
| `docs/articles/webhook-incident-report.md` | Operators, incident responders | Educational article and report outline for webhook incidents. | Educational content. Do not store real incident data here. |
| `docs/articles/webhook-failure-modes.md` | Operators, evaluators | Educational article about webhook loss boundaries and operational checks. | Educational content. Keep provider claims aligned with conformance docs. |
| `docs/articles/self-hosted-webhook-gateway-architecture.md` | Evaluators, architects, security reviewers | Educational architecture article covering PostgreSQL-first capture, OpenAPI, payload evidence, and audit-chain verification. | Educational content. Exact behavior remains in code, OpenAPI, migrations, and operations docs. |
| `docs/articles/webhook-security-review-checklist.md` | Security reviewers, platform teams | SaaS webhook security-review checklist for inbound trust, producer auth, tenant isolation, SSRF, secrets, and release evidence. | Checklist. It is not certification or legal advice. |
| `docs/launch-copy.md` | Maintainers, launch authors | Draft public launch copy for release announcement, communities, outreach, and product channels. | Prepared copy only. Do not treat as approval to post. |
| `docs/launch-metrics.md` | Maintainers, commercial operators | Privacy-safe launch measurement plan focused on qualified evaluations. | Metrics plan. Does not add runtime analytics. |
| `docs/customer-discovery-notes-template.md` | Maintainers, commercial operators | Sanitized early discovery-call template before a formal pilot. | Discovery notes template. Do not store secrets or customer data. |
| `docs/pilot-feedback-template.md` | Maintainers, commercial operators | Sanitized template for evaluator and pilot feedback. | Feedback template. Do not store secrets or customer data. |
| `docs/roadmap-intake-policy.md` | Maintainers | Policy for classifying pilot feedback into docs, bugs, paid work, roadmap, future, or out-of-scope. | Roadmap discipline. Does not override product invariants. |
| `docs/pilot-review-checklist.md` | Maintainers | Checklist for reviewing pilot findings and choosing the next engineering slice. | Review checklist. Keep production claims evidence-backed. |
| `TRADEMARKS.md` | Forks, redistributors, commercial users | Naming and trademark guidance. | Trademark policy only. |

## Maintenance Rule

When a behavior changes, update the smallest canonical source first:

1. Code, OpenAPI, migrations, deployment profile, or executable script.
2. The owning documentation page from the table above.
3. Short links or summaries in secondary docs.

Do not duplicate environment tables, command catalogs, route lists, provider
semantics, release gates, or non-claim language unless one document is clearly
named as the owner.
