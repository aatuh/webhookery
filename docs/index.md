# Webhookery Documentation Map

Use this map to find the canonical document for a task. Prefer editing the
owner document for a topic and linking to it from secondary docs.

| Document | Audience | Purpose | Source-of-truth boundary |
|----------|----------|---------|--------------------------|
| `README.md` | New readers, evaluators, developers | Product framing, current implementation status, local quickstart, and first smoke paths. | Entry point only. Do not maintain long command catalogs, route catalogs, or deployment runbooks here. |
| `AGENTS.md` | Coding agents and maintainers | Repository operating rules, implementation loop, security classification, and validation expectations. | Agent guidance only. It must reflect current repo evidence. |
| `.initial_design.md` | Maintainers, architects, agents | Historical design input, product framing, architecture rationale, and intended direction. | Not proof of implemented behavior. Current code, contracts, migrations, and maintained docs override it. |
| `openapi.yaml` | API consumers, SDK maintainers, reviewers | Canonical REST API contract. | API paths, schemas, status codes, auth schemes, and examples. |
| `sdk/openapi.yaml` | SDK maintainers | SDK-ready OpenAPI copy. | Derived from `openapi.yaml`; keep aligned with `make sdk-generate` and `make sdk-check`. |
| `cmd/`, `internal/`, `pkg/` | Developers, reviewers | Go implementation for processes, app logic, adapters, and public helpers. | Implemented behavior. Docs must not claim behavior not supported by these files. |
| `migrations/` | DB reviewers, operators, developers | PostgreSQL schema evolution. | Database schema history and migration ordering. |
| `Makefile` | Contributors, CI maintainers, release operators | Project-owned commands and validation gates. | Command names and check composition. Confirm with `make help`. |
| `docs/configuration.md` | Operators, deployment maintainers, contributors | Environment variables, defaults, safe production values, secret sensitivity, and process applicability. | Canonical configuration reference. Keep env examples and deployment profile references aligned here. |
| `docs/operations.md` | Self-hosted operators and SREs | Production doctor, RC checks, backup/restore, incident triage, audit verification, and recovery guidance. | Operator runbooks. Avoid moving API reference or command catalogs back into this file. |
| `docs/feature-behavior.md` | Maintainers, API reviewers, security reviewers, operators | Implemented behavior reference for capture, auth, routing, delivery, replay, reconciliation, transformations, retention, identity, producer trust, and SSRF. | Behavior summary. Code, OpenAPI, and migrations remain exact. |
| `docs/security-promise.md` | All readers | Durable-capture promise, security invariants, and canonical non-claims. | Canonical non-claims reference. Link here instead of repeating caveat lists. |
| `docs/cli.md` | Operators and developers using `whcp` | CLI command reference and moved README command catalog. | Human CLI reference. `cmd/whcp` remains exact behavior. |
| `sdk/README.md` | SDK users and maintainers | Committed SDK artifact guidance. | SDK usage and artifact expectations. |
| `collections/README.md` and `collections/` | API evaluators, operators | Postman and Bruno smoke request usage, local variables, placeholder signatures, and expected smoke responses. | Smoke examples, not full API coverage. |
| `docker-compose.yml` | Local developers, evaluators | Local API, worker, migration, PostgreSQL, and optional MinIO topology. | Local runtime example. Not production deployment guidance. |
| `docs/deployment.md` | Self-hosted operators, platform teams | Common deployment posture for dependencies, TLS/ingress, secret custody, object storage, network policy, readiness, backup/restore, upgrades, and rollback. | Shared production expectations. Profile READMEs own exact profile commands. |
| `deploy/kubernetes/`, `deploy/helm/`, `deploy/terraform/` | Platform operators | Profile-specific deployment manifests, chart, and Terraform module. | Deployment profile specifics. Common production posture belongs in shared deployment docs. |
| `docs/security-review-package.md` | Security reviewers | Artifact map, trust boundaries, review controls, and exit criteria. | Security review packet. It should route to canonical implementation and operations docs. |
| `docs/release-evidence-template.md` | Release managers, security reviewers | Canonical release evidence checklist and template. | Release evidence requirements. Other docs should link here instead of duplicating gates. |
| `RELEASE_EVIDENCE.md` | Release readers | Short router to the release evidence template. | Current release evidence pointer, not a parallel checklist. |
| `SECURITY.md` | Security researchers | Vulnerability reporting policy and sensitive-data handling. | Reporting process. Keep project architecture details elsewhere. |
| `CONTRIBUTING.md` | Contributors | Contribution policy, checks, and sensitive-data rules. | Contribution entry point. Link to canonical docs for details. |
| `GOVERNANCE.md` | Maintainers, contributors, commercial users | Decision model, maintainer role, and invariant governance. | Governance policy, not operations reference. |
| `SUPPORT.md` | Users and customers | Public and private support paths. | Support policy and sensitive-data warning. |
| `COMMERCIAL.md` | Commercial users | AGPL and commercial licensing boundary. | Business and licensing information. |
| `TRADEMARKS.md` | Forks, redistributors, commercial users | Naming and trademark guidance. | Trademark policy only. |

## Maintenance Rule

When a behavior changes, update the smallest canonical source first:

1. Code, OpenAPI, migrations, deployment profile, or executable script.
2. The owning documentation page from the table above.
3. Short links or summaries in secondary docs.

Do not duplicate environment tables, command catalogs, route lists, provider
semantics, release gates, or non-claim language unless one document is clearly
named as the owner.
