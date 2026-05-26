# Backlog

Project: Webhookery

Status legend:

- [ ] not done
- [x] done

## Epic E1 - Evidence Integrity And Contract Safety [x]

Description: Close the highest-risk correctness gaps around raw evidence discoverability and API contract drift before structural refactors.

### Ticket E1-T1 - Link Duplicate Raw Payload Evidence [x]

Description: Ensure duplicate inbound raw payload rows remain discoverable through receipts, timelines, retention, and body-inclusive exports.

Implementation rules:

- implement the ticket in the smallest sensible step
- add DB-backed tests proving duplicate raw payloads are exported or explicitly represented as receipt-linked evidence
- preserve canonical event dedupe behavior and do not mutate original event history
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E1-T2 - Add Router And OpenAPI Parity Checks [x]

Description: Replace the current `/openapi.yaml` smoke check with a real contract check that compares registered routes/methods against `openapi.yaml`.

Implementation rules:

- implement the ticket in the smallest sensible step
- make the check deterministic and non-mutating so it can run from `make openapi-check`
- include high-risk request/response examples for ingest, raw reads, replay, exports, auth, alerts, notification, SIEM, and producer token endpoints
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E1-T3 - Strengthen Evidence Export Tests [x]

Description: Add DB-backed export tests for raw payload bodies, duplicate receipts, delivery payloads, normalized envelopes, provider API evidence, and audit-chain proof files.

Implementation rules:

- implement the ticket in the smallest sensible step
- require `WEBHOOKERY_TEST_DATABASE_URL` for DB-backed export assertions
- assert body permission gates and `410 Gone` retained-body behavior
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

## Epic E2 - Authorization Enforcement Consistency [ ]

Description: Make resource-aware role bindings and access policies the enforcement path for sensitive workflows while preserving fixed-role compatibility.

### Ticket E2-T1 - Introduce A Central Authorization Service [x]

Description: Add a single application-layer authorization service that wraps baseline `authz.Can`, role bindings, access policies, scopes, tenant checks, and explain logging.

Implementation rules:

- implement the ticket in the smallest sensible step
- deny by default when tenant, actor, action, or resource context is missing
- preserve all existing fixed role and scoped API-key behavior
- add unit tests for allow, deny, wildcard, resource id, environment, scope, and wrong-tenant decisions
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E2-T2 - Wire Authorization Service Into Control Methods [x]

Description: Replace direct `authz.Can` calls in management workflows with the central authorization service.

Implementation rules:

- implement the ticket in dependency order after `E2-T1`
- cover sources, endpoints, subscriptions, routes, schemas, events, deliveries, replay, audit, retention, ops, alerts, notifications, SIEM, identity, producer trust, and adapter registry paths
- keep body access elevated and audited
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E2-T3 - Add Resource Policy Regression Tests [ ]

Description: Add wrong-tenant, denied-policy, allowed-binding, and scope-limited tests for every sensitive resource family.

Implementation rules:

- implement the ticket in dependency order after `E2-T2`
- include negative tests for raw payload reads, replay creation, audit export payload inclusion, endpoint production changes, notification mutation, SIEM mutation, and secret rotation
- assert explain output does not leak secrets, payload bodies, sessions, or provider tokens
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

## Epic E3 - Hexagonal Boundary Repair [ ]

Description: Reduce the blast radius of core changes by moving orchestration out of infrastructure adapters and splitting god files into cohesive modules.

### Ticket E3-T1 - Split Store Ports By Use Case [ ]

Description: Replace the monolithic `ControlStore` shape with smaller interfaces for source, endpoint, route, event, delivery, replay, audit, identity, ops, signal, and reconciliation use cases.

Implementation rules:

- implement the ticket in the smallest sensible step
- keep public behavior unchanged
- avoid moving SQL and business logic in the same patch unless required for compile safety
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E3-T2 - Move Delivery Fanout Orchestration Into App Services [ ]

Description: Move route/subscription matching, transformation selection, payload snapshot creation decisions, and replay fanout policy out of `postgres.Store`.

Implementation rules:

- implement the ticket after `E3-T1`
- leave SQL persistence focused on storing and claiming records
- preserve delivery payload hashes, route evidence, replay config modes, and live-over-replay priority
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E3-T3 - Move Reconciliation Orchestration Out Of Postgres Store [ ]

Description: Move provider scan, lookup, redelivery, and recovered-event orchestration into an application reconciliation service.

Implementation rules:

- implement the ticket after `E3-T1`
- keep provider HTTP adapters outside persistence packages
- preserve provider API evidence hashes, recovered-event semantics, redelivery audit evidence, and cursor behavior
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E3-T4 - Split HTTP And CLI Entrypoint Files [ ]

Description: Split `server.go` and `cmd/whcp/main.go` into cohesive resource and command files without changing routes or flags.

Implementation rules:

- implement the ticket after high-risk behavior fixes
- keep route registration explicit and easy to compare with OpenAPI
- preserve CLI flags, exit behavior, file permissions, and redaction guarantees
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

## Epic E4 - Runtime Resilience And Startup Safety [ ]

Description: Improve operational isolation so one subsystem failure or backfill cannot degrade unrelated core product work.

### Ticket E4-T1 - Isolate Worker Phases [ ]

Description: Change worker execution so delivery, retention, metrics, alerts, notification, and SIEM phases report independent results instead of returning on the first subsystem error.

Implementation rules:

- implement the ticket in the smallest sensible step
- preserve at-least-once semantics and existing retry state
- add tests proving one phase failure does not prevent independent phases from running
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E4-T2 - Make Audit Chain Backfill Explicit And Bounded [ ]

Description: Move audit-chain backfill out of automatic store construction into an explicit migration/admin/scheduler path with leases and bounded progress.

Implementation rules:

- implement the ticket after adding characterization tests for current backfill behavior
- avoid startup-time unbounded scans in API and worker processes
- preserve idempotence and deterministic `occurred_at, id` ordering
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E4-T3 - Add Trusted Proxy Policy For Session Metadata [ ]

Description: Stop trusting `X-Forwarded-For` unconditionally and add explicit trusted-proxy configuration for OIDC session IP metadata.

Implementation rules:

- implement the ticket in the smallest sensible step
- default to `RemoteAddr` unless a configured trusted proxy boundary applies
- do not accept proxy-supplied mTLS or auth identity headers
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

## Epic E5 - Persistence Test Quality [ ]

Description: Replace static persistence assertions with behavior-level confidence for tenant isolation, migrations, SQL constraints, and failure boundaries.

### Ticket E5-T1 - Convert Highest-Risk Static Store Tests To DB Tests [ ]

Description: Convert static tests for source/endpoint/route/subscription CRUD, alerts, notification, SIEM, retry policy, and audit chain into live Postgres tests.

Implementation rules:

- implement the ticket incrementally by resource family
- require `WEBHOOKERY_TEST_DATABASE_URL` and skip cleanly when absent
- include wrong-tenant negatives and transaction assertions
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E5-T2 - Add Migration Upgrade And Idempotence Tests [ ]

Description: Add integration tests that migrate a clean database, re-run migrations, and validate key constraints/indexes through SQL behavior.

Implementation rules:

- implement the ticket after `E5-T1` starts the DB test helper pattern
- verify additive migration safety for key tables and indexes
- do not rely only on checksum or source-string checks
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E5-T3 - Add CI Artifact For DB-Backed RC Evidence [ ]

Description: Upload a concise integration evidence artifact from the GitHub integration workflow showing migrations, RC E2E, and skipped restore-drill status.

Implementation rules:

- implement the ticket after DB tests are reliable
- keep artifacts free of database URLs, secrets, raw payload bodies, and customer data
- preserve no-live-provider/cloud-credential CI behavior
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
