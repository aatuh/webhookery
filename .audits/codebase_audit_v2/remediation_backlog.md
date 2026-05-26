# Backlog

Project: Webhookery

Status legend:

- [ ] not done
- [x] done

## Epic E1 - Ingress Trust Semantics [x]

Description: Ensure public provider ingress never turns structural payload validity into trusted side-effecting work without cryptographic verification or an explicit unsafe policy.

### Ticket E1-T1 - Separate CloudEvents Validity From Verification [x]

Description: Change CloudEvents handling so a structurally valid unsigned CloudEvents payload is captured as evidence but is not marked `signature_verified=true` and cannot fan out as trusted work by default.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Cover `internal/provider/provider.go`, `internal/app/service.go`, and `internal/app/delivery_fanout.go`.
- Preserve durable capture for malformed or unsigned CloudEvents where current ack policy allows evidence capture.

### Ticket E1-T2 - Add Explicit Unsafe Routing Policy Tests [x]

Description: Add negative tests proving unsigned CloudEvents do not create deliveries, plus policy tests for any intentionally allowed unsafe/archive-only routing mode.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Include provider-level, ingest-service, and delivery-fanout coverage.
- Update OpenAPI/docs only if the public contract changes.

## Epic E2 - SSRF-Safe Egress Dialing [x]

Description: Bind SSRF validation to the actual outbound connection for customer-controlled endpoint, notification, and SIEM URLs.

### Ticket E2-T1 - Implement Pinned-IP HTTP Transport [x]

Description: Add an egress transport that resolves the hostname, validates every resolved IP against policy, dials an allowed IP, and preserves the original Host/SNI semantics.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Keep redirects disabled or revalidate every redirect target before following it.
- Include DNS rebinding, private CIDR, metadata IP, IPv4-mapped IPv6, and IDNA cases.

### Ticket E2-T2 - Use Shared Safe Egress In Delivery And Signal Clients [x]

Description: Wire the pinned egress transport into `deliveryhttp` and `signalhttp`, including worker runtime construction.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Cover customer deliveries, notification channels, and SIEM sinks.
- Keep response truncation and signing behavior unchanged.

## Epic E3 - Durable Audit Evidence [x]

Description: Make audit evidence for sensitive control-plane actions required, transactional, or durably recoverable.

### Ticket E3-T1 - Replace Best-Effort Audit Writes For Sensitive Actions [x]

Description: Update state-changing and evidence-sensitive store methods so audit write failure is returned or captured through a durable audit outbox instead of ignored.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Prioritize API key revocation, delivery retry/cancel, audit export download, dead-letter release, quarantine approval/rejection, and replay state changes.
- Keep read-only audit behavior explicit if reads intentionally remain best-effort.

### Ticket E3-T2 - Add Audit Failure Injection Tests [x]

Description: Add tests that force audit persistence failure and assert sensitive actions do not silently succeed without audit evidence.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Prefer focused fake-store tests for app behavior and live Postgres tests for transaction behavior.
- Ensure audit-chain updates remain compatible with existing chain verification.

## Epic E4 - Concurrent Duplicate Capture [ ]

Description: Preserve raw duplicate evidence and provider receipts even when duplicate webhook deliveries arrive concurrently.

### Ticket E4-T1 - Make Dedupe Capture Atomic [x]

Description: Refactor inbound capture to avoid the select-then-insert race on `(tenant_id, dedupe_key)` while still linking duplicate raw payloads and receipts to the first event.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Consider `INSERT ... ON CONFLICT`, row-level locks, or an idempotency/dedupe record lock.
- Preserve one routing outbox item for the canonical event and evidence rows for every receipt.

### Ticket E4-T2 - Add Live Postgres Concurrency Regression Test [ ]

Description: Add an integration test that sends concurrent duplicate captures and verifies one event, multiple raw payloads, multiple provider receipts, and no failed duplicate response.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Use `WEBHOOKERY_TEST_DATABASE_URL`.
- Keep the test deterministic and isolated by tenant/source identifiers.

## Epic E5 - Maintainability And Persistence Test Depth [ ]

Description: Reduce future change risk around the largest modules and improve the live persistence safety net.

### Ticket E5-T1 - Split PostgreSQL Store By Resource Family [ ]

Description: Move related PostgreSQL methods into smaller files by resource family while preserving public store interfaces and behavior.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Do this after the audit, SSRF, and dedupe fixes have tests.
- Avoid behavior changes in the file split.

### Ticket E5-T2 - Add A Documented Live-Postgres Quality Gate [ ]

Description: Make live PostgreSQL integration coverage easier to run consistently and document exactly when it is required.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Align docs, Makefile, and CI naming around `WEBHOOKERY_TEST_DATABASE_URL`.
- Keep non-live `make fast-check` usable for local iteration.
