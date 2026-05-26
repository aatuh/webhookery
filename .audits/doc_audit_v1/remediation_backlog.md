# Backlog

Project: Webhookery documentation remediation v1

Status legend:

- [ ] not done
- [x] done

## Epic E1 - Stabilize Documentation Entry Points [x]

Description: Make the documentation source-of-truth clear before rewriting deeper docs. This epic removes stale guidance and gives readers a reliable first path through the repository.

### Ticket E1-T1 - Update Agent And Source-Of-Truth Guidance [x]

Description: Rewrite `AGENTS.md` so it reflects the current implementation-bearing repository and no longer claims the repo is pre-implementation.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Audit evidence: `AGENTS.md:20-24` and `AGENTS.md:103-110` are stale.

### Ticket E1-T2 - Rewrite README As The Primary Entry Point [x]

Description: Reduce `README.md` to product framing, implementation status, local quickstart, shortest smoke path, security promise, and links to canonical docs.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Move the long command list out of `README.md:24-113` instead of deleting useful commands.

### Ticket E1-T3 - Add A Canonical Documentation Map [x]

Description: Add a lean docs map in README or `docs/index.md` that names each canonical document, its audience, purpose, and source-of-truth boundary.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Keep the map short. Do not duplicate command lists or route catalogs.

### Ticket E1-T4 - Reclassify The Initial Design Document [x]

Description: Clarify whether `.initial_design.md` is historical design input or a maintained architecture reference, then add the minimum context needed to prevent misuse.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Audit evidence: `.initial_design.md:7-9` reads as prompt critique rather than maintained architecture documentation.

## Epic E2 - Split And Tighten Operator Documentation [x]

Description: Turn the overloaded operations runbook into maintainable operator documentation without losing the security-sensitive operational details.

### Ticket E2-T1 - Extract Canonical Configuration Reference [x]

Description: Create or designate one configuration reference for environment variables, defaults, safe production values, secrets, and process applicability.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Align `.env.example`, `.api.env.example`, `.test.env.example`, Helm values, and Kubernetes Secret examples.

### Ticket E2-T2 - Restructure Operations Around Runbooks [x]

Description: Rewrite `docs/operations.md` as a runbook-focused document for production doctor, RC checks, backup/restore, incident triage, audit verification, and recovery.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Preserve durable-capture, audit-chain, restore, raw-payload, and secret-redaction guidance.

### Ticket E2-T3 - Move Feature Behavior Reference Out Of The Runbook [x]

Description: Move dense feature behavior sections for auth, delivery, reconciliation, transformations, retention, signal egress, identity, producer trust, and SSRF into clearer reference sections or separate docs.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Do not create many tiny docs. Group by reader task and maintenance boundary.

### Ticket E2-T4 - Consolidate Non-Claims And Security Promise Language [x]

Description: Establish one canonical non-claims/security-promise section and replace repeated prose elsewhere with short links or references.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Keep legal, security, support, commercial, and trademark docs focused on their own audience.

## Epic E3 - Improve API, CLI, SDK, And Collection Task Support [x]

Description: Make the API-first product usable from contracts, CLI commands, SDKs, and request collections without forcing readers through the operations monolith.

### Ticket E3-T1 - Add OpenAPI Navigation And Common Contract Detail [x]

Description: Add OpenAPI tags, operation IDs, common error responses, and representative examples for high-value workflows without changing API behavior.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Preserve `openapi.yaml` as canonical and keep `sdk/openapi.yaml` aligned.

### Ticket E3-T2 - Create CLI Reference From Current Command Groups [x]

Description: Move the README command catalog into a CLI reference organized by command group, required scope, example, expected outcome, and elevated-risk action.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Prefer generated or command-verified content where practical so docs do not drift from `cmd/whcp`.

### Ticket E3-T3 - Expand SDK README For All Committed SDKs [x]

Description: Update `sdk/README.md` with Go, Python, and TypeScript setup, auth handling, basic event ingestion, audit-chain verification, and error-redaction notes.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Keep examples minimal and avoid showing real secrets.

### Ticket E3-T4 - Document Request Collection Smoke Paths [x]

Description: Add collection usage notes for Postman and Bruno, including local variables, placeholder signatures, expected responses, and what each smoke request proves.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Do not expand collections into full API coverage unless a real reader task requires it.

## Epic E4 - Strengthen Deployment And Release Documentation [x]

Description: Make the self-hosted RC posture clearer across Compose, Kubernetes, Helm, Terraform, release evidence, and restore workflows.

### Ticket E4-T1 - Write Common Deployment Posture Guidance [x]

Description: Add or designate one common deployment guide that explains external dependencies, TLS/ingress, secret custody, object storage, network policy, readiness, backup/restore, upgrade, and rollback expectations.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Keep profile-specific READMEs concise and link to the common guide.

### Ticket E4-T2 - Rewrite Kubernetes, Helm, And Terraform Profile READMEs [x]

Description: Update deployment profile READMEs with prerequisites, validation commands, secrets boundary, migration job behavior, image pinning, and links to operations/config references.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Avoid duplicating the same production-hardening text in three profile docs.

### Ticket E4-T3 - Normalize Release Evidence Documentation [x]

Description: Make `docs/release-evidence-template.md` the clear canonical release evidence artifact and reduce duplicated release-gate prose elsewhere.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Keep root `RELEASE_EVIDENCE.md` as a short router if useful.

### Ticket E4-T4 - Add Migration And Schema Operations Overview [x]

Description: Add a concise schema/migration overview for DB reviewers and operators, focused on migration ordering, rollback stance, evidence-authority tables, and restore compatibility risk.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- This should summarize migration practice, not duplicate every SQL table definition.

## Epic E5 - Add Documentation Maintenance Discipline [ ]

Description: Reduce future drift by documenting ownership, freshness checks, provider-claim review, and validation expectations.

### Ticket E5-T1 - Document Provider Claim Freshness Rules [x]

Description: Add a rule for dated provider-specific claims that records owner, review cadence, official source links, and how stale claims should be updated.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Current dated claims include provider behavior checked on May 25, 2026.

### Ticket E5-T2 - Add Documentation Review Checklist [x]

Description: Add a short checklist for documentation changes covering audience, doc type, source of truth, examples, command validation, security claims, and non-claim consistency.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Place this where contributors and agents will actually see it.

### Ticket E5-T3 - Align Documentation Checks With The New Structure [ ]

Description: Update documentation-adjacent validation so `make docs-check` continues to verify canonical docs, derived OpenAPI/SDK artifacts, collections, deployment docs, and required metadata after the split.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- This ticket depends on the earlier structural tickets so checks point at final canonical paths.
