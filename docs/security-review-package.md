# External Security Review Package

This reference document tells an external reviewer which artifacts define the
current Webhookery security and production-readiness posture. It is a router,
not a substitute for source inspection.

## Architecture Summary

- Product and architecture reference: `.initial_design.md`.
- Contract source: `openapi.yaml` and `sdk/openapi.yaml`.
- Runtime entry point: `cmd/whcp`.
- Domain/application code: `internal/domain`, `internal/app`, and
  provider-specific packages under `internal/`.
- Adapters: `internal/adapters/postgres`, HTTP API/UI adapters, delivery HTTP
  adapters, storage adapters, secret-box adapters, and metrics adapters.
- Public verifier helpers: `pkg/verifier`.
- Database authority: `migrations/`.
- Local runtime: `docker-compose.yml`.
- Deployment image: `Dockerfile`.
- Operations and recovery runbook: `docs/operations.md`.
- Release-candidate harness: `scripts/rc_acceptance.sh`.

## Threat Model Focus

Review at least these trust boundaries:

- external provider to ingress API,
- internal producer to event ingestion API,
- management API/UI to tenant resources,
- worker processes to PostgreSQL, object storage, queues, and egress network,
- delivery workers to customer-controlled URLs,
- operators to replay, quarantine, secrets, exports, audit, SIEM, and
  notification controls,
- tenant-to-tenant isolation for every list, read, write, replay, export, and
  delivery action.

Review at least these controls:

- durable capture before inbound success,
- exact raw-byte preservation before provider verification,
- provider-specific signature verification and timestamp windows,
- duplicate evidence preservation and dedupe behavior,
- outbound delivery signing, retry, DLQ, and replay semantics,
- SSRF validation at endpoint create/test/delivery time,
- raw payload, delivery payload, export, SIEM, metric, and log redaction,
- API-key, producer OAuth, OIDC, SCIM, session, RBAC, ABAC, and mTLS
  authorization boundaries,
- local, Vault Transit, and AWS KMS secret custody modes,
- audit-chain continuity, anchors, retention interaction, and export proofs,
- reconciliation gap evidence and provider API credential handling,
- alert notification and SIEM egress signing,
- Docker/Compose startup, readiness, production doctor output, and backup
  restore behavior.

## Evidence Bundle

Include these artifacts in the review package:

- `openapi.yaml`
- `sdk/openapi.yaml`
- `docs/operations.md`
- `docs/release-evidence-template.md`
- latest exact-tag release evidence file
- `migrations/`
- provider verification test vectors, if present
- `pkg/verifier/`
- `scripts/rc_acceptance.sh`
- SBOMs, Trivy output, `govulncheck`, and `gosec` outputs from the release
  workflow
- sanitized `make rc-check` output
- sanitized backup/restore drill output

## Review Exit Criteria

Broad production-readiness language should wait until review findings are fixed
or recorded as accepted risks with owner, severity, expiry, and mitigation in
the release evidence.

This repository still makes no exactly-once delivery claim, no provider-side
event completeness guarantee, no compliance certification claim, no legal
evidentiary certification claim, no external timestamping claim, and no
managed-service availability claim.
