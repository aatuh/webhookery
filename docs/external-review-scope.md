# External Review Scope Template

Use one completed copy per external security or production-maturity review.
Do not include real API keys, webhook secrets, bearer tokens, session cookies,
private keys, provider credentials, raw payload bodies, raw signatures,
database URLs with real credentials, customer data, exploit payloads, or
unredacted logs in public review packages.

## Review Identity

- Review name:
- Reviewer organization:
- Review owner:
- Start date:
- End date:
- Commit or tag:
- Deployment profile reviewed:
- Evidence package location:
- Status: `planned|in_progress|complete|accepted_risk|blocked`

## Scope

Include:

- API, worker, scheduler, migration, CLI, and minimal UI code.
- PostgreSQL migrations and store methods.
- Provider verification, normalization, reconciliation, and recovery paths.
- Outbound delivery, notification, and SIEM egress.
- Authentication, sessions, producer OAuth, producer mTLS, OIDC, SCIM, RBAC,
  ABAC, and API-key behavior.
- Secret custody modes: local, Vault Transit, and AWS KMS envelope encryption.
- Raw payload/object storage, retention, audit exports, audit chains, anchors,
  and bundle verification.
- Docker Compose, Dockerfile, Kubernetes, Helm, Terraform, CI, release, and
  evidence scripts.

Exclude unless explicitly contracted:

- Live provider accounts or customer receivers.
- Legal evidentiary certification.
- Compliance certification.
- External timestamping services.
- Multi-region active-active deployment.
- SAML, HSM/PKCS#11, marketplace plugins, Kafka/NATS backends, or vendor-
  specific notification apps.

## Review Questions

- Can Webhookery return success before durable capture under any configured
  mode?
- Can raw bytes be mutated before provider signature verification?
- Can unverified provider payloads route by default?
- Can one tenant read, export, replay, mutate, or infer another tenant's data?
- Can secrets, raw payloads, signatures, tokens, URL credentials, or private
  key material leak through logs, errors, UI, CLI, metrics, exports, backups,
  or CI artifacts?
- Can SSRF controls be bypassed at endpoint create/test/delivery time?
- Can replay, DLQ release, retention, reconciliation, or audit export be abused
  without authorization and audit evidence?
- Can audit-chain or bundle tampering be detected?
- Are migration, restore, and rollback boundaries explicit and rehearsable?

## Required Evidence

- `make finalize` output.
- `make release-acceptance` output.
- `make rc-check` output with and without `WEBHOOKERY_TEST_DATABASE_URL` where
  feasible.
- `make perf-smoke` output from disposable local PostgreSQL.
- `make provider-conformance-check` output.
- Backup/restore drill output when persistence or evidence behavior changed.
- SBOM, vulnerability, gosec, Trivy, Docker build, and OpenAPI/SDK checks.
- Production doctor output with secrets redacted.
- Branch protection status or accepted-risk record.

## Exit Criteria

Broad production-maturity language is allowed only when findings are fixed or
recorded in `docs/external-review-accepted-risks.md` with owner, severity,
expiry, mitigation, and release-blocking decision.
