# Webhook Security Review Checklist

Use this checklist when reviewing a Webhookery deployment, pilot, or fork.
It is written for SaaS security reviewers and platform teams. It is not legal
advice and does not certify a deployment.

Do not paste secrets, provider credentials, raw customer payloads, private keys,
bearer tokens, session cookies, raw signatures, or database URLs with passwords
into public issues, docs, or review packages.

## Inbound Provider Boundary

- Raw body is preserved before parsing or verification.
- Signature verification uses exact raw bytes.
- Timestamp or replay-window checks are enforced where provider semantics
  support them.
- Invalid signatures do not route to side-effecting destinations by default.
- Durable capture succeeds before any inbound success response.
- Storage failure returns non-success and does not leak secrets or payloads.

## Producer Boundary

- Product-event producers authenticate with scoped API keys, producer OAuth
  credentials, or verified producer mTLS identities.
- Producer credentials are tenant and source scoped where configured.
- Opaque tokens and client secrets are stored hashed or encrypted, not in
  plaintext.
- Revoked or expired credentials cannot ingest events.

## Tenant And Authorization Boundary

- Every list, read, update, export, replay, retry, and admin path is tenant
  scoped.
- Raw payload and transformed payload body reads require elevated permission
  and audit evidence.
- Replay requires authorization, reason capture, and rate controls.
- Security-sensitive changes are audited and explainable.

## Outbound Delivery Boundary

- Endpoint URLs are validated on create/update and revalidated at delivery.
- Private, loopback, link-local, metadata, multicast, and reserved addresses
  are blocked unless an explicit audited local/dev policy allows them.
- Redirects are not followed for delivery or signal egress.
- Delivery requests are signed over the exact payload bytes sent.
- Response bodies are truncated and redacted before storage.
- Receiver idempotency remains the receiver's responsibility.

## Secrets And Privacy

- Webhook secrets, endpoint signing secrets, API keys, OAuth client secrets,
  SCIM tokens, session tokens, object-store credentials, database passwords,
  and KMS details are redacted from logs, docs, UI, CLI output, and errors.
- Secret-box mode is configured deliberately for the environment.
- Key-custody mode and raw-storage mode are visible through redacted ops
  status and `whcp doctor production`.
- Demo and release artifacts use synthetic data only.

## Evidence And Retention

- Raw body hashes and payload hashes remain after body retention.
- Audit-chain entries are not deleted by normal audit-event retention.
- Evidence exports include manifests and file hashes.
- Body-inclusive exports require explicit intent and elevated permission.
- Retention policies preserve metadata, hashes, receipts, deliveries, attempts,
  and audit history.

## Operations And Release Evidence

- `make release-acceptance` passes.
- `make rc-check` passes locally, and DB-backed checks run with a disposable
  `WEBHOOKERY_TEST_DATABASE_URL` before production use.
- `make finalize`, `make gosec`, and `make vuln` pass for the release commit.
- Docker image digest, SBOMs, Trivy results, and release evidence are attached
  or linked from the release.
- Backup/restore drills have been rehearsed for the operator's deployment.
- Public metrics and dashboards do not include tenant labels or sensitive
  payload data.

## Review Exit Criteria

A production-style review should end with one of:

- approved for controlled self-hosted evaluation
- approved with accepted risks and owner/expiry/mitigation
- blocked until specific findings are fixed
- out of scope for Webhookery's current release-candidate maturity

Use `docs/security-review-package.md`,
`docs/external-review-package.md`, and `docs/release-evidence-template.md` to
collect the supporting artifacts.
