# Build Vs Buy: Webhook Evidence Infrastructure

Webhookery is for teams that need self-hosted, inspectable webhook evidence.
It is not always the right choice. This guide helps decide whether to use
Webhookery, buy a hosted webhook platform, or keep a simpler internal tool.

## Choose Webhookery When

- You need self-hosted control over webhook evidence.
- You need durable capture before inbound success.
- You need replay, DLQ, retention, audit-chain verification, and release
  evidence as first-class workflows.
- You need provider-specific signature evidence and raw payload preservation.
- You need commercial license exceptions or private modifications.
- Your security review prefers source-visible infrastructure and local release
  evidence.

## Choose A Hosted Vendor When

- You want someone else to operate the control plane.
- You need hosted multi-region availability and vendor-managed scale.
- Your team does not want to own PostgreSQL, object storage, backups,
  monitoring, upgrades, or incident response.
- Your primary need is outbound webhook delivery for your own API customers,
  rather than inbound evidence and recovery.

## Keep A Simpler Internal Tool When

- Webhook volume is low and replay/audit evidence is not a business
  requirement.
- Provider signatures and raw payload preservation are already covered by a
  small internal service.
- Incidents can be resolved from existing logs without customer or auditor
  evidence.
- You do not need tenant-scoped APIs, retention, audit exports, or operator
  workflows.

## Operational Ownership

Self-hosting Webhookery means owning:

- PostgreSQL durability and restore drills
- object-storage durability when S3 mode is enabled
- network policy and SSRF-safe egress posture
- TLS and mTLS configuration
- secret custody configuration
- monitoring, alerts, and incident response
- upgrade and migration review

Use `docs/deployment.md`, `docs/operations.md`, and
`docs/day-2-operations.md` before production evaluation.

## Honest Boundaries

Webhookery does not claim:

- exactly-once delivery
- provider-side event completeness
- downstream business success
- compliance certification
- hosted-service availability
- multi-region active-active operation

Its narrower promise is more useful: if Webhookery returns inbound success, the
configured durable capture path has recorded evidence. Loss boundaries remain
explicit, and recovery/replay actions are auditable.

## Evaluation Path

1. Run `docs/evaluator-quickstart.md`.
2. Review `docs/security-promise.md`.
3. Review `docs/provider-conformance.md`.
4. Run `make rc-check` in a disposable environment.
5. Compare your incident and audit requirements against the ownership list
   above.
6. Use `docs/commercial-evaluation.md` if commercial rights or support are
   required.
