# Pilot Topology

This is the single supported pilot topology for Webhookery v0.2-style
evaluation. It is intentionally narrow so evaluator feedback is comparable and
the product does not drift into a generic webhook platform.

Use this document to decide whether a pilot is in scope before changing
deployment, provider, storage, or support claims.

## Supported Pilot Shape

| Area | Pilot profile |
| --- | --- |
| Deployment | Single-region self-hosted Docker Compose or Helm. |
| Database | External PostgreSQL operated and backed up by the evaluator/operator. |
| Raw payload storage | PostgreSQL raw payload storage by default. |
| Optional object storage | S3-compatible storage or MinIO only after an explicit storage drill. |
| Providers | One to three providers, with Stripe and GitHub first and Shopify optional. |
| Receiver type | HTTP downstream receiver. |
| Traffic | Bounded low-to-moderate evaluation volume agreed before the pilot. |
| Tenancy | Single organization or a controlled tenant set. |
| Evidence | Audit chain, incident packet, and evidence bundle required. |
| Support | Commercial evaluation or production-readiness review with written scope. |

## Required Pilot Drills

- Run `docs/evaluator-quickstart.md`.
- Generate an incident packet from `examples/webhook-evidence-demo/`.
- Verify the evidence bundle with `whcp audit verify-bundle`.
- Run `make rc-check` against a disposable PostgreSQL database.
- Run the production doctor for the intended environment.
- Complete a backup/restore drill before production-like traffic.
- Record results in `docs/pilot-evidence-template.md`.

## Operator-Owned Responsibilities

The operator owns:

- PostgreSQL availability, backups, restore drills, credentials, and upgrades;
- TLS/ingress, DNS, network policy, egress controls, and firewalling;
- alert routing, incident response, on-call, and operational escalation;
- secret custody for API keys, webhook secrets, encryption keys, and provider
  credentials;
- retention configuration and review of evidence before sharing; and
- receiver behavior, idempotency, and downstream business processing.

## Optional S3/MinIO Storage

PostgreSQL raw payload storage is the default pilot path. S3-compatible object
storage is in scope only when the pilot explicitly runs a storage drill that
proves:

- object writes happen before accepted inbound success for object-backed raw
  payloads;
- object read failures are redacted in errors and support output;
- evidence exports are readable after backup/restore procedures; and
- missing object bodies are treated as an explicit evidence gap, not silently
  recovered.

## Out Of Scope

These requests are out of scope for the initial pilot unless repeated paid
pilot evidence justifies a new phase:

- multi-region active-active operation;
- Kafka, NATS, SQS, Pub/Sub, or another queue as the evidence authority;
- hosted SaaS operation by this repository;
- arbitrary code plugins or marketplace integrations;
- broad outbound-webhook platform positioning;
- SAML/HSM/enterprise identity expansion beyond the implemented surface;
- provider certification claims; and
- compliance, legal evidentiary, managed-service availability, exactly-once,
  or provider-side completeness claims.

## Go/No-Go Rule

A pilot is in scope only if the evaluator accepts the topology above and the
non-claims in `docs/security-promise.md`. If the requested topology needs a
broader platform, record it in `docs/pilot-feedback-template.md` and classify
it through `docs/roadmap-intake-policy.md` before implementation.
