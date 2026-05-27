# Self-Hosted Webhook Gateway Architecture

Webhookery is not a generic message queue with HTTP adapters. Its architecture
starts from a narrower promise: if Webhookery returns inbound success, the
event evidence has been durably captured.

This article explains the core shape for evaluators and reviewers. Exact
behavior remains owned by code, `openapi.yaml`, migrations, and the operations
docs.

## Architecture Goals

- preserve exact provider request bytes and headers before trust
- verify provider signatures using provider-specific rules
- write durable receipt, event, dedupe, audit, and outbox evidence before
  downstream work
- route and transform events through versioned configuration
- snapshot outbound delivery payload bytes and hashes
- retry and replay without mutating original evidence
- verify audit-chain continuity and export evidence bundles

## Core Components

| Component | Responsibility |
| --- | --- |
| API process | Receives provider and product events, handles management APIs, and serves OpenAPI/UI surfaces. |
| Worker process | Claims durable work, delivers payload snapshots, retries failures, updates DLQ, emits signal egress, and processes recovery jobs. |
| Scheduler process | Runs bounded recurring work such as rollups, retention, alerts, and SIEM cursor processing. |
| PostgreSQL | Source of truth for receipts, events, payload metadata, deliveries, attempts, audit chains, config versions, and operational state. |
| Object storage | Optional strict backend for raw payload bodies while PostgreSQL remains metadata authority. |
| Static/operator surfaces | CLI, minimal UI, docs, collections, and release evidence for inspection and control. |

## Evidence Flow

1. A provider request reaches an ingest route.
2. Webhookery reads the raw body once and captures raw headers.
3. Provider verification uses exact raw bytes and constant-time comparison.
4. The transaction writes durable receipt, event/quarantine evidence, payload
   metadata, audit evidence, and outbox work as appropriate.
5. Routing creates delivery work from versioned route/subscription/config
   evidence.
6. Transformation output is snapshotted as exact delivery payload bytes with
   a hash.
7. Workers deliver that snapshot, sign those exact bytes, and record attempts.
8. Replay creates new work linked to original evidence.
9. Audit-chain verification and evidence exports let operators inspect the
   lifecycle later.

## PostgreSQL-First Reasoning

PostgreSQL is the MVP authority because the product depends on transactions,
indexes, leases, tenant predicates, and restore drills. Queue or cache systems
can accelerate future deployments, but accepted work must not depend on a
volatile queue as the only source of truth.

Object storage is optional and strict when enabled. In S3 mode, inbound success
requires both the object write and metadata commit. Raw payload retention may
delete bodies later, but hashes and metadata remain.

## OpenAPI And SDK Boundary

`openapi.yaml` is the canonical REST contract. `sdk/openapi.yaml` is a derived
copy, and `make sdk-check` verifies alignment. UI and CLI actions are clients of
the same control plane rather than separate authority paths.

## Audit-Chain Verification

Audit events are chained per tenant. The chain covers audit-event metadata and
retention/tombstone continuity. It does not turn Webhookery into a compliance
certificate or external timestamping service. Payload integrity remains covered
by payload hashes, raw-body hashes, and export file hashes.

## What This Architecture Does Not Claim

- exactly-once delivery
- provider-side event completeness
- downstream business success
- universal recovery after provider-side loss
- compliance certification
- external timestamping
- multi-region active-active consistency

Use `docs/evaluator-quickstart.md`, `docs/provider-conformance.md`, and
`docs/release-evidence-template.md` to inspect the architecture through local
fake-provider evidence.
