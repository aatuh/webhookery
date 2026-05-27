# Performance Envelope

This document explains how to collect and interpret Webhookery performance
evidence for a controlled self-hosted release candidate. It is not a managed
service SLA, benchmark certification, or universal sizing guarantee.

## Local Smoke Harness

Run the local performance smoke against a disposable PostgreSQL database:

```bash
docker compose up -d postgres
WEBHOOKERY_TEST_DATABASE_URL=postgres://webhookery:change-me@localhost:5432/webhookery?sslmode=disable make perf-smoke
```

Expected result:

```text
perf-smoke: wrote tmp/perf-smoke/perf-smoke.json
perf-smoke: wrote tmp/perf-smoke/perf-smoke.md
```

The smoke uses local fake Stripe-style signatures and a fake receiver. It does
not call live Stripe, GitHub, Shopify, Slack, AWS, Vault, SIEM, PagerDuty, or
customer receivers.

The generated files contain aggregate timings and counts only. They must not
contain database URLs, endpoint URLs, secrets, raw signatures, raw payloads,
tenant IDs, provider tokens, or customer data.

## What The Smoke Covers

The current smoke records:

- inbound ingest latency percentiles for verified provider events;
- delivery drain time and delivered-throughput estimate;
- replay create-and-drain time for a current-config replay;
- retry scheduling evidence for a retryable receiver failure;
- successful delivery count and error count.

Use the output as release evidence that the core path still works under a small
local batch. Do not use it as a capacity promise for another deployment.

## Sizing Inputs

Production sizing depends on:

- sustained inbound event rate and peak burst size;
- raw body size distribution, including the current 2 MiB ingress body limit;
- header count and header size;
- number of tenants, sources, endpoints, subscriptions, and routes;
- fanout ratio from each event to deliveries;
- receiver latency, timeout rate, and retry behavior;
- replay volume and replay rate limits;
- retention windows for raw payloads, normalized envelopes, delivery payloads,
  provider API evidence, audit events, and exports;
- object storage mode and object-store latency when
  `WEBHOOKERY_RAW_STORAGE_MODE=s3`;
- PostgreSQL CPU, memory, storage IOPS, WAL volume, autovacuum behavior, and
  backup cadence.

## Storage Growth

Estimate storage from the evidence objects Webhookery keeps:

| Area | Growth driver |
|------|---------------|
| Raw payloads | Inbound body size times accepted/rejected request count until raw retention deletes bodies. |
| Events and receipts | One event/receipt row per captured request plus duplicate evidence. |
| Delivery payloads | One payload snapshot per delivery until delivery payload retention deletes bodies. |
| Attempts | One row per delivery attempt, including retries and replay deliveries. |
| Audit chain | Append-only audit chain metadata and hashes; retained longer than audit event rows. |
| Exports | Bundle metadata in PostgreSQL and bundle bytes in configured export storage. |
| Reconciliation | Provider API evidence metadata and optional provider response bodies until retention. |

S3-compatible raw storage reduces PostgreSQL body storage but does not remove
PostgreSQL metadata or backup requirements. PostgreSQL remains the evidence
authority.

## PostgreSQL Notes

For production pilots:

- use managed or operator-backed PostgreSQL with backups and restore drills;
- keep WAL and disk alerts ahead of retention/export/replay peaks;
- review indexes and query plans when tenant, endpoint, route, delivery, audit,
  and retention counts grow beyond smoke-test scale;
- run `WEBHOOKERY_TEST_DATABASE_URL=postgres://... make live-postgres-check`
  on disposable databases after migration changes;
- run restore drills before promoting schema or evidence-storage changes.

Do not run performance gates against production databases.

## Release Evidence

Attach sanitized `tmp/perf-smoke/perf-smoke.json` and
`tmp/perf-smoke/perf-smoke.md` to the release evidence package when
`make perf-smoke` is run for a candidate.

Record the machine shape, PostgreSQL version/configuration, object storage
mode, Webhookery commit, and whether the smoke used default Docker Compose or a
dedicated test database. Missing or skipped performance evidence should be
recorded as `blocked`, `fail`, or an accepted-risk exception in
`docs/release-evidence-template.md`.
