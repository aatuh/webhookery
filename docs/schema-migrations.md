# Schema And Migration Operations

This is the DB reviewer and operator overview for Webhookery PostgreSQL
migrations. The exact schema lives in `migrations/`; this document explains how
to review and operate it.

## Implemented Migration Runner

`go run ./cmd/whcp migrate up` uses `internal/adapters/postgres/migrate.go`.
The current runner:

- reads `*.up.sql` files from the selected migration directory;
- sorts filenames lexically, so numeric prefixes define order;
- applies each file in its own PostgreSQL transaction;
- records the migration filename stem and SHA-256 checksum in
  `schema_migrations`;
- skips a migration only when the same version and checksum already exist.

Do not edit an already-applied migration file. If a migration checksum changes
for a version that may have reached any shared environment, treat it as a
release blocker and add a new forward migration instead.

The CLI does not implement `migrate down`. The checked-in `.down.sql` files are
review and compatibility artifacts, not a production rollback workflow.

## Migration Ordering

Current migration files are ordered from `001_init` through
`028_replay_approval_expiry`. Review new files by filename, not commit order.

| Range | Schema area |
|-------|-------------|
| `001` | Core tenants, sources, endpoints, raw payload metadata, events, receipts, deliveries, replay, DLQ, quarantine, audit events, outbox, and worker leases. |
| `002`-`003` | Endpoint secrets, subscriptions, routes, schemas, and replay scope. |
| `004`-`005` | Users, memberships, API keys, idempotency, config versions, dedupe records, and replay items. |
| `006` | Retention, evidence exports, and raw payload storage lifecycle metadata. |
| `007`-`010` | Reproducible route/subscription/retry configuration, secret versions, delivery payload hashes, and replay payload hashes. |
| `011`-`012` | Provider reconciliation evidence and audit-chain heads, entries, and anchors. |
| `013`-`017` | Retry jitter evidence, legal hold, replay approval, endpoint mTLS, and generic JWT adapter metadata. |
| `018`-`021` | Metrics rollups, alerts, notification delivery, and SIEM delivery evidence. |
| `022` | Enterprise identity, SCIM, role bindings, access policies, and authz decision logs. |
| `023`-`025` | Adapter registry governance, producer trust, producer access tokens, and producer mTLS identities. |
| `026`-`028` | Incidents, replay reason codes, and replay approval expiry. |

For every new migration, document whether it changes evidence capture,
authorization, raw payload retention, replay, exports, or outbound delivery
behavior in the release evidence.

## Evidence-Authority Tables

PostgreSQL is the metadata and audit authority even when raw bodies are stored
in S3-compatible object storage. These table groups are evidence-critical:

| Group | Tables |
|-------|--------|
| Durable capture | `events`, `raw_payloads`, `provider_receipts`, `dedupe_records`, `outbox` |
| Delivery and replay | `deliveries`, `delivery_attempts`, `delivery_payloads`, `replay_jobs`, `replay_items`, `replay_receipts`, `dead_letter_entries`, `quarantine_entries` |
| Audit and export | `audit_events`, `audit_chain_heads`, `audit_chain_entries`, `audit_chain_anchors`, `evidence_exports`, `evidence_export_items` |
| Reproducible configuration | `sources`, `endpoints`, `endpoint_secrets`, `source_secret_versions`, `subscriptions`, `subscription_versions`, `routes`, `route_versions`, `retry_policies`, `config_versions`, `provider_adapters`, `adapter_versions`, `transformations`, `transformation_versions` |
| Provider reconciliation | `provider_connections`, `reconciliation_jobs`, `provider_api_evidence`, `reconciliation_items` |
| Authorization and identity | `tenants`, `users`, `memberships`, `api_keys`, `identity_providers`, `external_identities`, `auth_sessions`, `scim_tokens`, `scim_users`, `scim_groups`, `role_bindings`, `access_policy_rules`, `authz_decision_logs` |
| Operations signals | `retention_policies`, `retention_runs`, `retention_run_items`, `metrics_rollups`, `alert_rules`, `alert_firings`, `notification_channels`, `notification_deliveries`, `notification_delivery_attempts`, `siem_sinks`, `siem_deliveries`, `siem_delivery_attempts` |
| Producer trust | `producer_clients`, `producer_client_secrets`, `producer_access_tokens`, `producer_mtls_identities` |

Treat destructive changes to these groups as data-safety changes. They need a
backup/restore drill, release evidence, and explicit compatibility notes.

## Restore And Rollback Stance

Rollback is restore-first. Do not assume an image rollback reverses schema
changes or preserves compatibility with newer evidence rows.

Before applying migrations to important data:

1. Back up PostgreSQL with `scripts/backup_postgres.sh`.
2. Back up S3-compatible raw body storage separately when
   `WEBHOOKERY_RAW_STORAGE_MODE=s3`.
3. Restore into a disposable database with `scripts/restore_postgres.sh`.
4. Run `go run ./cmd/whcp migrate up` against the restored database.
5. Verify `/readyz`, event timelines, audit-chain verification, evidence export
   verification, storage status, and queue status.

When a migration fails, preserve the failed database state for analysis. Do not
retry by editing the already-applied migration. Add a new forward migration or
restore from a verified backup into a controlled target.

## Compatibility Review Checklist

Before merging a schema change, answer:

- Does the migration preserve tenant predicates for every scoped resource?
- Does it alter raw payload, delivery payload, audit, export, retention, or
  replay evidence?
- Does it require API, worker, scheduler, or migration Job rollout ordering?
- Does it require object-storage backup or restore coordination?
- Does it add nullable columns, defaults, or backfills that can run on existing
  rows without blocking live traffic?
- Does release evidence record the migration checksum summary and restore drill
  result?
