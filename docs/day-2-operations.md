# Day-2 Operations Guide

This guide is for controlled, single-region, self-hosted Webhookery
deployments after the first successful install. It links to canonical command
references instead of duplicating every CLI option.

Use:

- `docs/configuration.md` for environment variables.
- `docs/deployment.md` for deployment posture.
- `docs/stability.md` for compatibility and rollback boundaries.
- `docs/release-evidence-template.md` for release evidence.
- `docs/cli.md` for full `whcp` command syntax.

Do not include real API keys, bearer tokens, session cookies, webhook secrets,
private keys, provider credentials, raw payload bodies, raw signatures,
database URLs with real credentials, or customer data in tickets, public logs,
or release artifacts.

## Daily Checks

Run these checks from a trusted operator workstation or CI job with a scoped
operator key:

```bash
curl -fsS https://webhookery.example.com/readyz
whcp ops storage --base-url https://webhookery.example.com --api-key "$WEBHOOKERY_API_KEY"
whcp ops queues --base-url https://webhookery.example.com --api-key "$WEBHOOKERY_API_KEY"
whcp ops metrics --base-url https://webhookery.example.com --api-key "$WEBHOOKERY_API_KEY"
whcp alerts firings --base-url https://webhookery.example.com --api-key "$WEBHOOKERY_API_KEY"
whcp audit chain-head --base-url https://webhookery.example.com --api-key "$WEBHOOKERY_API_KEY"
```

Expected result: readiness exits zero, storage reports configured backends
without secrets, queue age is within the local objective, no unacknowledged
critical firings exist, and the audit chain has a current head.

## Backups And Restore Cadence

At minimum:

- back up PostgreSQL daily and before upgrades;
- back up object storage whenever `WEBHOOKERY_RAW_STORAGE_MODE=s3`;
- run a restore drill before each release candidate and after backup tooling
  changes.

PostgreSQL backup:

```bash
WEBHOOKERY_DATABASE_URL=postgres://... scripts/backup_postgres.sh backups
```

Expected result: the script prints a `backups/webhookery-<timestamp>.dump`
path with restrictive permissions.

Disposable restore drill:

```bash
WEBHOOKERY_DATABASE_URL=postgres://... \
WEBHOOKERY_RESTORE_CONFIRM=restore \
scripts/restore_postgres.sh backups/webhookery-20260525T000000Z.dump

WEBHOOKERY_DATABASE_URL=postgres://... go run ./cmd/whcp migrate up
curl -fsS http://localhost:8080/readyz
whcp audit verify-chain --base-url http://localhost:8080 --api-key "$WEBHOOKERY_API_KEY"
```

Expected result: restore and migrations exit zero, readiness succeeds, and
audit-chain verification returns `valid=true`.

Object bodies are not inside PostgreSQL dumps. If S3-compatible raw storage is
enabled, restore and verify the bucket separately before declaring the drill
complete.

## Upgrade Flow

1. Review `docs/stability.md` for migration and rollback boundaries.
2. Run `go run ./cmd/whcp doctor production` against the target configuration.
3. Run `make finalize` on the release commit.
4. Run `WEBHOOKERY_TEST_DATABASE_URL=postgres://... make rc-check` against a
   disposable database.
5. Back up PostgreSQL and object storage.
6. Run the migration job once.
7. Deploy API, worker, and scheduler images from the same release.
8. Verify readiness, queue status, audit-chain verification, and alert state.

Expected result: the migration job exits zero, all process readiness checks
pass, and accepted events continue to produce delivery or explicit failure
evidence.

Rollback is not only an image rollback. If migrations are not backward
compatible for the previous binary, restore from verified backup into a
controlled target instead of downgrading over live state.

## Incident Triage

Use this order during an incident:

1. Check `/readyz` and process logs for API, worker, scheduler, and migration
   jobs.
2. Check `whcp ops queues` for oldest pending outbox age, expired leases,
   delivery queue depth, DLQ, and quarantine counts.
3. Check alert firings and acknowledge only after assigning an owner:

   ```bash
   whcp alerts firings --api-key "$WEBHOOKERY_API_KEY"
   whcp alerts ack <firing_id> --reason "owner: on-call; investigating queue age" --api-key "$WEBHOOKERY_API_KEY"
   ```

4. Check storage posture:

   ```bash
   whcp ops storage --api-key "$WEBHOOKERY_API_KEY"
   ```

5. For provider gaps, create or inspect reconciliation jobs with fake/local
   evidence first; do not call live providers from local acceptance gates.
6. For audit concerns, run:

   ```bash
   whcp audit verify-chain --api-key "$WEBHOOKERY_API_KEY"
   whcp audit anchors --api-key "$WEBHOOKERY_API_KEY"
   ```

7. Preserve logs and database state before attempting destructive restore,
   bulk replay, retention changes, or credential rotation.

## Alert Handling

Alert rules and firings are operational state, not evidence authority. The
underlying evidence remains in events, receipts, deliveries, attempts,
quarantine, DLQ, reconciliation items, audit events, and audit-chain entries.

For every alert:

- assign an owner and incident link;
- acknowledge with a reason;
- resolve only after the underlying queue, storage, audit, or egress condition
  is clear;
- export or record relevant audit evidence when the incident affects trust
  boundaries.

Notification channels and SIEM sinks send signed HTTPS operational signals.
They must not contain raw payload bodies, secrets, provider credentials, API
keys, bearer tokens, or URL credentials.

## Key Rotation

Rotate keys through their dedicated surfaces:

- API keys: create replacement, update automation, revoke old key.
- Source verification secrets: rotate with grace period, then revoke old
  version.
- Endpoint signing secrets: rotate and verify receiver compatibility.
- Producer OAuth client secrets: rotate and update producers; tokens expire.
- Secret custody: follow `docs/configuration.md`; cross-mode re-encryption is
  not automatic.

After rotation:

```bash
go run ./cmd/whcp doctor production
whcp audit events --api-key "$WEBHOOKERY_API_KEY"
whcp audit verify-chain --api-key "$WEBHOOKERY_API_KEY"
```

Expected result: doctor has no blockers, rotation audit events exist, and the
audit chain verifies.

## Retention Review

Review retention policies before enabling or changing them:

```bash
whcp retention list --api-key "$WEBHOOKERY_API_KEY"
whcp audit verify-chain --api-key "$WEBHOOKERY_API_KEY"
```

Retention may delete body/data material while preserving hashes and metadata.
Expected post-retention behavior is `410 Gone` for deleted bodies and retained
metadata for evidence review.

## Audit Exports And Chain Verification

Before handing evidence to another party:

```bash
whcp audit export --reason "release evidence" --api-key "$WEBHOOKERY_API_KEY"
whcp audit export-status <export_id> --api-key "$WEBHOOKERY_API_KEY"
whcp audit download <export_id> --output release-evidence/audit-export.tar.gz --api-key "$WEBHOOKERY_API_KEY"
whcp audit verify-bundle --file release-evidence/audit-export.tar.gz
whcp audit verify-chain --api-key "$WEBHOOKERY_API_KEY"
```

Expected result: export reaches ready state, bundle verification passes, and
audit-chain verification reports continuity. Body-inclusive exports require
explicit elevated permission and should remain out of public release evidence.
