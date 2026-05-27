# Failure Drills

This runbook defines safe local and pilot failure drills for Webhookery. The
goal is repeated evidence, not chaos testing. Run destructive drills only
against disposable local or pilot-approved resources.

The helper script can list drills, write a sanitized plan, or run the local
evidence demo drill:

```bash
scripts/failure_drills.sh list
scripts/failure_drills.sh plan --output tmp/failure-drills
WEBHOOKERY_TEST_DATABASE_URL=postgres://... scripts/failure_drills.sh run local-demo
```

`plan` is non-live and safe for documentation/release checks. `run local-demo`
requires the same disposable PostgreSQL setup as `docs/evaluator-quickstart.md`
and reuses `examples/webhook-evidence-demo/run.sh`.

## Drill Catalog

| Drill | Expected result | Evidence |
|-------|-----------------|----------|
| downstream receiver fails | A valid synthetic event is captured, downstream delivery fails, and failure is visible before replay. | Incident report delivery timeline. |
| downstream recovers | Replay succeeds after receiver recovery. | Incident report replay section and `verify-output.json`. |
| invalid signature | Invalid provider signature is persisted as evidence and not routed to side-effecting destinations. | Local E2E output and quarantine evidence. |
| replay after DLQ | DLQ release or replay creates new work with reason-code evidence. | Incident report replay and DLQ sections. |
| PostgreSQL unavailable before capture | Ingress does not return success before durable capture is available. | Readiness/API error evidence from disposable stack. |
| object storage unavailable in S3 mode | Object-backed raw payload capture is not acknowledged when required object writes fail. | Storage drill notes and redacted API output. |
| audit-chain verification failure | Verification reports a failure in a disposable altered database copy. | `whcp audit verify-chain` output from the copy. |
| retention raw-payload tombstone | Raw body reads show retained/tombstoned state while metadata remains queryable. | Retention run, event timeline, and audit entries. |

## Restore Drill

Use `make restore-drill` or the script directly when a source database and a
separate disposable restore target are available:

```bash
WEBHOOKERY_DATABASE_URL=postgres://source \
WEBHOOKERY_RESTORE_DRILL_DATABASE_URL=postgres://disposable-restore \
make restore-drill
```

The restore target is destructive. The script refuses to run when the restore
URL is missing or equal to the source URL. It writes
`tmp/restore-drill/restore-drill.json` without database URLs.

PostgreSQL restore drills do not verify S3 or MinIO object bodies. If
`WEBHOOKERY_RAW_STORAGE_MODE=s3` is in scope, record a separate object-storage
read/write drill in `docs/pilot-evidence-template.md`.

## Recording Results

For pilot evidence, record:

- drill name and date;
- Webhookery version or commit;
- source of synthetic or sanitized event;
- incident ID, event ID, and evidence export ID;
- bundle verification result;
- raw payload inclusion status;
- known gaps and accepted risks; and
- follow-up decision from `docs/pilot-review-checklist.md`.

Do not store database URLs, provider credentials, webhook secrets, raw
signatures, raw payload bodies, customer data, or private receiver URLs in
public drill output.
