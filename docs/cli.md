# Webhookery CLI Reference

`whcp` is the operator and developer CLI for the Webhookery API, workers, local
migrations, evidence checks, and release support. This document preserves the
README command catalog in a reference-shaped home. For exact command ownership,
use `cmd/whcp` and `make help`.

Do not paste real API keys, provider credentials, webhook secrets, bearer
tokens, private keys, raw signatures, raw payload bodies, or customer data into
examples, terminals that are recorded, or support artifacts. Use environment
variables or local placeholder files.

## Conventions

Most API-backed commands accept:

- `--base-url`, defaulting to `http://localhost:8080`
- `--api-key`, defaulting to `$WEBHOOKERY_API_KEY`
- resource identifiers such as `evt_...`, `src_...`, `end_...`, and `rte_...`

Commands that change delivery, replay, identity, retention, exports, or secret
state should include a clear `--reason` where the command supports it. These
actions are operationally sensitive and should be run with a scoped API key.

## Local And Validation Commands

| Task | Command | Expected result |
|------|---------|-----------------|
| Run unit tests | `make test` | Go tests pass. |
| Run fast non-live gate | `make fast-check` | Unit, contract, SDK, docs-adjacent, and metadata checks pass. |
| Run docs-adjacent gate | `make docs-check` | OpenAPI, provider vectors, SDK, crypto inventory, deployment profile, collection, and metadata checks pass. |
| Run full gate | `make finalize` | Formatting, lint, vulnerability, gosec, unit, race, contract, SDK, and metadata checks pass. |
| Apply migrations | `go run ./cmd/whcp migrate up` | PostgreSQL schema is migrated. |
| Start API | `go run ./cmd/whcp api` | API listens on the configured address. |
| Run production doctor | `go run ./cmd/whcp doctor production` | Prints `blocker`, `warning`, and `ok` findings without secrets. |
| Check key custody | `go run ./cmd/whcp key-custody test` | Encrypt/decrypt check succeeds without printing plaintext or ciphertext. |

## Bootstrap And Identity

| Task | Command |
|------|---------|
| Hash a local API key | `go run ./cmd/whcp admin hash-key "$LOCAL_API_KEY"` |
| Create a database-backed API key | `go run ./cmd/whcp api-keys create --api-key "$WEBHOOKERY_API_KEY" --name local-operator --role owner --scopes '*'` |
| List API keys | `go run ./cmd/whcp api-keys list --api-key "$WEBHOOKERY_API_KEY"` |
| Revoke an API key | `go run ./cmd/whcp api-keys revoke --key-id key_... --reason "rotation" --api-key "$WEBHOOKERY_API_KEY"` |
| Create an identity provider | `go run ./cmd/whcp identity-providers create --name okta --issuer-url https://idp.example.com --client-id "$OIDC_CLIENT_ID" --client-secret "$OIDC_CLIENT_SECRET" --redirect-uri https://webhookery.example/v1/auth/oidc/callback --allowed-email-domains example.com --api-key "$WEBHOOKERY_API_KEY"` |
| Create a SCIM token | `go run ./cmd/whcp scim-tokens create --name okta-scim --api-key "$WEBHOOKERY_API_KEY"` |
| Create a role binding | `go run ./cmd/whcp role-bindings create --principal-type user --principal-id usr_... --role auditor --resource-family audit --environment production --reason "audit team access" --api-key "$WEBHOOKERY_API_KEY"` |
| Create an access policy | `go run ./cmd/whcp access-policies create --name deny-prod-raw --action events:raw --effect deny --resource-family event --environment production --reason "limit raw payload exposure" --api-key "$WEBHOOKERY_API_KEY"` |
| Explain authorization | `go run ./cmd/whcp authz explain --actor-id usr_... --action events:raw --resource-family event --resource-id evt_... --environment production --api-key "$WEBHOOKERY_API_KEY"` |

## Events And Sources

| Task | Command |
|------|---------|
| List events | `go run ./cmd/whcp events list --base-url http://localhost:8080 --api-key "$WEBHOOKERY_API_KEY"` |
| Get one event | `go run ./cmd/whcp events get --event-id evt_... --api-key "$WEBHOOKERY_API_KEY"` |
| View event timeline | `go run ./cmd/whcp events timeline --event-id evt_... --api-key "$WEBHOOKERY_API_KEY"` |
| View normalized envelope | `go run ./cmd/whcp events normalized --event-id evt_... --api-key "$WEBHOOKERY_API_KEY"` |
| Export raw payload bytes | `go run ./cmd/whcp events raw-export --event-id evt_... --output payload.bin --api-key "$WEBHOOKERY_API_KEY"` |
| Rotate source secret | `go run ./cmd/whcp sources rotate-secret --source-id src_... --secret "$NEXT_WEBHOOK_SECRET" --reason "scheduled rotation" --api-key "$WEBHOOKERY_API_KEY"` |
| Disable source | `go run ./cmd/whcp sources update --source-id src_... --state disabled --reason "retire old webhook" --api-key "$WEBHOOKERY_API_KEY"` |

Raw payload export requires elevated permission. Store exported files with the
same care as customer payload data.

## Adapters, Providers, And Reconciliation

| Task | Command |
|------|---------|
| Create provider connection | `go run ./cmd/whcp provider-connections create --name stripe-prod --provider stripe --credential "$PROVIDER_API_TOKEN" --config source_id=src_stripe --api-key "$WEBHOOKERY_API_KEY"` |
| Verify provider connection | `go run ./cmd/whcp provider-connections verify --connection-id pcn_... --reason "initial credential check" --api-key "$WEBHOOKERY_API_KEY"` |
| Create declarative adapter | `go run ./cmd/whcp adapters create --name acme-hmac --kind declarative --api-key "$WEBHOOKERY_API_KEY"` |
| Add adapter version | `go run ./cmd/whcp adapters version-create --adapter-id pad_... --version 2026-05-01 --definition-file acme-adapter.json --reason "upload declarative adapter" --api-key "$WEBHOOKERY_API_KEY"` |
| Request adapter review | `go run ./cmd/whcp adapters transition --adapter-id pad_... --version-id adv_... --action request_review --reason "ready for security review" --api-key "$WEBHOOKERY_API_KEY"` |
| Dry-run reconciliation | `go run ./cmd/whcp reconciliation-jobs dry-run --connection-id pcn_... --from 2026-05-25T00:00:00Z --to 2026-05-25T12:00:00Z --capture-missing --api-key "$WEBHOOKERY_API_KEY"` |
| Create reconciliation job | `go run ./cmd/whcp reconciliation-jobs create --connection-id pcn_... --capture-missing --route-recovered --reason "recover missing provider events" --api-key "$WEBHOOKERY_API_KEY"` |
| List reconciliation items | `go run ./cmd/whcp reconciliation-jobs items --job-id rec_... --api-key "$WEBHOOKERY_API_KEY"` |

Provider API credentials must be placeholders in docs and stored through the
configured secret custody mode in real environments. Recovered provider API
events are not signed webhook receipts.

## Routing, Delivery, And Replay

| Task | Command |
|------|---------|
| Update endpoint URL | `go run ./cmd/whcp endpoints update --endpoint-id end_... --url https://receiver.example/webhook --reason "move receiver" --api-key "$WEBHOOKERY_API_KEY"` |
| Delete endpoint | `go run ./cmd/whcp endpoints delete --endpoint-id end_... --reason "retire old receiver" --api-key "$WEBHOOKERY_API_KEY"` |
| Create mTLS endpoint | `go run ./cmd/whcp endpoints create --name mtls-receiver --url https://receiver.example/webhook --mtls-client-cert-file client.crt --mtls-client-key-file client.key --api-key "$WEBHOOKERY_API_KEY"` |
| Test endpoint | `go run ./cmd/whcp endpoints test --endpoint-id end_... --reason "verify receiver" --api-key "$WEBHOOKERY_API_KEY"` |
| Rotate endpoint secret | `go run ./cmd/whcp endpoints rotate-secret --endpoint-id end_... --reason "scheduled rotation" --api-key "$WEBHOOKERY_API_KEY"` |
| Update subscription | `go run ./cmd/whcp subscriptions update --subscription-id sub_... --event-types invoice.paid,invoice.updated --reason "narrow fanout" --api-key "$WEBHOOKERY_API_KEY"` |
| Update route | `go run ./cmd/whcp routes update --route-id rte_... --priority 10 --reason "prefer primary receiver" --api-key "$WEBHOOKERY_API_KEY"` |
| Create retry policy | `go run ./cmd/whcp retry-policies create --name standard --max-attempts 12 --max-duration-seconds 259200 --initial-delay-seconds 10 --max-delay-seconds 21600 --api-key "$WEBHOOKERY_API_KEY"` |
| Update retry policy | `go run ./cmd/whcp retry-policies update --retry-policy-id rtp_... --max-attempts 8 --reason "tune retries" --api-key "$WEBHOOKERY_API_KEY"` |
| Retry one delivery | `go run ./cmd/whcp deliveries retry --delivery-id del_... --reason "operator retry" --api-key "$WEBHOOKERY_API_KEY"` |
| Create replay job | `go run ./cmd/whcp replay-jobs create --event-id evt_... --config-mode original --rate-limit-per-minute 60 --require-approval --reason "customer replay request" --api-key "$WEBHOOKERY_API_KEY"` |
| Approve replay job | `go run ./cmd/whcp replay-jobs approve --replay-job-id rpl_... --reason "approved replay window" --api-key "$WEBHOOKERY_API_KEY"` |

Replay and retry create new delivery work linked to existing evidence. They do
not mutate original receipt history and should not be used without a reason.

## Schemas And Transformations

| Task | Command |
|------|---------|
| Create transformation | `go run ./cmd/whcp transformations create --name redact-email --operations-file operations.json --api-key "$WEBHOOKERY_API_KEY"` |
| Dry-run transformation | `go run ./cmd/whcp transformations dry-run --payload-file payload.json --operations-file operations.json` |
| Update event type | `go run ./cmd/whcp schemas event-type-update --name invoice.paid --description "Invoice paid events" --reason "clarify contract" --api-key "$WEBHOOKERY_API_KEY"` |
| Update schema state | `go run ./cmd/whcp schemas schema-update --name invoice.paid --version 2026-05-01 --state deprecated --reason "replace with 2026-06-01" --api-key "$WEBHOOKERY_API_KEY"` |
| Validate payload | `go run ./cmd/whcp schemas validate --name invoice.paid --version 2026-05-01 --payload-file payload.json --api-key "$WEBHOOKERY_API_KEY"` |
| Get schema | `go run ./cmd/whcp schemas schema-get --name invoice.paid --version 2026-05-01 --api-key "$WEBHOOKERY_API_KEY"` |
| Check compatibility | `go run ./cmd/whcp schemas check-compat --name invoice.paid --version 2026-05-01 --new-schema-file schema-next.json --api-key "$WEBHOOKERY_API_KEY"` |

Payload files may contain PII. Keep them out of commits and shared artifacts.

## Audit, Retention, And Evidence

| Task | Command |
|------|---------|
| Export evidence | `go run ./cmd/whcp audit export --include-timelines --include-payloads --reason "support case" --api-key "$WEBHOOKERY_API_KEY"` |
| Check export status | `go run ./cmd/whcp audit export-status --export-id exp_... --api-key "$WEBHOOKERY_API_KEY"` |
| Download export | `go run ./cmd/whcp audit download --export-id exp_... --output evidence.tar.gz --api-key "$WEBHOOKERY_API_KEY"` |
| Audit chain head | `go run ./cmd/whcp audit chain-head --api-key "$WEBHOOKERY_API_KEY"` |
| Verify audit chain | `go run ./cmd/whcp audit verify-chain --api-key "$WEBHOOKERY_API_KEY"` |
| Anchor audit chain | `go run ./cmd/whcp audit anchor --reason "daily anchor" --api-key "$WEBHOOKERY_API_KEY"` |
| List anchors | `go run ./cmd/whcp audit anchors --api-key "$WEBHOOKERY_API_KEY"` |
| Verify bundle locally | `go run ./cmd/whcp audit verify-bundle --file evidence.tar.gz` |
| Create retention policy | `go run ./cmd/whcp retention create --resource-type raw_payload --retention-days 30 --api-key "$WEBHOOKERY_API_KEY"` |
| Update legal hold | `go run ./cmd/whcp retention update --policy-id ret_... --legal-hold --hold-reason "customer legal request" --api-key "$WEBHOOKERY_API_KEY"` |

Evidence exports with payloads are sensitive. Use scoped authorization, short
retention, private file permissions, and a recorded support or legal reason.

## Operations, Alerts, And Signal Egress

| Task | Command |
|------|---------|
| Metrics | `go run ./cmd/whcp ops metrics --api-key "$WEBHOOKERY_API_KEY"` |
| Rollups | `go run ./cmd/whcp ops rollups --api-key "$WEBHOOKERY_API_KEY"` |
| Storage status | `go run ./cmd/whcp ops storage --api-key "$WEBHOOKERY_API_KEY"` |
| Runtime config view | `go run ./cmd/whcp ops config --api-key "$WEBHOOKERY_API_KEY"` |
| Worker status | `go run ./cmd/whcp ops workers --api-key "$WEBHOOKERY_API_KEY"` |
| Queue status | `go run ./cmd/whcp ops queues --api-key "$WEBHOOKERY_API_KEY"` |
| Create alert | `go run ./cmd/whcp alerts create --name dlq-open --rule-type dead_letter_open --threshold 1 --reason "page on DLQ growth" --api-key "$WEBHOOKERY_API_KEY"` |
| Create notification channel | `go run ./cmd/whcp notification-channels create --name ops-webhook --url https://ops.example/hooks/webhookery --signing-secret "$SIGNAL_SECRET" --api-key "$WEBHOOKERY_API_KEY"` |
| Update alert channel | `go run ./cmd/whcp alerts update --alert-id alr_... --channel-ids nch_... --reason "send DLQ pages" --api-key "$WEBHOOKERY_API_KEY"` |
| List alert firings | `go run ./cmd/whcp alerts firings --state open --api-key "$WEBHOOKERY_API_KEY"` |
| Acknowledge alert | `go run ./cmd/whcp alerts ack --firing-id alf_... --reason "operator investigating" --api-key "$WEBHOOKERY_API_KEY"` |
| List notification failures | `go run ./cmd/whcp notification-deliveries list --state failed --api-key "$WEBHOOKERY_API_KEY"` |
| Create SIEM sink | `go run ./cmd/whcp siem-sinks create --name audit-stream --url https://siem.example/ingest --signing-secret "$SIEM_SIGNAL_SECRET" --api-key "$WEBHOOKERY_API_KEY"` |
| List SIEM failures | `go run ./cmd/whcp siem-deliveries list --state failed --api-key "$WEBHOOKERY_API_KEY"` |

Signal and SIEM signing secrets are secrets. Do not document concrete values.

## Producer Trust

| Task | Command |
|------|---------|
| Create producer client | `go run ./cmd/whcp producer-clients create --name billing-producer --source-id src_internal --api-key "$WEBHOOKERY_API_KEY"` |
| Rotate producer client secret | `go run ./cmd/whcp producer-clients rotate-secret --client-id pcl_... --reason "scheduled rotation" --api-key "$WEBHOOKERY_API_KEY"` |
| Create producer mTLS identity | `go run ./cmd/whcp producer-mtls-identities create --name billing-cert --source-id src_internal --cert-file producer.crt --api-key "$WEBHOOKERY_API_KEY"` |
| Verify producer mTLS identity | `go run ./cmd/whcp producer-mtls-identities verify --identity-id pmi_... --cert-file producer.crt --api-key "$WEBHOOKERY_API_KEY"` |

Producer client secrets and OAuth access tokens are stored as hashes; mTLS
identity records store certificate metadata, not private keys.

## Backup, Restore, Release, And Collections

| Task | Command |
|------|---------|
| Backup PostgreSQL | `scripts/backup_postgres.sh backups` |
| Restore PostgreSQL into a target database | `WEBHOOKERY_RESTORE_CONFIRM=restore scripts/restore_postgres.sh backups/webhookery-20260525T000000Z.dump` |
| Start local MinIO profile | `docker compose --profile object-storage up --build` |
| Lint Helm profile | `helm lint deploy/helm/webhookery` |
| Check Terraform formatting | `terraform fmt -check -recursive deploy/terraform` |
| Release evidence checks | `make release-acceptance` |
| RC checks | `make rc-check` |
| Collection checks | `make collections-check` |

Backups and evidence bundles can contain sensitive operational data. Do not
commit generated backup files or release evidence containing real customer
data.
