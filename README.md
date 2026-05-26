# Webhookery

Webhookery is a self-hosted webhook evidence and delivery control plane. The
MVP implementation in this repository is PostgreSQL-first and API/CLI-first:
it captures raw webhook evidence before acknowledging providers, verifies
provider signatures using exact bytes, stores dedupe and audit evidence, and
delivers outbound webhooks with at-least-once semantics.

This repository is now implementation-bearing. `.initial_design.md` remains the
product design reference; `openapi.yaml`, `migrations/`, `cmd/`, `internal/`,
and `pkg/` are the implementation sources for their areas.

## Local Development

```bash
cp .env.example .env
docker compose up --build
```

The example bootstrap key for local development is `dev-bootstrap-key`. Create a
database-backed API key immediately and then remove or rotate the bootstrap
hash in production-style environments.

Useful commands:

```bash
make test
make fast-check
go run ./cmd/whcp migrate up
go run ./cmd/whcp api
go run ./cmd/whcp api-keys create --api-key dev-bootstrap-key --name local-operator --role owner --scopes '*'
go run ./cmd/whcp events list --base-url http://localhost:8080 --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp events get --event-id evt_... --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp events timeline --event-id evt_... --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp events normalized --event-id evt_... --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp events raw-export --event-id evt_... --output payload.bin --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp transformations create --name redact-email --operations-file operations.json --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp transformations dry-run --payload-file payload.json --operations-file operations.json
go run ./cmd/whcp audit export --include-timelines --include-payloads --reason "support case" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit export-status --export-id exp_... --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit download --export-id exp_... --output evidence.tar.gz --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit chain-head --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit verify-chain --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit anchor --reason "daily anchor" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit anchors --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit verify-bundle --file evidence.tar.gz
go run ./cmd/whcp retention create --resource-type raw_payload --retention-days 30 --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp retention update --policy-id ret_... --legal-hold --hold-reason "customer legal request" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp provider-connections create --name stripe-prod --provider stripe --credential "$STRIPE_API_KEY" --config source_id=src_stripe --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp provider-connections verify --connection-id pcn_... --reason "initial credential check" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp adapters create --name acme-hmac --kind declarative --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp adapters version-create --adapter-id pad_... --version 2026-05-01 --definition-file acme-adapter.json --reason "upload declarative adapter" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp adapters transition --adapter-id pad_... --version-id adv_... --action request_review --reason "ready for security review" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp sources update --source-id src_... --state disabled --reason "retire old webhook" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp endpoints update --endpoint-id end_... --url https://receiver.example/webhook --reason "move receiver" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp endpoints delete --endpoint-id end_... --reason "retire old receiver" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp subscriptions update --subscription-id sub_... --event-types invoice.paid,invoice.updated --reason "narrow fanout" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp subscriptions delete --subscription-id sub_... --reason "retire fanout" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp routes update --route-id rte_... --priority 10 --reason "prefer primary receiver" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp routes delete --route-id rte_... --reason "retire route" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp reconciliation-jobs dry-run --connection-id pcn_... --from 2026-05-25T00:00:00Z --to 2026-05-25T12:00:00Z --capture-missing --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp reconciliation-jobs create --connection-id pcn_... --capture-missing --route-recovered --reason "recover missing Stripe events" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp reconciliation-jobs items --job-id rec_... --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp retry-policies create --name standard --max-attempts 12 --max-duration-seconds 259200 --initial-delay-seconds 10 --max-delay-seconds 21600 --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp routes create --source-id src_... --endpoint-id end_... --event-types invoice.paid --retry-policy-id rtp_...
go run ./cmd/whcp routes versions --route-id rte_... --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp retry-policies update --retry-policy-id rtp_... --max-attempts 8 --reason "tune retries" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp retry-policies delete --retry-policy-id rtp_... --reason "retire retry policy" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp sources rotate-secret --source-id src_... --secret whsec_next --reason "scheduled rotation" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp endpoints rotate-secret --endpoint-id end_... --reason "scheduled rotation" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp endpoints create --name mtls-receiver --url https://receiver.example/webhook --mtls-client-cert-file client.crt --mtls-client-key-file client.key --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp schemas event-type-update --name invoice.paid --description "Invoice paid events" --reason "clarify contract" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp schemas schema-update --name invoice.paid --version 2026-05-01 --state deprecated --reason "replace with 2026-06-01" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp schemas validate --name invoice.paid --version 2026-05-01 --payload-file payload.json --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp schemas schema-get --name invoice.paid --version 2026-05-01 --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp schemas check-compat --name invoice.paid --version 2026-05-01 --new-schema-file schema-next.json --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp endpoints test --endpoint-id end_... --reason "verify receiver" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp deliveries retry --delivery-id del_... --reason "operator retry"
go run ./cmd/whcp replay-jobs create --event-id evt_... --config-mode original --rate-limit-per-minute 60 --require-approval --reason "customer replay request"
go run ./cmd/whcp replay-jobs approve --replay-job-id rpl_... --reason "approved replay window"
go run ./cmd/whcp ops metrics --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp ops rollups --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp ops storage --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp ops config --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp ops workers --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp ops queues --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp key-custody test
go run ./cmd/whcp producer-clients create --name billing-producer --source-id src_internal --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp producer-clients rotate-secret --client-id pcl_... --reason "scheduled rotation" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp producer-mtls-identities create --name billing-cert --source-id src_internal --cert-file producer.crt --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp producer-mtls-identities verify --identity-id pmi_... --cert-file producer.crt --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp alerts create --name dlq-open --rule-type dead_letter_open --threshold 1 --reason "page on DLQ growth" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp notification-channels create --name ops-webhook --url https://ops.example/hooks/webhookery --signing-secret "$SIGNAL_SECRET" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp alerts update --alert-id alr_... --channel-ids nch_... --reason "send DLQ pages" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp alerts firings --state open --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp alerts ack --firing-id alf_... --reason "operator investigating" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp notification-deliveries list --state failed --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp siem-sinks create --name audit-stream --url https://siem.example/ingest --signing-secret "$SIEM_SIGNAL_SECRET" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp siem-deliveries list --state failed --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp identity-providers create --name okta --issuer-url https://idp.example.com --client-id "$OIDC_CLIENT_ID" --client-secret "$OIDC_CLIENT_SECRET" --redirect-uri https://webhookery.example/v1/auth/oidc/callback --allowed-email-domains example.com --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp scim-tokens create --name okta-scim --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp role-bindings create --principal-type user --principal-id usr_... --role auditor --resource-family audit --environment production --reason "audit team access" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp access-policies create --name deny-prod-raw --action events:raw --effect deny --resource-family event --environment production --reason "limit raw payload exposure" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp authz explain --actor-id usr_... --action events:raw --resource-family event --resource-id evt_... --environment production --api-key "$WEBHOOKERY_API_KEY"
scripts/backup_postgres.sh backups
WEBHOOKERY_RESTORE_CONFIRM=restore scripts/restore_postgres.sh backups/webhookery-20260525T000000Z.dump
go run ./cmd/whcp doctor production
helm lint deploy/helm/webhookery
terraform fmt -check -recursive deploy/terraform
make release-acceptance
make rc-check
make collections-check
```

Set `WEBHOOKERY_ENABLE_UI=true` to expose the minimal operator console at `/`.
The UI keeps the entered API key in browser memory only and calls the same
tenant-scoped REST API as the CLI.

Raw payload bodies are stored in PostgreSQL by default. To use S3-compatible
storage, set `WEBHOOKERY_RAW_STORAGE_MODE=s3` plus the
`WEBHOOKERY_OBJECT_STORAGE_*` variables. In S3 mode, inbound success requires
the object write and PostgreSQL metadata commit to both succeed.

Webhook/source secrets, endpoint signing secrets, provider credentials, and
outbound mTLS private keys use local AES envelope encryption by default via
`WEBHOOKERY_SECRET_BOX_MODE=local` and `WEBHOOKERY_MASTER_KEY_BASE64`.
Operators that already run Vault Transit can set
`WEBHOOKERY_SECRET_BOX_MODE=vault-transit` with `WEBHOOKERY_VAULT_ADDR`,
`WEBHOOKERY_VAULT_TOKEN`, and `WEBHOOKERY_VAULT_TRANSIT_KEY`; PostgreSQL then
stores wrapped Vault ciphertext instead of locally encrypted ciphertext for
new secret writes. Operators using AWS KMS can set
`WEBHOOKERY_SECRET_BOX_MODE=aws-kms` with `WEBHOOKERY_AWS_REGION`,
`WEBHOOKERY_AWS_KMS_KEY_ID`, and optional `WEBHOOKERY_AWS_KMS_ENDPOINT`.
AWS KMS mode uses envelope encryption with generated data keys; it does not
directly KMS-encrypt large secret values and it does not automatically
re-encrypt rows written by local or Vault modes. `whcp key-custody test`
checks the configured mode without printing plaintext, ciphertext, or full key
ids.

Run `go run ./cmd/whcp doctor production` before promoting a self-hosted
deployment. The doctor reads environment/configuration only, prints
`blocker`, `warning`, and `ok` findings, and returns non-zero when blockers
remain. It never prints database passwords, API keys, webhook secrets, Vault
tokens, AWS credentials, raw KMS key ids, or object-store credentials.
Warnings are operator review items; blockers are unsafe or incomplete
production settings.

Product event producers can use API keys with `events:write`, OAuth client
credentials from `/v1/producer-clients`, or app-verified producer mTLS
identities from `/v1/producer-mtls-identities`. Source-bound producer
credentials must match the `source_id` in the `POST /v1/events` body. Producer
client secrets and OAuth access tokens are stored only as hashes, and mTLS
identity records store certificate metadata only, never private keys. Producer
mTLS requires app-side TLS configuration with
`WEBHOOKERY_PRODUCER_MTLS_CLIENT_CA_FILE`; proxy-supplied certificate headers
are not trusted.

Verified events also get canonical normalized envelope records. Routes and
subscriptions can reference deterministic JSON Pointer transformations; new
deliveries snapshot the exact outbound payload bytes and sign those stored
bytes. Transformation payloads may contain PII, so body reads and payload-body
exports require `events:raw`.

Private adapter registry governance is available through `/v1/adapters` and
`whcp adapters`. Declarative adapter definitions and plugin package metadata
are tenant-scoped, versioned, hashed, audited, and moved through the approval
workflow before activation. Active declarative HMAC-SHA256 adapters can verify
inbound requests using exact raw bytes and configured replay windows.
Code-plugin packages are recorded for review only; Webhookery does not execute
arbitrary plugin code.

Provider reconciliation jobs compare provider-side API evidence to local
Webhookery evidence when provider APIs permit it. Stripe event reconciliation
can capture recoverable missing events as `provider_api_reconciliation`
evidence; GitHub repository webhook reconciliation can compare delivery GUIDs
and request redelivery for failed deliveries. Shopify and Slack currently
record capability/limitation evidence instead of claiming generic missed-event
recovery. Recovered events are not marked as signed webhooks and route only
when `route_recovered=true`.

Audit events are written through a tenant-scoped SHA-256 hash chain. Existing
audit rows are backfilled into deterministic chain entries during startup, and
new audit writes append the audit row and chain entry in one transaction.
Evidence exports include `audit_chain_proof.jsonl`; `whcp audit verify-bundle`
checks bundle file hashes and chain continuity locally.

Alert notification channels send signed generic HTTPS callbacks for alert
open, acknowledged, and resolved transitions. Channel signing secrets are
encrypted at rest and never returned by API, CLI, or UI responses. Signal
payloads contain alert metadata only and are signed with
`Webhookery-Signal-Timestamp` plus `Webhookery-Signal-Signature`.

SIEM sinks stream chained audit-event metadata as signed HTTPS JSONL batches.
Each sink cursor advances only after a successful delivery, so failed SIEM
egress retries without skipping audit-chain entries. SIEM payloads exclude raw
webhook bodies, provider headers, API keys, bearer tokens, and egress secrets.

Retry scheduling records reproducibility evidence: deliveries carry a stored
`retry_seed`, and retryable attempts record the deterministic jitter delay and
next retry timestamp used by the worker.

For local MinIO testing:

```bash
docker compose --profile object-storage up --build
```

For Kubernetes, start from `deploy/kubernetes/README.md`. The manifests expect
external PostgreSQL and a separately managed `webhookery-secrets` Secret; they
do not install ingress, TLS, PostgreSQL, or object storage.

Postman and Bruno request collections are committed under `collections/`.
The `pkg/client` package provides a small Go REST client for producer event
ingestion and audit-chain verification; `pkg/verifier` remains the receiver
signature verification helper.

## Security Promise

Webhookery does not promise exactly-once delivery. Inbound success means the
platform durably captured raw request evidence and verification metadata. Every
loss boundary, duplicate, replay, and delivery attempt is intended to remain
visible and auditable.

## Production RC Readiness

The production-respectable target for this repository is a single-region
self-hosted release candidate. Before promoting a deployment:

1. Run `go run ./cmd/whcp doctor production`; production blockers must be
   fixed before promotion.
2. Run `make finalize`; all unit, contract, SDK, vulnerability, gosec, and race
   checks must pass.
3. Run `WEBHOOKERY_TEST_DATABASE_URL=postgres://... make live-postgres-check`
   against a disposable PostgreSQL database. This is the canonical live
   database quality gate; `make fast-check` remains non-live for local and CI
   iteration without credentials.
4. Run `WEBHOOKERY_TEST_DATABASE_URL=postgres://... make rc-check` against a
   disposable PostgreSQL database; it should end with
   `release-candidate acceptance checks passed`.
5. Run the restore drill with a separate disposable restore database by setting
   `WEBHOOKERY_RC_RESTORE_DATABASE_URL=postgres://...` before `make rc-check`.
6. Confirm the operator runbooks in `docs/operations.md` match the deployed
   storage, key-custody, TLS, and retention configuration.

This RC scope does not claim exactly-once delivery, multi-region active-active
operation, external timestamping, compliance certification, managed provider
availability, or live third-party recovery guarantees.
