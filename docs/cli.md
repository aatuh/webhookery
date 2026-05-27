# Webhookery CLI Reference

`whcp` is the operator and developer CLI for Webhookery processes, migrations,
control-plane APIs, evidence workflows, and release support. Exact behavior is
owned by `cmd/whcp`; this document is the human reference for current command
groups.

Most API-backed commands accept:

- `--base-url`, defaulting to `http://localhost:8080`
- `--api-key`, defaulting to `$WEBHOOKERY_API_KEY`

Do not paste real API keys, provider credentials, webhook secrets, bearer
tokens, private keys, raw signatures, raw payload bodies, customer data,
database URLs with real credentials, or evidence bundles into examples,
terminals that are recorded, issues, or support artifacts.

## Root Command Groups

Running `go run ./cmd/whcp` prints the current root command list and exits
non-zero because a command is required. The groups are:

| Group | Purpose | Typical scope | Elevated risk |
|-------|---------|---------------|---------------|
| `api`, `worker`, `scheduler`, `migrate` | Run processes and migrations. | Local environment access. | Migration and process lifecycle. |
| `admin`, `api-keys` | Bootstrap and database-backed API key lifecycle. | Owner or security-capable key. | Secret creation/revocation. |
| `producer-clients`, `producer-mtls-identities`, `key-custody` | Producer trust and key custody checks. | `security:write` for mutations. | Token/secret rotation and mTLS trust. |
| `doctor`, `ops` | Production preflight and operational visibility. | Local config or `ops:read`. | May expose operational posture; output must be redacted. |
| `identity-providers`, `scim-tokens`, `role-bindings`, `access-policies`, `authz` | Enterprise identity and authorization controls. | `security:write` for mutations. | High authorization impact. |
| `events`, `sources`, `provider-connections`, `adapters` | Event evidence, source config, provider credentials, and adapter governance. | `events:read`, `events:raw`, `sources:write`, or `security:write`. | Raw payloads, secrets, provider recovery. |
| `incidents` | Incident packets, attached event evidence, report snapshots, and incident evidence exports. | `incidents:read`, `incidents:write`, and `audit:read` for exports. | Evidence disclosure and support artifacts. |
| `endpoints`, `subscriptions`, `retry-policies`, `routes`, `transformations` | Outbound delivery configuration and reproducible payload shaping. | `routes:write` or related read scopes. | Delivery fanout and receiver impact. |
| `deliveries`, `replay-jobs`, `reconciliation-jobs`, `dead-letter`, `quarantine` | Delivery recovery, replay, provider reconciliation, DLQ, and quarantine decisions. | `deliveries:retry`, `replay:write`, or `security:write`. | Duplicate side effects and recovery claims. |
| `alerts`, `notification-channels`, `notification-deliveries` | Alert rules and signed notification egress. | `ops:read` or `ops:write`. | External egress and signing secrets. |
| `siem-sinks`, `siem-deliveries` | Signed audit metadata streaming. | `audit:read` for reads, `security:write` for mutations. | External egress and audit disclosure. |
| `audit`, `retention`, `schemas`, `signatures` | Audit evidence, retention, schema checks, and signature helpers. | `audit:read`, `events:raw`, `security:write`, or `schemas:write`. | Evidence export, retention, raw payload inclusion. |

## Local And Validation

| Task | Required scope | Example | Expected outcome | Elevated risk |
|------|----------------|---------|------------------|---------------|
| Run unit tests | Local shell | `make test` | Go tests pass. | No |
| Run docs-adjacent gate | Local shell | `make docs-check` | OpenAPI, vectors, SDK, deployment, collections, and metadata checks pass. | No |
| Run full gate | Local shell | `make finalize` | Formatting, lint, vulnerability, gosec, unit, race, contract, SDK, and metadata checks pass. | No |
| Apply migrations | Database URL | `go run ./cmd/whcp migrate up` | PostgreSQL schema reaches latest migration. | Yes, schema mutation |
| Start API | Runtime env | `go run ./cmd/whcp api` | API listens on configured address. | Process lifecycle |
| Run production doctor | Local config | `go run ./cmd/whcp doctor production` | `blocker`, `warning`, and `ok` findings without secrets. | Config disclosure |
| Check key custody | Secret custody env | `go run ./cmd/whcp key-custody test` | Encrypt/decrypt smoke succeeds without plaintext or ciphertext output. | Secret custody |

## Identity And Access

| Task | Required scope | Example | Expected outcome | Elevated risk |
|------|----------------|---------|------------------|---------------|
| Hash a local API key | Local shell | `go run ./cmd/whcp admin hash-key "$LOCAL_API_KEY"` | Prints a `sha256:` hash for bootstrap config. | Secret handling |
| Create API key | Owner or security-capable key | `go run ./cmd/whcp api-keys create --name local-operator --role owner --scopes '*' --api-key "$WEBHOOKERY_API_KEY"` | Returns a one-time API token and metadata. | Secret creation |
| Revoke API key | Owner or security-capable key | `go run ./cmd/whcp api-keys revoke --key-id key_... --reason "rotation" --api-key "$WEBHOOKERY_API_KEY"` | Key is revoked and cannot authenticate. | Access removal |
| Create identity provider | `security:write` | `go run ./cmd/whcp identity-providers create --name okta --issuer-url https://idp.example.com --client-id "$OIDC_CLIENT_ID" --client-secret "$OIDC_CLIENT_SECRET" --redirect-uri https://webhookery.example/v1/auth/oidc/callback --allowed-email-domains example.com --api-key "$WEBHOOKERY_API_KEY"` | OIDC provider metadata is created; secret is not returned. | Identity trust |
| Create SCIM token | `security:write` | `go run ./cmd/whcp scim-tokens create --name okta-scim --api-key "$WEBHOOKERY_API_KEY"` | Returns one-time token value and token metadata. | Secret creation |
| Bind role | `security:write` | `go run ./cmd/whcp role-bindings create --principal-type user --principal-id usr_... --role auditor --resource-family audit --environment production --reason "audit team access" --api-key "$WEBHOOKERY_API_KEY"` | Role binding is created and audited. | Authorization change |
| Add deny policy | `security:write` | `go run ./cmd/whcp access-policies create --name deny-prod-raw --action events:raw --effect deny --resource-family event --environment production --reason "limit raw payload exposure" --api-key "$WEBHOOKERY_API_KEY"` | Access policy is created and audited. | Authorization change |
| Explain authz | Relevant read access | `go run ./cmd/whcp authz explain --actor-id usr_... --action events:raw --resource-family event --resource-id evt_... --environment production --api-key "$WEBHOOKERY_API_KEY"` | Redacted decision with matched role/policy context. | No secrets expected |

## Events, Sources, And Providers

| Task | Required scope | Example | Expected outcome | Elevated risk |
|------|----------------|---------|------------------|---------------|
| List events | `events:read` | `go run ./cmd/whcp events list --api-key "$WEBHOOKERY_API_KEY"` | Paginated event metadata. | No raw body |
| View timeline | `events:read` | `go run ./cmd/whcp events timeline --event-id evt_... --api-key "$WEBHOOKERY_API_KEY"` | Receipt, delivery, attempt, and audit timeline. | No raw body |
| Export raw payload | `events:raw` | `go run ./cmd/whcp events raw-export --event-id evt_... --output payload.bin --api-key "$WEBHOOKERY_API_KEY"` | Writes raw bytes to a private local file. | Raw payload |
| Rotate source secret | `security:write` | `go run ./cmd/whcp sources rotate-secret --source-id src_... --secret "$NEXT_WEBHOOK_SECRET" --reason "scheduled rotation" --api-key "$WEBHOOKERY_API_KEY"` | New active secret version and bounded grace for prior version. | Secret rotation |
| Disable source | `sources:write` | `go run ./cmd/whcp sources update --source-id src_... --state disabled --reason "retire old webhook" --api-key "$WEBHOOKERY_API_KEY"` | Future ingress is rejected; historical evidence remains. | Ingress interruption |
| Create provider connection | `sources:write` | `go run ./cmd/whcp provider-connections create --name stripe-prod --provider stripe --credential "$PROVIDER_API_TOKEN" --config source_id=src_stripe --api-key "$WEBHOOKERY_API_KEY"` | Provider credential is encrypted and redacted metadata is returned. | Provider credential |
| Request adapter review | `security:write` | `go run ./cmd/whcp adapters transition --adapter-id pad_... --version-id adv_... --action request_review --reason "ready for security review" --api-key "$WEBHOOKERY_API_KEY"` | Adapter version moves through governance state. | Verification behavior |

Raw payloads and provider API responses may contain PII or customer data. Keep
exports out of commits and public support artifacts.

## Incidents And Reports

| Task | Required scope | Example | Expected outcome | Elevated risk |
|------|----------------|---------|------------------|---------------|
| Create incident | `incidents:write` | `go run ./cmd/whcp incidents create --title "Stripe payment webhook failed" --reason "support investigation" --api-key "$WEBHOOKERY_API_KEY"` | Incident metadata is created and audited. | Support artifact |
| Attach event | `incidents:write`, `events:read` | `go run ./cmd/whcp incidents add-event --incident-id inc_... --event-id evt_... --reason "failed downstream delivery" --api-key "$WEBHOOKERY_API_KEY"` | Event is linked to the incident in the same tenant. | Evidence grouping |
| Generate report | `incidents:write`, `events:read` | `go run ./cmd/whcp incidents generate-report --incident-id inc_... --reason "support handoff" --api-key "$WEBHOOKERY_API_KEY"` | JSON and Markdown report snapshot is generated and audited. | Evidence disclosure |
| Save report | `incidents:read` | `go run ./cmd/whcp incidents report --incident-id inc_... --format markdown --output incident-report.md --api-key "$WEBHOOKERY_API_KEY"` | Markdown report is written with private file permissions. | Support artifact |
| Export incident evidence | `incidents:write`, `events:read`, `audit:read` | `go run ./cmd/whcp incidents export --incident-id inc_... --reason "customer evidence package" --output incident-evidence.tar.gz --api-key "$WEBHOOKERY_API_KEY"` | Bundle includes `incident_report.json`, `incident_report.md`, timeline evidence, manifest, and hashes. | Evidence disclosure |

Incident reports use event timelines and hashes. They do not include raw
payload bodies, webhook secrets, signatures, bearer tokens, or private keys by
default. Exported incident bundles should be handled like other evidence
bundles and kept out of commits and public support channels.

## Routing, Delivery, And Replay

| Task | Required scope | Example | Expected outcome | Elevated risk |
|------|----------------|---------|------------------|---------------|
| Update endpoint URL | `routes:write` | `go run ./cmd/whcp endpoints update --endpoint-id end_... --url https://receiver.example/webhook --reason "move receiver" --api-key "$WEBHOOKERY_API_KEY"` | URL is SSRF-validated before commit. | Receiver egress |
| Rotate endpoint secret | `security:write` | `go run ./cmd/whcp endpoints rotate-secret --endpoint-id end_... --reason "scheduled rotation" --api-key "$WEBHOOKERY_API_KEY"` | New signing secret version is created; handle any rotation response as sensitive. | Secret rotation |
| Update route | `routes:write` | `go run ./cmd/whcp routes update --route-id rte_... --priority 10 --reason "prefer primary receiver" --api-key "$WEBHOOKERY_API_KEY"` | New route version is recorded. | Delivery fanout |
| Create retry policy | `routes:write` | `go run ./cmd/whcp retry-policies create --name standard --max-attempts 12 --max-duration-seconds 259200 --initial-delay-seconds 10 --max-delay-seconds 21600 --api-key "$WEBHOOKERY_API_KEY"` | Retry policy version is created. | Delivery volume |
| Retry delivery | `deliveries:retry` | `go run ./cmd/whcp deliveries retry --delivery-id del_... --reason "operator retry" --api-key "$WEBHOOKERY_API_KEY"` | New delivery attempt is scheduled. | Duplicate side effects |
| Create replay job | `replay:write` | `go run ./cmd/whcp replay-jobs create --event-id evt_... --config-mode original --rate-limit-per-minute 60 --require-approval --reason "customer replay request" --api-key "$WEBHOOKERY_API_KEY"` | Replay is scheduled or awaits approval. | Duplicate side effects |
| Approve replay job | `replay:write` | `go run ./cmd/whcp replay-jobs approve --replay-job-id rpl_... --reason "approved replay window" --api-key "$WEBHOOKERY_API_KEY"` | Replay approval is audited and work can proceed. | Duplicate side effects |
| Create reconciliation job | `replay:write` | `go run ./cmd/whcp reconciliation-jobs create --connection-id pcn_... --capture-missing --route-recovered --reason "recover missing provider events" --api-key "$WEBHOOKERY_API_KEY"` | Provider evidence job is created; recovered events route only when requested. | Recovery claims |

Replay and retry create new delivery work linked to existing evidence. They do
not mutate original event history.

## Schemas And Transformations

| Task | Required scope | Example | Expected outcome | Elevated risk |
|------|----------------|---------|------------------|---------------|
| Create transformation | `routes:write` | `go run ./cmd/whcp transformations create --name redact-email --operations-file operations.json --api-key "$WEBHOOKERY_API_KEY"` | Transformation is created with immutable versions. | Payload shaping |
| Dry-run transformation | Local file | `go run ./cmd/whcp transformations dry-run --payload-file payload.json --operations-file operations.json` | Prints transformed result for local review. | PII in local files |
| Update event type | `schemas:write` | `go run ./cmd/whcp schemas event-type-update --name invoice.paid --description "Invoice paid events" --reason "clarify contract" --api-key "$WEBHOOKERY_API_KEY"` | Event type metadata changes and is audited. | Contract change |
| Validate payload | `schemas:read` | `go run ./cmd/whcp schemas validate --name invoice.paid --version 2026-05-01 --payload-file payload.json --api-key "$WEBHOOKERY_API_KEY"` | Validation result is returned. | PII in local files |
| Check compatibility | `schemas:read` | `go run ./cmd/whcp schemas check-compat --name invoice.paid --version 2026-05-01 --new-schema-file schema-next.json --api-key "$WEBHOOKERY_API_KEY"` | Compatibility result is returned. | Contract change |

Payload and schema files can contain customer data or business-sensitive
contracts. Keep them out of commits unless deliberately sanitized.

## Audit, Retention, And Evidence

| Task | Required scope | Example | Expected outcome | Elevated risk |
|------|----------------|---------|------------------|---------------|
| Export evidence | `audit:read`; add `events:raw` for payload bodies | `go run ./cmd/whcp audit export --include-timelines --include-payloads --reason "support case" --api-key "$WEBHOOKERY_API_KEY"` | Evidence bundle is created with manifest and hashes. | Raw payload inclusion |
| Download export | `audit:read`; add `events:raw` when export includes bodies | `go run ./cmd/whcp audit download --export-id exp_... --output evidence.tar.gz --api-key "$WEBHOOKERY_API_KEY"` | Bundle is written locally. | Evidence disclosure |
| Verify bundle locally | Local file | `go run ./cmd/whcp audit verify-bundle --file evidence.tar.gz` | File hashes and audit-chain proof verify. | Sensitive local file |
| Verify audit chain | `audit:read` | `go run ./cmd/whcp audit verify-chain --api-key "$WEBHOOKERY_API_KEY"` | Chain verification result is returned. | No raw body |
| Anchor audit chain | `security:write` | `go run ./cmd/whcp audit anchor --reason "daily anchor" --api-key "$WEBHOOKERY_API_KEY"` | Anchor is written after verification. | Evidence governance |
| Create retention policy | `security:write` | `go run ./cmd/whcp retention create --resource-type raw_payload --retention-days 30 --api-key "$WEBHOOKERY_API_KEY"` | Retention policy is created and audited. | Destructive retention |
| Place legal hold | `security:write` | `go run ./cmd/whcp retention update --policy-id ret_... --legal-hold --hold-reason "customer legal request" --api-key "$WEBHOOKERY_API_KEY"` | Policy is held and skipped by retention worker. | Legal/retention |

Evidence exports with payloads are sensitive. Use scoped authorization, private
file permissions, and a recorded reason.

## Operations, Alerts, And Signal Egress

| Task | Required scope | Example | Expected outcome | Elevated risk |
|------|----------------|---------|------------------|---------------|
| Read metrics | `ops:read` | `go run ./cmd/whcp ops metrics --api-key "$WEBHOOKERY_API_KEY"` | Tenant-scoped operational metrics. | No secrets expected |
| Read queues | `ops:read` | `go run ./cmd/whcp ops queues --api-key "$WEBHOOKERY_API_KEY"` | Durable outbox and delivery queue status. | Operational posture |
| Create alert | `ops:write` | `go run ./cmd/whcp alerts create --name dlq-open --rule-type dead_letter_open --threshold 1 --reason "page on DLQ growth" --api-key "$WEBHOOKERY_API_KEY"` | Alert rule is created. | Paging behavior |
| Create notification channel | `ops:write` | `go run ./cmd/whcp notification-channels create --name ops-webhook --url https://ops.example/hooks/webhookery --signing-secret "$SIGNAL_SECRET" --api-key "$WEBHOOKERY_API_KEY"` | Signed alert egress channel is created. | External egress and secret |
| Retry notification | `ops:write` | `go run ./cmd/whcp notification-deliveries retry --delivery-id ndl_... --reason "receiver fixed" --api-key "$WEBHOOKERY_API_KEY"` | Notification delivery is rescheduled. | External egress |
| Create SIEM sink | `security:write` | `go run ./cmd/whcp siem-sinks create --name audit-stream --url https://siem.example/ingest --signing-secret "$SIEM_SIGNAL_SECRET" --api-key "$WEBHOOKERY_API_KEY"` | Signed SIEM sink is created. | Audit egress and secret |
| List SIEM failures | `audit:read` | `go run ./cmd/whcp siem-deliveries list --state failed --api-key "$WEBHOOKERY_API_KEY"` | Failed SIEM deliveries are listed. | Audit egress status |

Signal and SIEM signing secrets are secrets. Use placeholders in docs and
managed secrets in deployments.

## Backup, Restore, Release, And Collections

| Task | Required scope | Example | Expected outcome | Elevated risk |
|------|----------------|---------|------------------|---------------|
| Back up PostgreSQL | Database URL | `scripts/backup_postgres.sh backups` | Timestamped dump is written with restrictive permissions. | Sensitive backup |
| Restore PostgreSQL | Database URL and confirmation | `WEBHOOKERY_RESTORE_CONFIRM=restore scripts/restore_postgres.sh backups/webhookery-20260525T000000Z.dump` | Target DB is restored with `pg_restore --clean --if-exists`. | Destructive restore |
| Start local MinIO profile | Local shell | `docker compose --profile object-storage up --build` | Compose starts object-storage services. | Local credentials only |
| Lint Helm profile | Local Helm | `helm lint deploy/helm/webhookery` | Chart lint passes. | No |
| Check Terraform formatting | Local Terraform | `terraform fmt -check -recursive deploy/terraform` | Terraform files are formatted. | No |
| Release evidence checks | Local shell | `make release-acceptance` | Release evidence metadata checks pass. | No live providers |
| RC checks | Local shell, optional test DB URLs | `make rc-check` | RC acceptance checks pass or skip live DB work when URLs are absent. | May run destructive restore drill when restore DB URL is set |
| Collection checks | Local shell | `make collections-check` | Postman and Bruno smoke files are present and shaped correctly. | No |

Backups, restore targets, and evidence bundles can contain sensitive operational
data. Do not commit generated backup files, raw payload exports, or release
evidence containing real customer data.
