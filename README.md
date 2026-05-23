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
go run ./cmd/whcp events raw-export --event-id evt_... --output payload.bin --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit export --include-timelines --reason "support case" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit export-status --export-id exp_... --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp audit download --export-id exp_... --output evidence.tar.gz --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp retention create --resource-type raw_payload --retention-days 30 --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp retry-policies create --name standard --max-attempts 12 --max-duration-seconds 259200 --initial-delay-seconds 10 --max-delay-seconds 21600 --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp routes create --source-id src_... --endpoint-id end_... --event-types invoice.paid --retry-policy-id rtp_...
go run ./cmd/whcp routes versions --route-id rte_... --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp sources rotate-secret --source-id src_... --secret whsec_next --reason "scheduled rotation" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp endpoints rotate-secret --endpoint-id end_... --reason "scheduled rotation" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp schemas validate --name invoice.paid --version 2026-05-01 --payload-file payload.json --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp schemas check-compat --name invoice.paid --version 2026-05-01 --new-schema-file schema-next.json --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp endpoints test --endpoint-id end_... --reason "verify receiver" --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp deliveries retry --delivery-id del_... --reason "operator retry"
go run ./cmd/whcp replay-jobs create --event-id evt_... --config-mode original --rate-limit-per-minute 60 --reason "customer replay request"
go run ./cmd/whcp ops metrics --api-key "$WEBHOOKERY_API_KEY"
```

Set `WEBHOOKERY_ENABLE_UI=true` to expose the minimal operator console at `/`.
The UI keeps the entered API key in browser memory only and calls the same
tenant-scoped REST API as the CLI.

Raw payload bodies are stored in PostgreSQL by default. To use S3-compatible
storage, set `WEBHOOKERY_RAW_STORAGE_MODE=s3` plus the
`WEBHOOKERY_OBJECT_STORAGE_*` variables. In S3 mode, inbound success requires
the object write and PostgreSQL metadata commit to both succeed.

For local MinIO testing:

```bash
docker compose --profile object-storage up --build
```

## Security Promise

Webhookery does not promise exactly-once delivery. Inbound success means the
platform durably captured raw request evidence and verification metadata. Every
loss boundary, duplicate, replay, and delivery attempt is intended to remain
visible and auditable.
