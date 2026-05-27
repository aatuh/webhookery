# Shopify Operator Guide

This guide is for operators configuring Shopify as a Webhookery source. It
covers the implemented Webhookery behavior and the Shopify behavior that was
checked against official docs on 2026-06-04.

## Scope

Implemented Webhookery behavior:

- `X-Shopify-Hmac-SHA256` base64 HMAC-SHA256 verification over the exact raw
  body.
- Delivery identity from `X-Shopify-Webhook-Id`.
- Event type from `X-Shopify-Topic`.
- Shop domain metadata from Shopify delivery headers when present.
- Duplicate deliveries remain visible as evidence; dedupe can suppress
  processing but must not erase receipts or raw payload metadata.
- Replay creates new Webhookery delivery work linked to the original evidence.

This guide does not claim Shopify provider certification, provider-side event
completeness, ordering, exactly-once delivery, or downstream business success.
In short: this is not provider certification.

Official sources checked:

- <https://shopify.dev/docs/apps/build/webhooks>
- <https://shopify.dev/docs/apps/build/webhooks/delivery-structure>
- <https://shopify.dev/docs/apps/build/webhooks/verify-deliveries>
- <https://shopify.dev/docs/apps/build/webhooks/troubleshoot>

## Setup

Use a development store or test app first. Do not use production shop data for
proof runs.

1. Start Webhookery and set a control-plane API key:

   ```bash
   cp .env.example .env
   docker compose up --build
   export WEBHOOKERY_API_KEY=dev-bootstrap-key
   ```

2. Store the Shopify app client secret in a local shell or secret manager. Do
   not commit it or paste it into issues.

   ```bash
   export WEBHOOKERY_SHOPIFY_CLIENT_SECRET='replace-with-app-client-secret'
   ```

3. Create a Shopify source:

   ```bash
   go run ./cmd/whcp sources create \
     --name shopify-development-store \
     --provider shopify \
     --secret "$WEBHOOKERY_SHOPIFY_CLIENT_SECRET" \
     --api-key "$WEBHOOKERY_API_KEY"
   ```

4. Save the returned source ID outside commits:

   ```bash
   export WEBHOOKERY_SHOPIFY_SOURCE_ID=src_replace_me
   ```

5. Configure a Shopify webhook subscription for a development-store topic such
   as `products/create`:

   ```text
   https://webhookery.example.test/v1/ingest/shopify/${WEBHOOKERY_SHOPIFY_SOURCE_ID}
   ```

Use HTTPS for public Shopify deliveries. During local development, use your
normal Shopify development tunnel or another temporary webhook proxy, and
remove it after the proof.

## Signature Verification

Shopify HTTPS deliveries include a base64 HMAC signature in
`X-Shopify-Hmac-SHA256`, generated with the app client secret and raw request
body. Webhookery verifies the raw body before treating the event as trusted.

Keep these operating rules:

- Preserve exact raw request bytes until verification completes.
- Use the app client secret that Shopify uses for the app sending the webhook.
- Reject or quarantine missing, malformed, or wrong-secret signatures.
- Verify before trusting topic, shop domain, or payload content.

## Event ID And Type Extraction

Webhookery normalizes:

| Shopify header | Webhookery use |
|----------------|----------------|
| `X-Shopify-Webhook-Id` | provider delivery identity and dedupe key |
| `X-Shopify-Topic` | event type, for example `products/create` |
| `X-Shopify-Shop-Domain` | shop metadata |
| `X-Shopify-Event-Id` | correlation metadata when present |

If the same merchant action produces multiple deliveries, Shopify can provide
separate webhook IDs with a shared event ID. Keep both values visible in
evidence where present.

## Duplicate Handling

Shopify says apps can receive the same webhook more than once, for example
after a timeout or retry. Webhookery records duplicate receipts instead of
overwriting evidence. Downstream handlers should still be idempotent.

## Retry Expectations

Shopify expects a `200` series response for successful HTTPS delivery. Current
official docs say failed deliveries are retried up to 8 times; troubleshooting
docs describe this as an 8-attempt retry pattern over a four-hour period.

Webhookery's downstream delivery retries are separate from Shopify's provider
retries. Webhookery may have durably captured the Shopify delivery even when a
customer receiver later fails.

## Manual Recovery Limitations

Do not claim universal Shopify recovery. Some gaps can be investigated by
checking Shopify delivery logs or by querying Shopify resource APIs for a
specific topic, but that is topic-specific reconciliation evidence. It is not
signed webhook evidence and it is not proof that every provider-side event can
be recovered.

## Route By Topic

Create a route for the Shopify topic you subscribed to:

```bash
export WEBHOOKERY_RECEIVER_URL='https://receiver.example.test/fail-first'

go run ./cmd/whcp endpoints validate-url \
  --url "$WEBHOOKERY_RECEIVER_URL" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp endpoints create \
  --name shopify-proof-receiver \
  --url "$WEBHOOKERY_RECEIVER_URL" \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_ENDPOINT_ID=end_replace_me

go run ./cmd/whcp routes create \
  --name shopify-products-proof \
  --source-id "$WEBHOOKERY_SHOPIFY_SOURCE_ID" \
  --endpoint-id "$WEBHOOKERY_ENDPOINT_ID" \
  --event-types products/create \
  --state draft \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_ROUTE_ID=rte_replace_me

go run ./cmd/whcp routes activate \
  --route-id "$WEBHOOKERY_ROUTE_ID" \
  --reason "shopify proof route activation" \
  --api-key "$WEBHOOKERY_API_KEY"
```

## Development-Store Proof

Trigger the subscribed topic in a development store. For example, create a
product to trigger `products/create`.

```bash
go run ./cmd/whcp events list --api-key "$WEBHOOKERY_API_KEY"
export WEBHOOKERY_EVENT_ID=evt_replace_me
go run ./cmd/whcp events timeline \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --format markdown \
  --api-key "$WEBHOOKERY_API_KEY"
```

Expected evidence:

- provider verification is valid;
- topic and webhook ID metadata are present;
- route matching uses the configured topic;
- downstream failure and replay evidence remain separate from Shopify retry
  evidence.

## Replay Workflow

After the receiver is fixed, replay with an explicit reason:

```bash
go run ./cmd/whcp replay-jobs dry-run \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --config-mode original \
  --reason-code receiver_fixed \
  --reason "shopify proof receiver fixed before replay" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp replay-jobs create \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --config-mode original \
  --reason-code receiver_fixed \
  --reason "shopify proof receiver fixed before replay" \
  --api-key "$WEBHOOKERY_API_KEY"
```

If the event reached DLQ, release the DLQ entry instead:

```bash
go run ./cmd/whcp dead-letter list --api-key "$WEBHOOKERY_API_KEY"
export WEBHOOKERY_DLQ_ID=dlq_replace_me
go run ./cmd/whcp dead-letter release \
  --entry-id "$WEBHOOKERY_DLQ_ID" \
  --reason-code receiver_fixed \
  --reason "shopify proof receiver recovered" \
  --api-key "$WEBHOOKERY_API_KEY"
```

## Incident Packet Example

Generate a report and evidence export after replay:

```bash
go run ./cmd/whcp incidents create \
  --title "Shopify development-store webhook failed then replayed" \
  --reason "shopify proof investigation" \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_INCIDENT_ID=inc_replace_me

go run ./cmd/whcp incidents add-event \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --reason "attach Shopify development-store delivery" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents generate-report \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --reason "shopify proof report" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents report \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --format markdown \
  --output shopify-incident-report.private.md \
  --api-key "$WEBHOOKERY_API_KEY"
```

Keep completed live reports and bundles private. Commit only sanitized samples
such as `docs/live-provider-proof/samples/shopify-incident-report.redacted.md`.

## Non-Claims

This guide does not prove:

- downstream business processing succeeded;
- Shopify will redeliver every provider-side event forever;
- universal recovery for every topic;
- global event ordering;
- exactly-once delivery;
- compliance or legal evidentiary certification; or
- safe use of production shop data in public evidence.

