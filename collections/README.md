# Request Collection Smoke Paths

Webhookery includes small Postman and Bruno collections for local smoke checks.
They are not full API coverage and they do not replace `make docs-check`,
`make rc-check`, or OpenAPI contract tests.

## Files

| Collection | Path |
|------------|------|
| Postman | `collections/postman/webhookery.postman_collection.json` |
| Bruno | `collections/bruno/Webhookery/` |

Run the static collection shape check with:

```bash
make collections-check
```

That check verifies committed files and key routes. It does not send live HTTP
requests.

## Local Variables

Set these variables before sending requests:

| Variable | Example | Notes |
|----------|---------|-------|
| `base_url` | `http://localhost:8080` | Local API URL. |
| `api_key` | `dev-bootstrap-key` | Local bootstrap key only. Replace with a database-backed API key outside local development. |
| `tenant_id` | `ten_dev` | Must match the local tenant. |
| `source_id` | `src_...` | Replace with a real generic HMAC source ID before sending ingest smoke requests. |

The generic ingest request uses this placeholder header:

```text
Webhook-Signature: sha256=replace-with-hmac-sha256-hex
```

Replace it with an HMAC-SHA256 hex digest over the exact raw request body using
the source verification secret. Do not put a real source secret into the
collection file. Keep it in the collection runner's local variable store or a
secret manager.

## Smoke Requests

| Request | Expected response | What it proves |
|---------|-------------------|----------------|
| Readiness | `200` from `/readyz` | API process can reach required dependencies. |
| List Events | `200` JSON page from `/v1/events` | Bearer auth works and the tenant can read event metadata. |
| Ingest Generic Event | `200` JSON with `received: true` when `source_id` exists and the HMAC is valid. Placeholder signatures should fail. | Durable provider-style capture path works for a signed generic HMAC source. |
| Audit Chain Head | `200` JSON from `/v1/audit-chain/head` | Audit-chain metadata is readable with the configured API key. |
| Verify Audit Chain | `200` JSON verification result from `/v1/audit-chain:verify` | Audit-chain verification endpoint is reachable and returns current chain status. |

Inbound success proves durable capture and verification metadata for that
request. It does not prove downstream business processing succeeded.

## Postman

1. Import `collections/postman/webhookery.postman_collection.json`.
2. Select or create an environment with the variables above.
3. Start Webhookery locally:

   ```bash
   cp .env.example .env
   docker compose up --build
   ```

4. Run `Readiness`, then authenticated read requests.
5. Before running `Ingest Generic Event`, replace `source_id` and
   `Webhook-Signature` with values for a local generic HMAC source.

## Bruno

1. Open `collections/bruno/Webhookery/` in Bruno.
2. Use the committed `local` environment as a starting point.
3. Replace `source_id` and the ingest `Webhook-Signature` header before sending
   the generic ingest request.
4. Run requests in sequence: readiness, list events, optional signed ingest,
   audit-chain head, audit-chain verify.

## Safety

Do not commit modified collections containing real API keys, source secrets,
provider credentials, raw payload bodies, customer data, or generated evidence.
Placeholder signatures are intentional in committed collection files.
