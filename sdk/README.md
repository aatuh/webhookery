# Webhookery SDK Artifacts

This directory contains committed SDK-facing artifacts for local use and
release evidence.

| Artifact | Audience | Status |
|----------|----------|--------|
| `sdk/openapi.yaml` | SDK maintainers and API consumers | Derived copy of root `openapi.yaml`; keep aligned with `make sdk-generate` and `make sdk-check`. |
| `pkg/client` | Go producers and audit tooling | Small Go REST client for product event ingestion and audit-chain verification. |
| `sdk/python` | Python producers and audit tooling | Stdlib-only local Python client for the same core calls. |
| `sdk/typescript` | TypeScript producers and audit tooling | Fetch-based local TypeScript client for the same core calls. |

These clients cover a deliberately small surface:

- `POST /v1/events`
- `GET /v1/audit-chain/head`
- `POST /v1/audit-chain:verify`

Use `openapi.yaml` for the full REST contract.

## Authentication

All committed clients use bearer API keys:

```text
Authorization: Bearer <api-key>
```

Use `WEBHOOKERY_API_KEY` or a secret manager in real environments. Do not put
real API keys, provider credentials, webhook secrets, raw payload bodies, raw
signatures, private keys, or customer data in docs, tests, issues, support
artifacts, or generated examples.

## Go

Setup from this repository:

```bash
go test ./pkg/client
```

Producer event ingestion:

```go
package main

import (
	"context"
	"os"

	"webhookery/pkg/client"
)

func main() error {
	c, err := client.New("http://localhost:8080", os.Getenv("WEBHOOKERY_API_KEY"))
	if err != nil {
		return err
	}

	_, err = c.CreateEvent(context.Background(), client.ProductEvent{
		ID:       "evt_product_123",
		Type:     "demo.created",
		SourceID: "src_internal",
		Data:     map[string]any{"ok": true},
	}, client.WithIdempotencyKey("demo-event-123"))
	return err
}
```

Audit-chain verification:

```go
head, err := c.AuditChainHead(context.Background())
if err != nil {
	return err
}
_ = head

verification, err := c.VerifyAuditChain(context.Background(), client.AuditChainVerifyRequest{})
if err != nil {
	return err
}
if !verification.Valid {
	return errors.New("audit chain did not verify")
}
```

## Python

Setup from this repository:

```bash
PYTHONPATH=sdk/python python3 -m unittest discover -s sdk/python/tests
```

Producer event ingestion:

```python
import os
from webhookery import WebhookeryClient

client = WebhookeryClient("http://localhost:8080", os.environ["WEBHOOKERY_API_KEY"])

client.create_event(
    {
        "id": "evt_product_123",
        "type": "demo.created",
        "source_id": "src_internal",
        "data": {"ok": True},
    },
    idempotency_key="demo-event-123",
)
```

Audit-chain verification:

```python
head = client.audit_chain_head()
verification = client.verify_audit_chain()
if not verification.get("valid"):
    raise RuntimeError("audit chain did not verify")
```

## TypeScript

Setup from this repository:

```bash
tsc -p sdk/typescript/tsconfig.json
node --test sdk/typescript/test/client.test.mjs
```

Producer event ingestion:

```ts
import { WebhookeryClient } from "@webhookery/client";

const client = new WebhookeryClient(
  "http://localhost:8080",
  process.env.WEBHOOKERY_API_KEY ?? "",
);

await client.createEvent(
  {
    id: "evt_product_123",
    type: "demo.created",
    source_id: "src_internal",
    data: { ok: true },
  },
  { idempotencyKey: "demo-event-123" },
);
```

Audit-chain verification:

```ts
const head = await client.auditChainHead();
void head;

const verification = await client.verifyAuditChain();
if (verification.valid !== true) {
  throw new Error("audit chain did not verify");
}
```

## Error Handling And Redaction

Client constructors validate base URLs and require API keys where the language
client can enforce it. HTTP errors include status codes and bounded response
bodies, but clients do not add API key material to error messages.

The server is responsible for returning redacted problem details. SDK tests
include checks that API keys are not included in client error messages. Treat
raw event data, evidence bundles, and local payload files as sensitive even
when the client library does not log them.
