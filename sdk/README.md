# Webhookery SDK Artifacts

`sdk/openapi.yaml` is the committed SDK-ready OpenAPI source copied from the
canonical root `openapi.yaml`. `pkg/client` contains a small Go client for
producer event ingestion and audit-chain verification over the REST API.

Operator request collections are committed under `collections/postman` and
`collections/bruno`.

```go
c, err := client.New("http://localhost:8080", os.Getenv("WEBHOOKERY_API_KEY"))
if err != nil {
    return err
}
_, err = c.CreateEvent(ctx, client.ProductEvent{
    ID: "evt_product_123",
    Type: "invoice.paid",
    SourceID: "src_internal",
    Data: map[string]any{"invoice_id": "inv_123"},
})
```
