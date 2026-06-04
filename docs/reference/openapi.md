# OpenAPI Reference

`openapi.yaml` is the canonical REST API contract for Webhookery API version `0.1.0`.

Self-hosted webhook evidence and delivery control plane.

- Rendered HTML reference: [`docs/openapi/index.html`](../openapi/index.html)
- API contract matrix: [`docs/reference/api-contract-matrix.md`](api-contract-matrix.md)
- Total operations: `214`

## Operations By Tag

| Tag | Operations |
| --- | ---: |
| API Keys | 3 |
| Audit And Retention | 13 |
| Auth And Identity | 36 |
| Delivery And Replay | 22 |
| Endpoints And Routing | 26 |
| Events And Ingestion | 13 |
| Incidents | 8 |
| Operations | 16 |
| Producer Trust | 13 |
| Reconciliation | 6 |
| Schemas And Transformations | 18 |
| Signal Egress | 18 |
| Sources And Providers | 18 |
| System | 4 |

## Maintenance

When `openapi.yaml` changes, run `make openapi-reference-generate` and commit the regenerated reference artifacts with the contract change. `make openapi-reference-check` verifies that the generated files are current.
