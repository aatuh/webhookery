# Error Codes

Webhookery API problem responses include two code fields:

- `code`: a short legacy problem code kept for compatibility.
- `stable_code`: a namespaced code intended for CLI output, SDK handling,
  support triage, and incident reports.

Problem responses also include `request_id`. Do not include bearer tokens,
webhook secrets, raw signatures, raw payload bodies, database URLs, private
keys, provider credentials, or unnecessary PII in problem details.

## Major Stable Codes

| Stable code | Typical status | Meaning | Operator action |
|-------------|----------------|---------|-----------------|
| `WEBHOOKERY_AUTHENTICATION_REQUIRED` | 401 | Bearer token, session, or client credential is missing or invalid. | Retry with a valid credential; rotate if exposure is suspected. |
| `WEBHOOKERY_TENANT_ACCESS_DENIED` | 403 | Actor lacks tenant membership, scope, role, or raw-payload permission. | Check API key scopes, role bindings, access policies, and tenant context. |
| `WEBHOOKERY_VALIDATION_FAILED` | 400 | Request body, query, path, or form input is malformed or unsupported. | Fix the request shape using `openapi.yaml` and preserve `request_id` for support. |
| `WEBHOOKERY_PROVIDER_SIGNATURE_INVALID` | 401 | Provider webhook evidence was captured, but signature verification failed. | Check provider secret, exact raw body handling, timestamp policy, and source configuration. |
| `WEBHOOKERY_DURABLE_CAPTURE_UNAVAILABLE` | 503 | Required durable capture dependency is unavailable before acknowledgement. | Do not force success; restore PostgreSQL/object-storage health and retry. |
| `WEBHOOKERY_RAW_PAYLOAD_RETAINED_METADATA_ONLY` | 410 | Raw body was removed or expired by retention while metadata and hashes remain. | Use metadata, hashes, timeline, and audit evidence; do not treat body absence as silent loss. |
| `WEBHOOKERY_SSRF_BLOCKED_DESTINATION` | 400 | Customer-controlled endpoint, notification, or SIEM URL failed SSRF policy. | Use an allowed HTTPS destination and revalidate redirects/DNS behavior. |
| `WEBHOOKERY_PAYLOAD_TOO_LARGE` | 413 | Request body exceeds configured capture limit. | Adjust provider/source configuration or size limits only after risk review. |
| `WEBHOOKERY_HEADERS_TOO_LARGE` | 431 | Header count or total header bytes exceed ingress limits. | Reduce headers or review configured limits. |
| `WEBHOOKERY_RESOURCE_NOT_FOUND` | 404 | Resource does not exist or is not visible to the actor's tenant. | Confirm ID and tenant scope. |
| `WEBHOOKERY_INTERNAL_ERROR` | 500 | Unexpected server-side failure. | Preserve `request_id`, check logs/metrics, and avoid exposing internal detail. |
| `WEBHOOKERY_UNKNOWN_ERROR` | varies | Fallback for a future or unmapped problem code. | Preserve response body and `request_id`; update client handling if this recurs. |

## CLI Behavior

For API calls that decode a response internally, `whcp` returns errors that
include the HTTP status, `stable_code` when present, and `request_id` when
present. The CLI must not include bearer tokens or raw request bodies in those
errors.

For commands that stream raw JSON responses, the API problem body is written as
returned by the server and the command exits non-zero on non-2xx status.

## Incident Reports

Incident reports may reference stable error codes from delivery attempts,
replay previews, retention reads, or support notes. A stable code is evidence
for local Webhookery behavior; it does not prove downstream business success,
provider-side completeness, exactly-once delivery, or legal/compliance
certification.
