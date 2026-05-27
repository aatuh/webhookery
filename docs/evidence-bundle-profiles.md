# Evidence Bundle Profiles

This reference defines approved export profiles for common review audiences.
The current implementation exposes export inclusion flags, not a named
`--profile` CLI option. Use these profiles as policy labels when choosing
`whcp audit export` flags, reviewing incident exports, and deciding whether a
bundle is safe to share.

Raw payload bodies are never part of a default profile. Including raw payloads
or normalized/delivery payload bodies requires elevated permission, a reason,
and a separate review before sharing.

## Profile Matrix

| Profile | Audience | Include | Exclude by default | Review rule |
|---------|----------|---------|--------------------|-------------|
| `minimal-hash-proof` | External reviewer who only needs bundle integrity proof. | `manifest.json`, file hashes, audit-chain proof when present, non-claims. | Timelines, raw payload bodies, normalized payload bodies, provider response bodies. | Safe starting point for public examples after path and identifier review. |
| `customer-support` | Customer support or customer-facing incident handoff. | Incident report, event identity, verification status, delivery/replay timeline, hashes, redacted errors, non-claims. | Raw payload bodies, secrets, signatures, bearer tokens, provider credentials, private endpoint URLs. | Share only after support owner confirms identifiers and messages are sanitized. |
| `commercial-evaluation` | Paid evaluator or production-readiness reviewer. | Incident report, manifest, timelines, audit proof, provider conformance references, pilot evidence checklist, accepted risks. | Raw bodies unless explicitly approved in private scope. | Attach to `docs/pilot-evidence-template.md` and keep completed evidence outside public source. |
| `security-review` | Security reviewer under private review scope. | Manifest, audit events, audit-chain proof, config evidence, timelines, redaction policy, relevant incident report. | Secrets, bearer tokens, private keys, plaintext webhook secrets, unnecessary PII. | May include sensitive metadata only under the private review scope in `docs/security-review-package.md`. |
| `internal-forensics` | Internal SRE/security investigation. | Full manifest, timelines, audit events, chain proof, incident report, reconciliation evidence, hashes. | Raw bodies unless the investigator has `events:raw` and a recorded reason. | Keep in restricted storage; do not forward as a support artifact without downscoping. |

## CLI Flag Mapping

Use the current flags to approximate a profile:

| Profile | Example flags |
|---------|---------------|
| `minimal-hash-proof` | `whcp audit export --reason "hash proof for review"` |
| `customer-support` | `whcp audit export --include-timelines --reason "customer support incident handoff"` |
| `commercial-evaluation` | `whcp audit export --include-timelines --reason "commercial evaluation evidence"` |
| `security-review` | `whcp audit export --include-timelines --reason "security review evidence"` |
| `internal-forensics` | `whcp audit export --include-timelines --reason "internal incident investigation"` |

Only add `--include-raw` or `--include-payloads` when the actor has the
required raw-payload permission, the reason is specific, and the destination is
private. Those flags can expose sensitive payload data and should not be used
for customer-support or public examples by default.

## Incident Exports

Incident evidence exports should default to the `customer-support` shape:

- include `incident_report.json` and `incident_report.md`;
- include timelines, manifest, hashes, and audit references;
- include non-claims from `docs/security-promise.md`; and
- omit raw payload bodies, webhook secrets, signatures, bearer tokens,
  private keys, provider credentials, and endpoint secrets.

If a reviewer needs more than the customer-support shape, create a private
review scope first and record the reason in the export request.

## Verification

Every shared bundle should be verified locally before handoff:

```bash
go run ./cmd/whcp audit verify-bundle --file evidence.tar.gz
```

Expected result: verification returns `valid: true`. A valid bundle proves the
local manifest and file hashes are consistent; it does not prove provider-side
event completeness, downstream business success, legal admissibility, or
exactly-once delivery.
