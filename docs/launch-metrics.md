# Launch Metrics Plan

Webhookery's first public release should optimize for qualified evaluations and
conversations, not vanity metrics alone.

Do not add invasive product analytics, runtime tracking scripts, customer
payload collection, or tenant-labeled public metrics for launch measurement.

## Primary Metrics

| Metric | Why it matters | Collection method |
| --- | --- | --- |
| Qualified commercial inquiries | Best early revenue signal. | Manual CRM or private tracker. |
| Evaluation calls booked | Shows real buyer pain. | Calendar or manual tracker. |
| Evaluator quickstart completions | Shows the local path works. | Voluntary feedback, issues, or calls. |
| Release downloads / image pulls | Shows install interest. | GitHub release and GHCR stats where available. |
| Issues from real evaluators | Shows friction and missing docs. | GitHub issues with sanitized templates. |
| Pilot requests | Shows commercial intent. | Manual tracker. |

## Secondary Metrics

- GitHub stars.
- repository clones.
- docs page visits if a privacy-respecting static-site analytics setup is
  approved later.
- support-package inquiries.
- release evidence package requests.

Secondary metrics help with distribution but should not drive product scope by
themselves.

## Review Cadence

Review launch signals weekly for the first four weeks after `v0.1.0-rc1`:

1. Count qualified conversations.
2. Classify issues as bug, docs gap, evaluator friction, missing integration,
   or unrelated feature request.
3. Identify repeated blockers.
4. Update the pilot feedback tracker.
5. Decide whether the next implementation slice is docs, hardening, provider
   compatibility, commercial packaging, or bug fixes.

## Private Tracker Template

Keep the launch tracker private unless every row is sanitized for public
sharing. A spreadsheet, CRM, or private issue board is enough; do not add
runtime analytics or product telemetry to collect these fields.
If you use a file-based tracker in this checkout, keep it under
`launch-metrics-private/`; that path is ignored by git and Docker build
contexts.

| Week | Metric | Count | Source | Quality notes | Follow-up owner | Next action |
| --- | --- | ---: | --- | --- | --- | --- |
| `2026-W__` | Qualified commercial inquiries | 0 | Manual CRM/private tracker | Segment, provider mix, and urgency only. |  |  |
| `2026-W__` | Evaluation calls booked | 0 | Calendar/private tracker | Record pain category, not sensitive details. |  |  |
| `2026-W__` | Evaluator quickstart completions | 0 | Voluntary feedback/issues/calls | Link sanitized issue or notes. |  |  |
| `2026-W__` | Release downloads/image pulls | 0 | GitHub/GHCR stats | Aggregate counts only. |  |  |
| `2026-W__` | Issues from real evaluators | 0 | GitHub issues/private tracker | Classify as bug, docs gap, or evaluator friction. |  |  |
| `2026-W__` | Pilot requests | 0 | Manual tracker | Track stage and next decision. |  |  |

For each serious evaluator, link to `docs/pilot-feedback-template.md` or a
private sanitized equivalent. Store customer-identifying details only in the
private tracker, never in public release evidence.

## Privacy Boundary

Launch metrics must not collect:

- API keys
- bearer tokens
- session cookies
- webhook secrets
- raw provider signatures
- private keys
- provider credentials
- raw payload bodies
- customer PII
- tenant IDs in public metrics
- database URLs with passwords

## Success Criteria For The First Release Candidate

The release candidate is successful if it produces:

- at least a few qualified conversations with teams that have webhook evidence,
  replay, audit, or self-hosting pain
- actionable evaluator feedback
- a short list of repeated blockers
- no need to weaken the product's non-claims

It is not a failure if stars are modest while qualified evaluations are strong.
