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
