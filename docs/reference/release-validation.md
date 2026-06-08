# Release Validation

Webhookery release validation is evidence-first. Passing local checks is
necessary, but it does not turn a release candidate into a broad production
guarantee, provider certification, compliance certification, exactly-once
delivery proof, or legal evidentiary certification.

## Local Gates

Run these from a clean checkout before preparing release evidence:

```sh
make docs-check
make release-acceptance
make rc-check
make finalize
```

For DB-backed release-candidate evidence, run with a disposable PostgreSQL
database:

```sh
WEBHOOKERY_TEST_DATABASE_URL=postgres://... make rc-check
WEBHOOKERY_TEST_DATABASE_URL=postgres://... make live-postgres-check
```

For destructive restore evidence, use a disposable or explicitly approved
database:

```sh
WEBHOOKERY_RESTORE_DRILL_DATABASE_URL=postgres://... make restore-drill
```

## Public Metadata Gates

These checks keep public repository metadata aligned with implementation
artifacts:

```sh
make openapi-reference-check
make meta-files-check
make static-site-check
```

`make openapi-reference-check` verifies that `docs/openapi/index.html`,
`docs/reference/openapi.md`, and `docs/reference/api-contract-matrix.md` match
the canonical `openapi.yaml`.

## Evidence To Record

Each tagged release evidence packet should record:

- tag, source commit, release workflow run, and image digest when an image is
  published;
- `make release-acceptance`, `make rc-check`, and `make finalize` output;
- DB-backed `make rc-check` and `make live-postgres-check` output when a
  disposable database is available;
- restore drill output or an accepted-risk decision when skipped;
- OpenAPI and migration checksum summaries;
- source and image SBOM references when generated;
- Trivy, govulncheck, gosec, CodeQL, and Scorecard status;
- provider conformance and provider proof metadata status;
- branch protection or repository ruleset status;
- external review status or accepted-risk decision;
- live-provider proof status, if available and sanitized.

## Current Release Candidate

`release/current.json` points to the current public release candidate and the
next pilot-readiness checklist. GitHub Releases remains the external source of
truth for published tags and assets.
