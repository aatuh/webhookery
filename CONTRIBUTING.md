# Contributing

Webhookery accepts contributions selectively. The project uses an AGPL public
license plus optional commercial license exceptions, so contribution rights must
be handled deliberately.

## License Requirement

By default, Webhookery is licensed under `AGPL-3.0-only`.

Substantive external contributions require explicit maintainer approval and a
contributor license agreement before merge. The purpose is to preserve the
ability to offer commercial license exceptions while keeping the public
repository available under AGPL. Issue reports and high-level discussion do not
require a contributor license agreement.

Do not submit code, docs, tests, schemas, generated artifacts, or provider
vectors unless you have the right to license them to the project under terms
compatible with this model.

## Development Rules

Before opening a change:

1. Read `AGENTS.md`, `.initial_design.md`, `README.md`, `openapi.yaml`, and the
   relevant docs under `docs/`.
2. Keep OpenAPI, tests, migrations, docs, SDK artifacts, examples, and release
   evidence aligned when behavior changes.
3. Preserve durable-capture-before-success semantics, exact raw-byte provider
   verification, tenant isolation, replay auditability, SSRF-safe endpoint
   handling, secret redaction, and at-least-once delivery language.
4. Do not introduce exactly-once delivery claims, provider-side event
   completeness guarantees, compliance certification claims, live-provider
   acceptance-test dependencies, or arbitrary transformation scripting.

Useful checks:

```sh
make docs-check
make fast-check
make finalize
```

For production-readiness changes, also run:

```sh
make release-acceptance
make rc-check
```

Database-backed checks require `WEBHOOKERY_TEST_DATABASE_URL`. Do not point test
commands at production databases or live provider accounts.

Do not include API keys, webhook secrets, bearer tokens, session tokens, private
keys, provider credentials, database URLs, raw payloads, customer data, local
backup files, or release evidence artifacts in commits.
