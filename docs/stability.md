# Stability And Compatibility Policy

This policy defines the compatibility promise for self-hosted Webhookery
releases. It is intentionally conservative until the project has broader
deployment history, performance evidence, and external review evidence.

## Release Stage

Current public positioning is release-candidate/early-GA for controlled
single-region self-hosted deployments.

Do not describe a release as broadly production mature unless the release
evidence package includes passing RC gates, DB-backed checks, restore drill
evidence, provider conformance evidence, performance smoke output, and current
security-review status.

## Versioning

Webhookery uses semantic version tags for release artifacts:

| Version | Compatibility expectation |
|---------|---------------------------|
| `0.x` | Public contract is useful but may change with clear release notes and migration guidance. Breaking changes must be called out before promotion. |
| `1.x` | Stable REST, CLI, migration, and deployment behavior for documented production-core workflows. Breaking changes require deprecation or a major version. |
| Patch | Bug, security, documentation, and compatibility fixes only. |
| Minor | Backward-compatible features, additive API fields, additive tables/columns, new checks, and new docs. |
| Major | Intentional breaking changes to APIs, CLI behavior, persistence compatibility, or deployment contract. |

`openapi.yaml` is the canonical REST contract. `sdk/openapi.yaml` must remain
an exact copy for SDK consumers.

## API Compatibility

Backward-compatible REST changes include:

- adding optional request fields;
- adding response fields that clients can ignore;
- adding enum values only when existing clients can safely treat them as
  unknown;
- adding endpoints under the existing versioned path;
- clarifying problem-details messages without changing machine-readable codes.

Breaking REST changes include:

- removing or renaming endpoints, fields, headers, scopes, or problem codes;
- changing required request fields or response types;
- narrowing authorization in a way that breaks documented core workflows
  without migration guidance;
- changing default retention, replay, delivery, or capture semantics.

High-risk API behavior must keep examples in `openapi.yaml` and must pass
`make openapi-check` and `make sdk-check`.

## CLI Compatibility

The `whcp` CLI is operator-facing. Keep command names, required flags, exit
codes, and output safety stable for documented workflows. New JSON fields are
allowed. Removing commands or changing destructive-action guards is breaking.

CLI output must not print secrets, database passwords, bearer/session tokens,
webhook secrets, private keys, raw signatures, raw payload bodies, or customer
data unless the command is explicitly an elevated body export and the operator
selected an output file.

## Persistence And Migrations

PostgreSQL is the evidence and metadata authority. Migration compatibility is
restore-first:

- never edit a migration that may have reached a shared environment;
- add forward migrations for schema changes;
- record migration checksum summaries in release evidence;
- run restore drills for changes that affect evidence, retention, export,
  audit chain, replay, delivery, secret custody, or authorization data.

Rollback is not only image rollback. If the database has advanced, use the
restore workflow in `docs/schema-migrations.md` and `docs/operations.md`.

## Support Windows

Until a `1.0` release policy replaces this section:

- the current release tag receives security and critical data-safety fixes;
- the immediately previous minor release may receive fixes when migration risk
  is lower than upgrade risk;
- unsupported versions should be upgraded before production promotion or
  external security review.

Commercial support windows may be longer by written agreement. Public docs must
not imply an SLA unless it is contracted.

## Deprecation Rules

Deprecations must identify:

- the affected API, CLI command, config variable, migration behavior, or
  deployment profile;
- the replacement path;
- the first release where warnings appear;
- the earliest release where removal can happen;
- migration, restore, or compatibility risks.

Security fixes can remove unsafe behavior faster, but the release evidence must
record the reason and operator impact.

## Non-Claims

This policy does not claim exactly-once delivery, provider-side event
completeness, managed-service availability, multi-region active-active
operation, compliance certification, legal evidentiary certification, external
timestamping, or recovery of every provider-side event.

Use `docs/security-promise.md` as the canonical non-claims reference.
