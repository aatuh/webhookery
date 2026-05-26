# Release Evidence

Webhookery release evidence is an operator and reviewer artifact. It records
the exact commit, tag, image digest, checks, SBOMs, vulnerability scans, OpenAPI
checksum, migration state, production-doctor output, and acceptance evidence for
a release.

The canonical template is:

- [`docs/release-evidence-template.md`](docs/release-evidence-template.md)

The local release gates are:

```sh
make release-acceptance
make rc-check
```

The release-candidate gate uses local Docker Compose services, fake providers,
and fake receivers. It must not require live Stripe, GitHub, Shopify, Slack,
AWS, Vault, or other third-party provider credentials.

Commercial release evidence packages may include signed release manifests,
image digests, SBOMs, vulnerability scan outputs, OpenAPI checksums, migration
checks, acceptance evidence, support notes, deployment hardening notes, and
upgrade guidance.

Release evidence is not a certification. It makes no exactly-once delivery
claim, no provider-side event completeness guarantee, no compliance
certification claim, no external timestamping claim, no managed-service
availability claim, and no legal evidentiary certification claim.
