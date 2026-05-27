# Release Evidence

This file is the release-evidence router. The canonical evidence artifact for
each tagged release is:

- [`docs/release-evidence-template.md`](docs/release-evidence-template.md)

Copy that template for the release being reviewed and fill in commit, tag,
image digest, checks, SBOMs, vulnerability scans, OpenAPI checksums, migration
state, production-doctor output, performance smoke output, provider
conformance output, failure-drill output, branch protection status, external
review status, accepted-risk status, and acceptance evidence.

Local acceptance gates start with:

```sh
make release-acceptance
make rc-check
```

Commercial release evidence packages may include signed release manifests,
image digests, SBOMs, vulnerability scan outputs, OpenAPI checksums, migration
checks, acceptance evidence, support notes, deployment hardening notes, and
upgrade guidance.

Release evidence is not a certification. The canonical non-claims are in
[`docs/security-promise.md`](docs/security-promise.md): no exactly-once delivery,
no provider-side event completeness guarantee, no compliance certification, no
external timestamping, no managed-service availability, and no legal
evidentiary certification.
