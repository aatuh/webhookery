# Source Of Truth

This page summarizes the public repository evidence surfaces for Webhookery.
It exists to make the GitHub-facing metadata easier to audit without changing
the implementation source of truth.

| Area | Source Of Truth | Notes |
| --- | --- | --- |
| Product entry point | `README.md` | Short positioning, quickstart, badges, and links. |
| Implemented API contract | `openapi.yaml` | Canonical REST contract. `sdk/openapi.yaml` and rendered docs are derived artifacts. |
| Rendered API docs | `docs/openapi/index.html` | Generated from `openapi.yaml` by `make openapi-reference-generate`. |
| API operation matrix | `docs/reference/api-contract-matrix.md` | Generated from `openapi.yaml`; useful for review and badge count checks. |
| Database schema | `migrations/` | Migration history and evidence-authority schema. |
| Release metadata | `release/current.json` | Pointer to the current public release candidate and pilot checklist. GitHub Releases remains external source of truth. |
| Release evidence | `docs/reference/release-evidence-index.md` and `docs/release-evidence-template.md` | Public artifact map and release evidence requirements. |
| Release validation | `docs/reference/release-validation.md` | Project-owned release validation path and expected evidence. |
| Security policy | `SECURITY.md` | Vulnerability reporting and sensitive-data handling. |
| Governance | `GOVERNANCE.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS` | Contribution, maintainer, conduct, and review ownership policy. |
| Public workflows | `.github/workflows/` | CI, security, integration, fuzz, CodeQL, Scorecard, release, and Pages publication workflows. |
| Dependency updates | `.github/dependabot.yml` | Weekly checks for Go modules, GitHub Actions, Docker, TypeScript package metadata, and Terraform profile dependencies. |
| Static site | `site/` and `.github/workflows/site-pages.yml` | Product page source and GitHub Pages publication workflow. |
| Provider proof metadata | `docs/provider-proof-manifest.json` | Freshness metadata for manual live-provider proof guides; no live provider calls are committed. |

## Boundaries

The public metadata does not prove live provider acceptance, branch protection,
private vulnerability reporting settings, completed external review, or
customer pilot outcomes by itself. Those items must be recorded in release or
pilot evidence when available.
