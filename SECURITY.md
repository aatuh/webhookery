# Security Policy

Webhookery is high-trust webhook evidence and delivery infrastructure. Security
reports are welcome, especially around provider webhook verification, raw body
preservation, durable capture, tenant isolation, authorization, replay, audit
exports, retention, SSRF-safe delivery, secret custody, Docker images, and
release evidence.

## Reporting A Vulnerability

If you believe you found a vulnerability, contact Aatu Harju through LinkedIn:

<https://www.linkedin.com/in/aatu-harju>

Use the initial message to request a private reporting channel. Do not include
API keys, webhook secrets, bearer tokens, session tokens, private keys, provider
credentials, database URLs, raw payloads, customer data, exploit payloads
against third-party systems, or other sensitive material in the first message.

## What To Include

Once a private channel is established, include:

- affected commit, tag, image digest, or deployment profile,
- concise impact statement,
- reproduction steps or proof of concept,
- affected endpoints, commands, packages, provider adapters, or worker modes,
- whether secrets, tenant data, raw payloads, delivery evidence, replay
  evidence, audit records, or exports are exposed,
- whether a provider request, outbound delivery, replay, export, retention run,
  SIEM stream, or notification path is involved,
- suggested fix if known.

## Supported Scope

Security support focuses on the current `master` branch and current release
tags. Older releases are best effort unless a commercial support agreement says
otherwise.

Out of scope:

- denial-of-service reports that require unrealistic local resource access,
- issues caused only by unsupported production configuration,
- findings that depend on publishing secrets or raw customer payloads in public
  channels,
- reports that rely on live third-party provider abuse rather than local
  reproduction or responsible provider disclosure,
- claims broader than the canonical non-claims in `docs/security-promise.md`.

## Disclosure

Please allow time for triage and remediation before public disclosure. Public
fixes should avoid exposing exploit details before affected users have a
reasonable update path.

Do not post secrets, raw webhook payloads, private keys, provider credentials,
session tokens, bearer tokens, database URLs, or customer data in public issues,
pull requests, screenshots, logs, or release evidence.
