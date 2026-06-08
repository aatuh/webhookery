## Summary

Describe the change and the implemented behavior it affects.

## Security Context

- Context: `api | authz | session-auth | provider-webhook | cli | frontend | secrets-privacy | data | infra | library | none`
- Trust boundaries touched:
- Security invariants preserved:

## Validation

List the commands run and their results. Use project-owned targets such as
`make docs-check`, `make fast-check`, `make rc-check`, or `make finalize` when
they apply.

## Sensitive Data Check

- [ ] This PR does not include API keys, webhook secrets, bearer tokens,
      private keys, raw provider signatures, raw payload bodies, customer data,
      production database URLs, or private live-provider proof artifacts.
- [ ] Public docs and examples use placeholders or sanitized evidence only.
