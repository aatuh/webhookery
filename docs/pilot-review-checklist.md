# Pilot Review Checklist

Use this checklist after the first evaluator or customer pilots to decide the
next Webhookery implementation slice.

The goal is disciplined product learning. Do not broaden scope into marketplace
plugins, multi-region operation, hosted SaaS, SAML, HSM, or vendor-specific
apps unless pilot evidence justifies that phase.

## Inputs

- [ ] Completed `docs/pilot-feedback-template.md`.
- [ ] Completed `docs/pilot-evidence-template.md`.
- [ ] Accepted pilot topology from `docs/pilot-topology.md`.
- [ ] Sanitized quickstart/demo result.
- [ ] Relevant issue links.
- [ ] Commercial intent, if any.
- [ ] Support expectation.
- [ ] Provider mix.
- [ ] Deployment constraints.
- [ ] Security review requirements.

## Review Questions

- Did the evaluator complete the local quickstart?
- Did the evidence demo explain the product value?
- Which blocker repeated across more than one evaluator?
- Which blocker affected durable capture, replay, audit, retention, provider
      conformance, or deployment safety?
- Which request is clearly paid custom work rather than general roadmap?
- Which request would weaken a security invariant or non-claim?
- Which doc would have prevented the issue?
- Which release evidence artifact was missing or unclear?

## Classification

For each finding, choose one:

- fix immediately
- document immediately
- include in next product backlog
- handle as paid custom work
- track as accepted risk
- reject as out of scope
- defer as enterprise/future

## Release Claim Review

Before changing production language, confirm:

- [ ] `make release-acceptance` passes.
- [ ] `make rc-check` passes.
- [ ] Provider conformance evidence is current.
- [ ] Performance and failure-drill evidence supports the claim.
- [ ] External review or accepted-risk status is reflected where relevant.
- [ ] The claim does not imply exactly-once delivery.
- [ ] The claim does not imply provider-side completeness.
- [ ] The claim does not imply compliance certification.

## Output

Produce one short decision note:

- pilot summary
- top three repeated blockers
- accepted risks
- next docs fixes
- next bug fixes
- next product backlog candidate
- commercial follow-up
- explicit out-of-scope requests
