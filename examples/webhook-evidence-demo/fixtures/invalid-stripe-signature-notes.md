# Invalid Signature Scenario

The release-candidate E2E path sends a Stripe-style payload with a signature
computed from the wrong synthetic secret.

Expected behavior:

- Webhookery stores rejection/quarantine evidence where feasible.
- The event is not accepted as trusted.
- No route creates side-effecting delivery work.
- The failure reason is visible without exposing the signing secret or raw
  signature value.

This fixture intentionally does not contain a real Stripe signing secret or a
real signature header.
