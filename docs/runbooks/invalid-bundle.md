# Runbook: invalid bundle

## Reject and keep the previous policy

`Apply` increments the rejected count and leaves the active snapshot unchanged when:

- the signature is missing or does not verify
- the tenant does not match the edge
- the Rego is rejected
- the validity window is longer than the risk class allows, or the clock is outside it
- the revision is older than the active revision
- the same revision arrives with a different digest

A duplicate of the active revision and digest returns success and does not add another activation.

## Stream limit

If the envelope is larger than `max_bundle_bytes`, `FetchBundle` returns `ResourceExhausted` before the edge activates anything. The lab default is 1 MiB. A test sets the limit to 64 bytes and expects that code.

## Restart during activation

`StageStoppingBeforeActivate` verifies the candidate and returns `activation_interrupted` without swapping. On restart, `Recover` installs the persisted snapshot only when it still verifies and is still inside its window. A tampered snapshot leaves the edge with no active policy.
