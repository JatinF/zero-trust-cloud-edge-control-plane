# ADR 002: Fail closed inside a bounded offline window

Date: 2026-11-12

## Status

Accepted.

## Decision

A disconnected edge keeps enforcing the last verified policy until that policy's `not_after`. It denies when the window has passed, when the caller is unknown, and when a privileged grant has expired. The cache cannot flip a decision. The cloud cannot push a revoke into a disconnected edge.

Low-risk policy validity is at most 30 minutes. High-risk policy validity and privileged grants are at most 5 minutes. These are illustrative lab limits.

## Consequences

Exposure during a partition is the remaining validity, not zero. Documentation and the demo report say so. Instant global revocation is not a feature of this design.
