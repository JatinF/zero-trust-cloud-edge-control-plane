# ADR 005: OPA does not own the grant clock

Date: 2026-11-12

## Status

Accepted.

## Decision

Rego answers whether the subject, action, resource, and grant inputs match the policy. Go decides whether the policy window is current and whether a grant is unexpired, and it passes `grant_valid` into the evaluation. An empty input must not allow, and `default allow := true` is rejected at publish time.

## Consequences

A policy author cannot extend a grant by omitting the expiry check inside Rego. The privileged module still requires `grant_valid` to be true. Tests advance the lab clock without depending on OPA's own time.
