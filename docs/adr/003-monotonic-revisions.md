# ADR 003: Monotonic snapshots and signed rollback

Date: 2026-11-12

## Status

Accepted.

## Decision

Revisions are strictly increasing. The edge activates the latest eligible snapshot after a reconnect. Intermediate revisions remain in history and their deployments become superseded.

A rollback is a new higher revision with `rollback` set. The signature covers that flag. A lower revision number is rejected as `revision_replayed` even if the flag is set. The flag does not authorize an older number.

Concurrent publishers read the latest revision and retry when the store reports that the chosen number is no longer next. The store commit is what makes the number unique.

## Consequences

Operators cannot reactivate revision 1 by replaying it. They publish a new revision that carries the desired rules. Duplicate notifications do not double-activate an edge.
