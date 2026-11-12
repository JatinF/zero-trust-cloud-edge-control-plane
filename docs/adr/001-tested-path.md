# ADR 001: Tested path and unapplied dependencies

Date: 2026-11-12

## Status

Accepted.

## Decision

The tests run against an in-memory store, an in-memory at-least-once log, and a non-authoritative cache. PostgreSQL, NATS JetStream, and Redis are named in the schema, the compose file, and the gates. They were not started, and no driver calls them.

## Consequences

A reviewer can run `go test` without those services. A gate that is `not-run` must stay `not-run` in the README. Setting a connection variable blocks the gate and does not open a connection. The SQL files are documentation of the intended constraints. A later change that adds a driver has to apply the migration and test it before any claim that PostgreSQL ran.
