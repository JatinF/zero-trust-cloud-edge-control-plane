# System design

This is a self-directed reference for a simulated zero-trust policy control plane. It is not product code and it is not a customer deployment. Go is the implementation language for the portfolio brief. The tenant is `SYN-TENANT-CEDAR`. A second tenant, `SYN-TENANT-BIRCH`, exists so cross-tenant reads can be tested.

## What runs

The tested path is one process:

- An in-memory store commits a policy revision and its outbox row together. A failed commit discards the draft.
- An in-memory log redelivers an unpublished event until the consumer acknowledges it. That models at-least-once delivery. An acknowledgment is not exactly-once execution. The edge treats an equal revision and digest as a duplicate.
- Redis is represented by a metadata cache. Authorization does not read an allow or a deny from it.
- Open Policy Agent evaluates the embedded Rego modules through `github.com/open-policy-agent/opa`.
- Policy sync uses gRPC with TLS 1.3 over an in-process listener. Workload certificates carry a SPIFFE URI. SPIRE was not started. This is not a production mesh.
- PostgreSQL, NATS JetStream, Redis, an OIDC provider, and an OTLP collector were not started. `GET /v1/gates` reports each one as `not-run` unless the matching variable is set, in which case the status is `blocked` and the process still does not connect.

`policy-manager` and `audit-service` are extra executables beyond the first proposed tree. Each executable has a health probe and a local check. They do not form a running multi-process cluster. The control-plane lab performs publish, sync, enforcement, grants, discovery, and audit.

## Planes

```text
administrator
    REST /v1 on the control plane
        validate, sign, commit revision + outbox
        in-memory log
        gRPC PolicySyncService over mTLS
            HQ, regional, and branch edge backends
                local OPA decision
                endpoint inventory records
```

Edges are `SYN-EDGE-HQ`, `SYN-EDGE-REGION`, and `SYN-EDGE-BRANCH`. Each holds one active snapshot. Subscribe sends the latest revision of each policy that is newer than the edge's active revision. Intermediate revisions stay in history and are marked superseded when a later snapshot is acknowledged. The edge does not activate every intermediate revision.

Endpoint IDs `SYN-EP-001` through `SYN-EP-300` are inventory records, assigned round-robin across the three edges. Cryptographic identities exist for `SYN-EP-001` and `SYN-EP-002` only. The impersonation test uses the first certificate to report status as the second endpoint.

## Identity

Human callers use lab bearer tokens. The store keeps the SHA-256 of the token. Workload callers use a certificate. The gRPC interceptor reads the URI SAN and looks up the registration. A request field named `tenant_id` or `edge_id` must match that registration. A mismatch is `PermissionDenied` and is audited as impersonation.

Online, with the store available, the store is authoritative for identity status. Offline, or while the store is down, the edge uses the directory it last refreshed. A token that is not in that directory is denied. A cloud revocation of an identity is not visible to a disconnected edge until the edge reconciles or the local policy expires.

Workload certificate lifetime uses the process wall clock. The lab clock used for policy and grants is frozen at `2026-11-11T18:00:00Z` and then advanced by tests. Human tokens last 24 hours on the lab clock so a policy-expiry test does not also expire the caller.

## Authorization

Default is deny. A low-risk read of an application in the same tenant is the non-privileged allow. The privileged action is `admin` on the database, and only while a matching grant is valid. Grant expiry is computed in Go from the lab clock and passed into Rego as booleans. OPA does not own the grant clock.

Illustrative limits, from `configs/cloud.yaml`:

- Privileged grants last 5 minutes.
- A low-risk policy may stay valid offline for at most 30 minutes.
- A high-risk policy may stay valid offline for at most 5 minutes.

A disconnected edge cannot learn that the cloud revoked a still-valid policy. The design does not claim instant global revocation during a partition. The bound is the remaining validity, and grants are short.

## Discovery

Connectors are `sim-cmdb` and `sim-app`. Any other name, including an address, returns `unknown_connector`. The worker does not dial the network. The pool size is 4. A full pool returns `worker_pool_saturated` instead of growing a queue. A gRPC asset report must match `Scan` exactly.

## Audit

Sensitive changes and authorization decisions append an audit row in the same process. While the store is down, rows spool in memory and flush when the store is available again. That is not a claim that PostgreSQL captured the event during the outage. TLS handshake failures happen before the application and are not application audit rows.
