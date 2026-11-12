# Threat model

Scope is the in-process lab. The synthetic tenant is `SYN-TENANT-CEDAR`. There is no customer data and no production edge.

## Assets

- Policy snapshots and their signatures.
- Human tokens and workload certificates.
- Privileged grants.
- The audit history of decisions.
- The edge's last verified policy, which remains the enforcement input while the cloud is unreachable.

## Trust boundary

The control plane trusts a caller only after authentication. The gRPC server trusts the peer certificate, then the registration bound to that SPIFFE ID. Request body fields do not select a tenant. The edge trusts a bundle only after the signature, tenant, revision, validity window, and Rego checks all succeed. Activation is a swap after those checks. A failed check leaves the previous policy in place.

The lab certificate authority is generated in memory. It is not an HSM and it is not SPIRE.

## Cases the tests cover

| Case | Result |
| --- | --- |
| Birch reads a Cedar policy | `not_found`, audited as `tenant_forbidden` on the Cedar policy |
| Expired or foreign workload certificate | TLS handshake fails |
| Valid identity, unpermitted action | deny |
| Expired privileged grant | `grant_expired` |
| Older revision, including one newly signed with the rollback flag | `revision_replayed` |
| Tampered bundle or missing signature | rejected, previous policy kept |
| Endpoint certificate used as a different endpoint | `PermissionDenied` |
| Inactive or revoked identity, store online | deny |
| Revoked identity with a still-valid certificate | application `PermissionDenied`, audited |
| Cache set to allow, or cache marked down | the decision does not follow the cache |
| Store or bus marked down | local policy still bounds the edge; publish and dispatch fail closed |

`InvalidAccepted` on the edge stays at zero. Tests also require a rejected update and an unchanged active revision.

## Partition

While an edge is disconnected, a cloud revoke of a grant does not reach it. The test records `grant_permit` during the partition and `grant_revoked` after reconnect. After the offline window, the same edge returns `policy_expired`. That delay is the residual risk. Short grants and a bounded policy window are the control. The system must not be described as providing immediate global revocation.

## Other residuals

- The in-process gRPC listener is not a network of machines. Packet loss, clock skew between sites, and a real mesh are outside this measurement.
- Three hundred endpoints are records. Only two have certificates.
- Central audit cannot be written while the store is down. The spool is local memory.
- SQL migrations document tenant isolation and unique revisions. They were not applied.
- A signed rollback is a new higher revision. The flag does not reactivate a lower revision number.
