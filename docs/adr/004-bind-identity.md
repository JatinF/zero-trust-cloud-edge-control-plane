# ADR 004: Bind transport identity to registration

Date: 2026-11-12

## Status

Accepted.

## Decision

The gRPC server maps the peer certificate's SPIFFE URI to a registered edge, endpoint, or discovery worker. `tenant_id`, `edge_id`, and `endpoint_id` in the request must match that registration. Human REST calls use a bearer token stored as a hash, and the caller's tenant scopes every read and write.

SPIRE and an external OIDC provider were not started. The lab issues its own certificates and tokens.

## Consequences

A client cannot choose another tenant by writing it in the request. The certificate tests cover expiry, a foreign authority, and impersonation. Those checks are not a claim that a production identity plane was deployed.
