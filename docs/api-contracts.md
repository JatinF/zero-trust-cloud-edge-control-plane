# API contracts

OpenAPI for the administrative routes is `docs/api/openapi.yaml`. A unit test checks that every path in `httpapi.Routes` appears there. The file is maintained with the routes. It was not emitted by a code generator.

`GET /health` and `GET /metrics` are unauthenticated process probes. They are not tenant APIs and they are not in the OpenAPI document. `/health` returns the service name and `ok`. It returns no tenant data.

## REST

Every `/v1` route requires a `Bearer` token. The raw token is authenticated. It is not redacted before lookup. Error messages are redacted. The caller must hold the role for the action, and the tenant on the caller must own the resource.

| Method | Path | Role |
| --- | --- | --- |
| POST | `/v1/tenants` | platform |
| POST | `/v1/policies` | policy-admin |
| POST | `/v1/policies/{id}/publish` | policy-admin |
| GET | `/v1/policies/{id}/versions` | policy-admin |
| GET | `/v1/edges` | policy-admin |
| GET | `/v1/edges/{id}/endpoints` | policy-admin |
| POST | `/v1/discovery/jobs` | policy-admin |
| GET | `/v1/assets` | policy-admin |
| POST | `/v1/access-requests` | requester, approver, or policy-admin |
| POST | `/v1/access-requests/{id}/approve` | approver, and not the requester |
| POST | `/v1/access-requests/{id}/revoke` | approver or policy-admin |
| GET | `/v1/audit/events` | policy-admin |
| GET | `/v1/gates` | any authenticated caller |

`GET /v1/gates` is extra. It exists so the not-run integrations are visible. A cross-tenant policy read returns 404 `not_found` and writes `tenant_forbidden` on the policy's tenant. Bodies are limited to 1 MiB. Invalid JSON is `policy_format`.

## gRPC

`PolicySyncService` is `Subscribe`, `FetchBundle`, and `Acknowledge`, as specified. `EndpointService.ReportStatus` and `DiscoveryService.ReportAssets` are the other two services.

The server requires a TLS client certificate with a SPIFFE URI. The registry maps that URI to one edge, one endpoint, or the discovery worker. `Subscribe` and `Acknowledge` reject an edge id or tenant id that does not match the certificate. `ReportStatus` rejects an endpoint id or edge id that does not match. `ReportAssets` accepts only the discovery identity, and the asset list must equal the simulator catalog for that connector.

`FetchBundle` sends a JSON envelope of payload and signature, split into chunks. The default maximum envelope is 1 MiB. A larger envelope returns `ResourceExhausted` and the edge does not activate it. The server limits are fixed when the server is constructed. Deadlines on the lab calls are 5 seconds for sync and 2 seconds for the certificate tests. Application errors use the codes in `internal/apperr`. gRPC status codes wrap those errors.

Privileged grants are pushed in process to connected edges. There is no grant RPC in the policy sync protocol.
