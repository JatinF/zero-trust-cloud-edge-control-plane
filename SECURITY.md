# Security

This repository is a self-directed reference implementation. It is not a production control plane and it has no customer deployment.

## Reporting

Open a GitHub issue for a defect in this repository. Do not include live credentials, customer names, or production policy.

## What this tree does

- Lab tokens and workload certificates are generated in memory for synthetic identities.
- The signing key and the lab certificate authority are not written to disk.
- Administrative routes require a bearer token. Error text redacts `lab-token-...` values.
- A cache entry cannot turn a deny into an allow.

## What this tree does not do

- It does not start PostgreSQL, NATS JetStream, Redis, SPIRE, or an OIDC provider.
- It does not revoke a disconnected edge instantly. The offline validity window is the exposure bound.
- It does not scan networks. Discovery accepts only the named simulator connectors.
