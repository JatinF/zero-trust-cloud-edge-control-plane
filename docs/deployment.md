# Deployment

The authoring workstation does not have Docker or kubectl. Nothing in `deployments/` was applied. Images named in the compose file were not pulled locally. Terraform has no provider. The Helm chart was not installed.

## Reproduce the lab

From the repository root, with Go 1.26.4:

```text
go test ./... -count=1 -timeout 180s
go run ./cmd/control-plane demo
go run ./cmd/control-plane bench
```

`make` is a thin wrapper for the same commands. It was not required on Windows.

`demo` prints one JSON object for the Cedar lifecycle. `bench` prints the in-process samples described in `docs/benchmarks.md`. Both print `"price":"none"`.

Each other executable supports `health` and `check`. `check` reads local config or the embedded policy. It does not start PostgreSQL, NATS, Redis, or a second machine. With no arguments, the process listens on `127.0.0.1` and serves `/health` and `/metrics` only. The log line says the multi-process stack was not started.

Default probe ports are 8080 for the control plane, then 8081 through 8087 for policy-manager, policy-sync, edge-backend, endpoint-agent, discovery-worker, access-broker, and audit-service.

## Gates

Copy `.env.example` only if you want the variable names. Leave the values empty. `GET /v1/gates` then returns `not-run`. Setting a variable changes that gate to `blocked` and the process still does not connect. The reason text does not echo the value.

## GitHub Actions

`.github/workflows/ci.yml` runs `go test -race`, `go vet`, `go build -o bin/ ./cmd/...`, and `docker build` on `ubuntu-24.04`. The image tags `golang:1.26-bookworm` and `debian:bookworm-slim` are public Docker Hub tags. The local workstation did not build the image. A green Actions docker job is the image proof.

`.github/workflows/security.yml` runs `scripts/reject_private_keys.py`. The scanner splits the PEM marker so the script does not match itself. Lab keys stay in memory and are not committed.

## Schema

`db/migrations/001_init.sql` and `db/queries/insert_policy_version.sql` document the PostgreSQL shape, including tenant foreign keys and a unique `(policy_id, revision)`. They were not executed. The in-memory store is the implementation the tests run.
