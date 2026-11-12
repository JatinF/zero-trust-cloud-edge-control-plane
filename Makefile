.PHONY: test race vet build demo bench check

test:
	go test ./... -count=1 -timeout 180s

race:
	go test -race -count=1 ./... -timeout 300s

vet:
	go vet ./...

build:
	go build -o bin/ ./cmd/...

demo:
	go run ./cmd/control-plane demo

bench:
	go run ./cmd/control-plane bench

check:
	go run ./cmd/policy-manager check
	go run ./cmd/policy-sync check
	go run ./cmd/edge-backend check
	go run ./cmd/endpoint-agent check
	go run ./cmd/discovery-worker check
	go run ./cmd/access-broker check
	go run ./cmd/audit-service check
