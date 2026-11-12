package main

import (
	"encoding/json"
	"os"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/config"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/service"
)

func main() {
	os.Exit(service.Run("policy-sync", "127.0.0.1:8082", os.Args[1:], check))
}

func check([]string) error {
	file, limits, err := config.Load("configs/cloud.yaml")
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"service":          file.Service,
		"chunk_bytes":      limits.ChunkBytes,
		"max_bundle_bytes": limits.MaxBundleBytes,
		"note":             "Authenticated gRPC runs inside the control-plane lab over an in-process listener. This process did not open a network socket for policy sync.",
	})
}
