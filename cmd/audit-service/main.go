package main

import (
	"encoding/json"
	"os"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/service"
)

func main() {
	os.Exit(service.Run("audit-service", "127.0.0.1:8087", os.Args[1:], check))
}

func check([]string) error {
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "local",
		"note":   "Audit rows are written by the in-process control plane. This process did not open a database.",
	})
}
