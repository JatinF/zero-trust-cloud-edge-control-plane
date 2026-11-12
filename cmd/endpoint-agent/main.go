package main

import (
	"encoding/json"
	"os"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/config"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/service"
)

func main() {
	os.Exit(service.Run("endpoint-agent", "127.0.0.1:8084", os.Args[1:], check))
}

func check([]string) error {
	_, limits, err := config.Load("configs/cloud.yaml")
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"simulated_endpoints": limits.SimulatedEndpoints,
		"note":                "The lab stores endpoint inventory records. This process did not start one operating-system process per endpoint.",
	})
}
