package main

import (
	"encoding/json"
	"os"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/config"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/service"
)

func main() {
	os.Exit(service.Run("edge-backend", "127.0.0.1:8083", os.Args[1:], check))
}

func check(args []string) error {
	path := "configs/edge-hq.yaml"
	if len(args) > 0 {
		path = args[0]
	}
	file, limits, err := config.Load(path)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"edge_id":               file.EdgeID,
		"location":              file.Location,
		"low_risk_offline_ttl":  limits.LowRiskOfflineTTL.String(),
		"high_risk_offline_ttl": limits.HighRiskOfflineTTL.String(),
		"note":                  "This process loaded edge configuration. It did not join a cloud control plane.",
	})
}
