package main

import (
	"encoding/json"
	"os"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/config"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/service"
)

func main() {
	os.Exit(service.Run("access-broker", "127.0.0.1:8086", os.Args[1:], check))
}

func check([]string) error {
	_, limits, err := config.Load("configs/cloud.yaml")
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"grant_ttl_seconds": int(limits.GrantTTL.Seconds()),
		"note":              "Grant lifetime is configured here. Approval still runs inside the control-plane lab. This process did not issue a grant.",
	})
}
