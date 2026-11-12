package main

import (
	"encoding/json"
	"os"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/policy"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/service"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/policies"
)

func main() {
	os.Exit(service.Run("policy-manager", "127.0.0.1:8081", os.Args[1:], check))
}

func check([]string) error {
	if err := policy.Validate(policies.Access, policies.Privileged); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status":   "valid",
		"packages": []string{"zt.authz", "zt.privileged"},
		"note":     "Embedded Rego compiled in this process. A separate policy-manager cluster member was not started.",
	})
}
