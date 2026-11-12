package main

import (
	"encoding/json"
	"os"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/discovery"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/service"
)

func main() {
	os.Exit(service.Run("discovery-worker", "127.0.0.1:8085", os.Args[1:], check))
}

func check([]string) error {
	cmdb, err := discovery.Scan("sim-cmdb")
	if err != nil {
		return err
	}
	app, err := discovery.Scan("sim-app")
	if err != nil {
		return err
	}
	_, err = discovery.Scan("http://10.0.0.1/")
	if code := codeOf(err); code != "unknown_connector" {
		return apperr.New("unknown_connector", "an address outside the simulator catalog was not rejected", 422)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"assets":  len(cmdb) + len(app),
		"unknown": "rejected",
		"note":    "Discovery read the fixed simulator catalog. It did not open a network connection.",
	})
}

func codeOf(err error) string {
	item, ok := apperr.As(err)
	if !ok {
		return ""
	}
	return item.Code
}
