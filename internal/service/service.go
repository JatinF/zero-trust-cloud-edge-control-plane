// Package service is the shared health and metrics probe for each executable.
package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/telemetry"
)

func Health(name string) map[string]string {
	return map[string]string{"service": name, "status": "ok"}
}

func Mux(name string) http.Handler {
	hub := telemetry.New(name)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Health(name))
	})
	mux.Handle("GET /metrics", hub.Handler())
	return mux
}

// Run is the process entry for a service that was not started as its own cluster member.
// health prints a probe. check runs a local function. Any other invocation listens for probes only.
func Run(name, addr string, args []string, check func([]string) error) int {
	if len(args) > 0 && args[0] == "health" {
		_ = json.NewEncoder(os.Stdout).Encode(Health(name))
		return 0
	}
	if len(args) > 0 && args[0] == "check" {
		if check == nil {
			fmt.Fprintf(os.Stderr, "%s has no local check. The multi-process stack was not started.\n", name)
			return 1
		}
		if err := check(args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		return 0
	}
	fmt.Fprintf(os.Stderr, "%s health on %s. The multi-process stack was not started.\n", name, addr)
	return exitCode(http.ListenAndServe(addr, Mux(name)))
}

func exitCode(err error) int {
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	return 0
}
