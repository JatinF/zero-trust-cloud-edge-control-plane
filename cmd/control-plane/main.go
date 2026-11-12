package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/platform"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/service"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) > 0 && args[0] == "health" {
		_ = json.NewEncoder(os.Stdout).Encode(service.Health("control-plane"))
		return 0
	}
	if len(args) > 0 && args[0] == "demo" {
		lab, err := platform.NewLab()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		defer lab.Close()
		report, err := lab.Demo()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		_ = json.NewEncoder(os.Stdout).Encode(report)
		return 0
	}
	if len(args) > 0 && args[0] == "bench" {
		lab, err := platform.NewLab()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		defer lab.Close()
		report, err := lab.Bench()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		_ = json.NewEncoder(os.Stdout).Encode(report)
		return 0
	}
	addr := "127.0.0.1:8080"
	if len(args) > 1 && args[0] == "-addr" {
		addr = args[1]
	}
	fmt.Fprintf(os.Stderr, "control-plane health on %s. The multi-process stack was not started.\n", addr)
	return code(http.ListenAndServe(addr, service.Mux("control-plane")))
}

func code(err error) int {
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	return 0
}
