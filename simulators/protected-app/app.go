// Package protectedapp is a protected application simulator.
package protectedapp

import "github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"

type Authorizer func(action, resourceID string) model.Decision

type Simulator struct {
	ResourceID string
	Authorize  Authorizer
}

func (s Simulator) Read() (string, model.Decision) {
	decision := s.Authorize("read", s.ResourceID)
	if !decision.Allow {
		return "", decision
	}
	return "synthetic-page", decision
}
