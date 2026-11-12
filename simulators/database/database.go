// Package database is a protected database simulator.
// It asks the edge authorizer before returning a row.
package database

import "github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"

type Authorizer func(action, resourceID string) model.Decision

type Simulator struct {
	ResourceID string
	Authorize  Authorizer
}

func (s Simulator) Query(tokenAction string) (string, model.Decision) {
	decision := s.Authorize(tokenAction, s.ResourceID)
	if !decision.Allow {
		return "", decision
	}
	return "synthetic-row", decision
}
