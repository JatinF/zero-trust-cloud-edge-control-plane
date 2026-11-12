// Package authz asks OPA for a decision after the Go layer has checked
// authentication, policy lifetime, and grant lifetime.
// Grant expiry uses the lab clock. OPA does not see a raw expiry timestamp.
package authz

import (
	"context"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/policy"
)

const PrivilegedAction = "admin"

type Request struct {
	Identity      model.Identity
	Action        string
	Resource      model.Resource
	GrantValid    bool
	GrantAction   string
	GrantResource string
}

func Decide(ctx context.Context, accessRego, privilegedRego string, req Request) (model.Decision, error) {
	if req.Identity.Status == "inactive" {
		return model.Decision{Allow: false, Reason: "identity_inactive"}, nil
	}
	if req.Identity.Status == "revoked" {
		return model.Decision{Allow: false, Reason: "identity_revoked"}, nil
	}
	if req.Identity.Status != "active" {
		return model.Decision{Allow: false, Reason: "unauthenticated"}, nil
	}
	input := map[string]any{
		"subject": map[string]any{
			"id":        req.Identity.ID,
			"tenant_id": req.Identity.TenantID,
			"status":    req.Identity.Status,
		},
		"action": req.Action,
		"resource": map[string]any{
			"id":        req.Resource.ID,
			"tenant_id": req.Resource.TenantID,
			"kind":      req.Resource.Kind,
		},
		"grant_valid":       req.GrantValid,
		"grant_action":      req.GrantAction,
		"grant_resource_id": req.GrantResource,
	}
	accessAllow, privAllow, err := policy.Eval(ctx, accessRego, privilegedRego, input)
	if err != nil {
		return model.Decision{Allow: false, Reason: "policy_format"}, err
	}
	if req.Action == PrivilegedAction {
		if privAllow {
			return model.Decision{Allow: true, Reason: "grant_permit"}, nil
		}
		if !req.GrantValid {
			return model.Decision{Allow: false, Reason: "grant_invalid"}, nil
		}
		return model.Decision{Allow: false, Reason: "denied"}, nil
	}
	if accessAllow {
		return model.Decision{Allow: true, Reason: "permit"}, nil
	}
	return model.Decision{Allow: false, Reason: "denied"}, nil
}
