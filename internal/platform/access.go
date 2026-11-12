package platform

import (
	"context"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/authz"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/edge"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"
)

func (l *Lab) RequestAccess(caller model.Identity, resourceID, action, reason string) (model.AccessRequest, error) {
	if caller.TenantID == "" || (!model.HasRole(caller, RoleRequester) && !model.HasRole(caller, RoleAdmin) && !model.HasRole(caller, RoleApprover)) {
		l.record(caller.TenantID, caller.ID, "request_access", "forbidden", resourceID)
		return model.AccessRequest{}, apperr.New("forbidden", "requester role is required", 403)
	}
	if action != authz.PrivilegedAction {
		l.record(caller.TenantID, caller.ID, "request_access", "policy_format", action)
		return model.AccessRequest{}, apperr.New("policy_format", "privileged action must be admin", 422)
	}
	if _, err := l.Store.Resource(caller.TenantID, resourceID); err != nil {
		l.record(caller.TenantID, caller.ID, "request_access", codeOf(err), resourceID)
		return model.AccessRequest{}, err
	}
	saved, err := l.Store.AddRequest(model.AccessRequest{
		TenantID: caller.TenantID, RequesterID: caller.ID, ResourceID: resourceID,
		Action: action, State: "pending", Reason: reason,
	})
	if err != nil {
		return model.AccessRequest{}, err
	}
	l.record(caller.TenantID, caller.ID, "request_access", "pending", saved.ID)
	return saved, nil
}

func (l *Lab) Approve(caller model.Identity, requestID string) (model.Grant, error) {
	if !model.HasRole(caller, RoleApprover) {
		l.record(caller.TenantID, caller.ID, "approve", "forbidden", requestID)
		return model.Grant{}, apperr.New("forbidden", "approver role is required", 403)
	}
	req, err := l.Store.Request(caller.TenantID, requestID)
	if err != nil {
		l.record(caller.TenantID, caller.ID, "approve", codeOf(err), requestID)
		return model.Grant{}, err
	}
	if req.RequesterID == caller.ID {
		l.record(caller.TenantID, caller.ID, "approve", "self_approval", requestID)
		return model.Grant{}, apperr.New("self_approval", "requester cannot approve their own request", 403)
	}
	if req.State != "pending" {
		l.record(caller.TenantID, caller.ID, "approve", "conflict", requestID)
		return model.Grant{}, apperr.New("conflict", "request is not pending", 409)
	}
	expires := l.Clock.Now().Add(l.Limits.GrantTTL).Unix()
	grant, err := l.Store.AddGrant(model.Grant{
		TenantID: caller.TenantID, RequestID: req.ID, SubjectID: req.RequesterID,
		ResourceID: req.ResourceID, Action: req.Action, Scope: req.ResourceID + ":" + req.Action,
		ExpiresAtUnix: expires,
	}, "approved")
	if err != nil {
		return model.Grant{}, err
	}
	l.pushGrants(caller.TenantID)
	l.record(caller.TenantID, caller.ID, "approve", "approved", grant.ID)
	return grant, nil
}

func (l *Lab) Revoke(caller model.Identity, requestID string) (model.Grant, error) {
	if !model.HasRole(caller, RoleApprover) && !model.HasRole(caller, RoleAdmin) {
		l.record(caller.TenantID, caller.ID, "revoke", "forbidden", requestID)
		return model.Grant{}, apperr.New("forbidden", "approver role is required", 403)
	}
	grant, err := l.Store.RevokeGrant(caller.TenantID, requestID, l.Clock.Now().Unix())
	if err != nil {
		l.record(caller.TenantID, caller.ID, "revoke", codeOf(err), requestID)
		return model.Grant{}, err
	}
	l.pushGrants(caller.TenantID)
	l.record(caller.TenantID, caller.ID, "revoke", "revoked", grant.ID)
	return grant, nil
}

func (l *Lab) pushGrants(tenant string) {
	grants := l.Store.Grants(tenant)
	for _, backend := range l.Backends {
		if backend.TenantID == tenant && backend.Connected() && l.Store.Available() {
			backend.ReplaceGrants(grants)
		}
	}
}

func (l *Lab) Authorize(edgeID, rawToken, action, resourceID string) model.Decision {
	backend, ok := l.Backends[edgeID]
	if !ok {
		return model.Decision{Allow: false, Reason: "not_found"}
	}
	// Metadata may be cached. The decision itself is never taken from the cache.
	_, _ = l.Cache.Get("metadata")
	decision := l.decide(backend, rawToken, action, resourceID)
	l.record(backend.TenantID, principalFrom(rawToken, l), "authorize", decision.Reason, resourceID)
	return decision
}

func (l *Lab) decide(backend *edge.Backend, rawToken, action, resourceID string) model.Decision {
	online := backend.Connected() && l.Store.Available()
	if online {
		identity, rec, err := l.Store.Authenticate(rawToken, l.Clock.Now().Unix())
		if err != nil {
			reason := codeOf(err)
			if reason == "dependency_unavailable" {
				return backend.Authorize(context.Background(), rawToken, action, resourceID)
			}
			return model.Decision{Allow: false, Reason: reason}
		}
		backend.Remember(identity, rec)
	}
	return backend.Authorize(context.Background(), rawToken, action, resourceID)
}

func principalFrom(raw string, lab *Lab) string {
	if !lab.Store.Available() {
		return "local"
	}
	id, _, err := lab.Store.Authenticate(raw, lab.Clock.Now().Unix())
	if id.ID != "" {
		return id.ID
	}
	if err != nil {
		return "anonymous"
	}
	return "anonymous"
}
