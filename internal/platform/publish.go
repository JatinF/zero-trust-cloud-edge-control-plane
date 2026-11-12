package platform

import (
	"context"
	"time"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/policy"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/policies"
)

func (l *Lab) CreateTenant(caller model.Identity, id, name string) (model.Tenant, error) {
	if !model.HasRole(caller, RolePlatform) {
		l.record(caller.TenantID, caller.ID, "create_tenant", "forbidden", id)
		return model.Tenant{}, apperr.New("forbidden", "platform role is required", 403)
	}
	tenant := model.Tenant{ID: id, Name: name, Status: "active"}
	if err := l.Store.PutTenant(tenant); err != nil {
		l.record(caller.TenantID, caller.ID, "create_tenant", codeOf(err), id)
		return model.Tenant{}, err
	}
	l.record(id, caller.ID, "create_tenant", "created", id)
	return tenant, nil
}

func (l *Lab) CreatePolicy(caller model.Identity, id, scope, risk string) (model.Policy, error) {
	if !model.HasRole(caller, RoleAdmin) || caller.TenantID == "" {
		l.record(caller.TenantID, caller.ID, "create_policy", "forbidden", id)
		return model.Policy{}, apperr.New("forbidden", "policy-admin role is required", 403)
	}
	if risk == "" {
		risk = "low"
	}
	if risk != "low" && risk != "high" {
		return model.Policy{}, apperr.New("policy_format", "risk must be low or high", 422)
	}
	if scope == "" {
		scope = "edge"
	}
	item := model.Policy{ID: id, TenantID: caller.TenantID, Scope: scope, Risk: risk}
	if err := l.Store.CreatePolicy(item); err != nil {
		l.record(caller.TenantID, caller.ID, "create_policy", codeOf(err), id)
		return model.Policy{}, err
	}
	l.record(caller.TenantID, caller.ID, "create_policy", "created", id)
	return item, nil
}

func (l *Lab) Publish(caller model.Identity, policyID, risk, accessRego, privilegedRego string, rollback bool) (model.PolicyVersion, error) {
	ctx, end := l.Telemetry.Start(context.Background(), "policy.publish")
	defer end()
	_ = ctx
	if !model.HasRole(caller, RoleAdmin) || caller.TenantID == "" {
		l.record(caller.TenantID, caller.ID, "publish", "forbidden", policyID)
		return model.PolicyVersion{}, apperr.New("forbidden", "policy-admin role is required", 403)
	}
	current, err := l.Store.Policy(caller.TenantID, policyID)
	if err != nil {
		if other, ok := l.Store.PolicyAny(policyID); ok && other.TenantID != caller.TenantID {
			l.record(other.TenantID, caller.ID, "publish", "tenant_forbidden", policyID)
			return model.PolicyVersion{}, apperr.New("not_found", "policy was not found", 404)
		}
		l.record(caller.TenantID, caller.ID, "publish", codeOf(err), policyID)
		return model.PolicyVersion{}, err
	}
	if risk == "" {
		risk = current.Risk
	}
	if accessRego == "" {
		accessRego = policies.Access
	}
	if privilegedRego == "" {
		privilegedRego = policies.Privileged
	}
	ttl := l.Limits.HighRiskOfflineTTL
	if risk == "low" {
		ttl = l.Limits.LowRiskOfflineTTL
	}
	// Two publishers can read the same latest revision. The store rejects the loser.
	// Retry with a newly signed next revision. A lost race is not a committed duplicate.
	var version model.PolicyVersion
	for attempt := 0; attempt < 32; attempt++ {
		latest, err := l.Store.LatestRevision(caller.TenantID, policyID)
		if err != nil {
			return model.PolicyVersion{}, err
		}
		now := l.Clock.Now().Unix()
		signed, err := l.Signer.Sign(policy.Bundle{
			TenantID:       caller.TenantID,
			PolicyID:       policyID,
			Revision:       latest + 1,
			Risk:           risk,
			NotBeforeUnix:  now,
			NotAfterUnix:   now + int64(ttl/time.Second),
			AccessRego:     accessRego,
			PrivilegedRego: privilegedRego,
			Rollback:       rollback,
		})
		if err != nil {
			l.record(caller.TenantID, caller.ID, "publish", codeOf(err), policyID)
			return model.PolicyVersion{}, err
		}
		version = model.PolicyVersion{
			PolicyID: policyID, TenantID: caller.TenantID, Revision: signed.Bundle.Revision,
			Digest: signed.Digest, Signature: policy.SignatureText(signed.Signature), Risk: risk,
			NotBeforeUnix: signed.Bundle.NotBeforeUnix, NotAfterUnix: signed.Bundle.NotAfterUnix,
			Rollback: rollback, Payload: signed.Payload, SignatureBytes: signed.Signature,
		}
		if _, err := l.Store.AddVersion(version, "policy.revision.committed", signed.Digest); err != nil {
			if code := codeOf(err); code == "conflict" || code == "revision_replayed" {
				continue
			}
			l.record(caller.TenantID, caller.ID, "publish", codeOf(err), policyID)
			return model.PolicyVersion{}, err
		}
		l.record(caller.TenantID, caller.ID, "publish", "committed", policyID)
		return version, nil
	}
	l.record(caller.TenantID, caller.ID, "publish", "conflict", policyID)
	return model.PolicyVersion{}, apperr.New("conflict", "revision could not be reserved", 409)
}

func (l *Lab) Versions(caller model.Identity, policyID string) ([]model.PolicyVersion, error) {
	if caller.TenantID == "" || !model.HasRole(caller, RoleAdmin) {
		l.record(caller.TenantID, caller.ID, "read_policy", "forbidden", policyID)
		return nil, apperr.New("forbidden", "policy-admin role is required", 403)
	}
	versions, err := l.Store.Versions(caller.TenantID, policyID)
	if err != nil {
		if other, ok := l.Store.PolicyAny(policyID); ok && other.TenantID != caller.TenantID {
			l.record(other.TenantID, caller.ID, "read_policy", "tenant_forbidden", policyID)
			return nil, apperr.New("not_found", "policy was not found", 404)
		}
		l.record(caller.TenantID, caller.ID, "read_policy", codeOf(err), policyID)
		return nil, err
	}
	return versions, nil
}

func (l *Lab) Dispatch() error {
	events, err := l.Store.Unpublished()
	if err != nil {
		return err
	}
	now := l.Clock.Now().Unix()
	for _, event := range events {
		if _, err := l.Bus.Publish(event.ID, event.Type, event.Payload); err != nil {
			return err
		}
		if err := l.Store.MarkPublished(event.ID, now); err != nil {
			return err
		}
	}
	return nil
}
