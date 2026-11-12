package platform

import (
	"context"
	"time"

	discoveryv1 "github.com/JatinF/zero-trust-cloud-edge-control-plane/gen/discovery/v1"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/discovery"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"
)

func (l *Lab) StartDiscovery(caller model.Identity, connector string) (model.DiscoveryJob, error) {
	if caller.TenantID == "" || !model.HasRole(caller, RoleAdmin) {
		l.record(caller.TenantID, caller.ID, "discover", "forbidden", connector)
		return model.DiscoveryJob{}, apperr.New("forbidden", "policy-admin role is required", 403)
	}
	if _, err := discovery.Scan(connector); err != nil {
		l.record(caller.TenantID, caller.ID, "discover", codeOf(err), connector)
		return model.DiscoveryJob{}, err
	}
	job, err := l.Store.AddJob(model.DiscoveryJob{TenantID: caller.TenantID, Connector: connector, Status: "running"})
	if err != nil {
		return model.DiscoveryJob{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	err = l.Pool.Submit(ctx, func() {
		items, scanErr := discovery.Scan(connector)
		if scanErr != nil {
			done <- scanErr
			return
		}
		if addErr := l.Store.AddAssets(discovery.ToModel(caller.TenantID, l.Clock.Now().Unix(), items)); addErr != nil {
			done <- addErr
			return
		}
		done <- l.Store.FinishJob(job.ID, "succeeded")
	})
	if err != nil {
		_ = l.Store.FinishJob(job.ID, "rejected")
		l.record(caller.TenantID, caller.ID, "discover", codeOf(err), connector)
		return job, err
	}
	if waitErr := <-done; waitErr != nil {
		l.record(caller.TenantID, caller.ID, "discover", codeOf(waitErr), job.ID)
		return job, waitErr
	}
	job.Status = "succeeded"
	l.record(caller.TenantID, caller.ID, "discover", "succeeded", job.ID)
	return job, nil
}

func (l *Lab) Assets(caller model.Identity, kind string) ([]model.Asset, error) {
	if caller.TenantID == "" || !model.HasRole(caller, RoleAdmin) {
		return nil, apperr.New("forbidden", "policy-admin role is required", 403)
	}
	items, err := l.Store.Assets(caller.TenantID, kind)
	if err != nil {
		return nil, err
	}
	sortBy(items, func(item model.Asset) string { return item.ID })
	return items, nil
}

func (l *Lab) saveAssets(jobID, connector string, assets []*discoveryv1.Asset) (int, error) {
	job, ok := l.Store.Job(jobID)
	if !ok {
		return 0, apperr.New("not_found", "job was not found", 404)
	}
	if job.Connector != connector {
		return 0, apperr.New("conflict", "connector does not match the job", 409)
	}
	expected, err := discovery.Scan(connector)
	if err != nil {
		return 0, err
	}
	if len(assets) != len(expected) {
		return 0, apperr.New("policy_format", "asset report does not match the connector catalog", 422)
	}
	catalog := map[string]discovery.Asset{}
	for _, item := range expected {
		catalog[item.ID] = item
	}
	for _, item := range assets {
		match, found := catalog[item.GetAssetId()]
		if !found || match.Type != item.GetAssetType() || match.Source != item.GetSource() {
			return 0, apperr.New("policy_format", "asset is not in the connector catalog", 422)
		}
	}
	if err := l.Store.AddAssets(discovery.ToModel(job.TenantID, l.Clock.Now().Unix(), expected)); err != nil {
		return 0, err
	}
	return len(expected), nil
}

func (l *Lab) Audit(caller model.Identity, decision string) ([]model.AuditEvent, error) {
	if caller.TenantID == "" || !model.HasRole(caller, RoleAdmin) {
		return nil, apperr.New("forbidden", "policy-admin role is required", 403)
	}
	l.flushAudit()
	return l.Store.Audit(caller.TenantID, decision)
}

func (l *Lab) flushAudit() {
	if !l.Store.Available() {
		return
	}
	l.mu.Lock()
	pending := append([]model.AuditEvent(nil), l.spool...)
	l.spool = nil
	l.mu.Unlock()
	for _, item := range pending {
		if _, err := l.Store.AddAudit(item); err != nil {
			l.mu.Lock()
			l.spool = append(l.spool, item)
			l.mu.Unlock()
		}
	}
}
