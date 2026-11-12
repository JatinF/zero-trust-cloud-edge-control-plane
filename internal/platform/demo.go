package platform

import (
	"time"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
)

type DemoReport struct {
	Tenant                 string `json:"tenant"`
	Revision               uint64 `json:"revision"`
	Edges                  int    `json:"edges"`
	EndpointAcks           int    `json:"endpoint_acks"`
	Read                   string `json:"read"`
	CrossTenant            string `json:"cross_tenant"`
	Tampered               string `json:"tampered"`
	Replay                 string `json:"replay"`
	SelfApproval           string `json:"self_approval"`
	GrantTTLSeconds        int    `json:"grant_ttl_seconds"`
	PrivilegedBeforeExpiry string `json:"privileged_before_expiry"`
	PrivilegedAfterExpiry  string `json:"privileged_after_expiry"`
	RevokeWhilePartition   string `json:"revoke_while_partition"`
	RevokeAfterReconnect   string `json:"revoke_after_reconnect"`
	OfflineRead            string `json:"offline_read"`
	ExpiredOffline         string `json:"expired_offline"`
	InvalidBundlesAccepted int    `json:"invalid_bundles_accepted"`
	RejectedUpdates        int    `json:"rejected_updates"`
	UnauthorizedGrants     int    `json:"unauthorized_grants"`
	AuditMissing           int    `json:"audit_missing"`
	Price                  string `json:"price"`
}

// Demo runs the synthetic Cedar lifecycle. It does not contact a customer environment.
func (l *Lab) Demo() (DemoReport, error) {
	report := DemoReport{Tenant: TenantCedar, Price: "none"}
	ada, err := l.Identity("ada")
	if err != nil {
		return report, err
	}
	birch, err := l.Identity("birch")
	if err != nil {
		return report, err
	}
	jules, err := l.Identity("jules")
	if err != nil {
		return report, err
	}
	kiran, err := l.Identity("kiran")
	if err != nil {
		return report, err
	}
	if _, err := l.CreatePolicy(ada, PolicyAccess, "edge", "low"); err != nil {
		return report, err
	}
	first, err := l.Publish(ada, PolicyAccess, "low", "", "", false)
	if err != nil {
		return report, err
	}
	if err := l.Dispatch(); err != nil {
		return report, err
	}
	if err := l.SyncAll(); err != nil {
		return report, err
	}
	second, err := l.Publish(ada, PolicyAccess, "low", "", "", false)
	if err != nil {
		return report, err
	}
	if err := l.Dispatch(); err != nil {
		return report, err
	}
	if err := l.SyncAll(); err != nil {
		return report, err
	}
	report.Revision = second.Revision
	for _, edgeID := range EdgeIDs {
		if active, ok := l.Backends[edgeID].Active(); ok && active.Revision == second.Revision {
			report.Edges++
		}
		items, err := l.Endpoints(ada, edgeID)
		if err != nil {
			return report, err
		}
		for _, ep := range items {
			if ep.ActiveRevision == second.Revision {
				report.EndpointAcks++
			}
		}
	}
	report.Read = l.Authorize(EdgeBranch, l.Token("ada"), "read", AppLedger).Reason
	if _, err := l.Versions(birch, PolicyAccess); err != nil {
		report.CrossTenant = codeOf(err)
	}
	tampered := append([]byte(nil), second.Payload...)
	tampered[len(tampered)-1] ^= 0x01
	report.Tampered = codeOf(l.Present(EdgeBranch, tampered, second.SignatureBytes))
	report.Replay = codeOf(l.Present(EdgeBranch, first.Payload, first.SignatureBytes))
	report.UnauthorizedGrants = l.Store.GrantCount()

	own, err := l.RequestAccess(kiran, DBLedger, "admin", "inspect")
	if err != nil {
		return report, err
	}
	if _, err := l.Approve(kiran, own.ID); err != nil {
		report.SelfApproval = codeOf(err)
	}
	request, err := l.RequestAccess(jules, DBLedger, "admin", "maintenance window")
	if err != nil {
		return report, err
	}
	grant, err := l.Approve(kiran, request.ID)
	if err != nil {
		return report, err
	}
	report.GrantTTLSeconds = int(time.Unix(grant.ExpiresAtUnix, 0).Sub(l.Clock.Now()).Seconds())
	report.PrivilegedBeforeExpiry = l.Authorize(EdgeBranch, l.Token("jules"), "admin", DBLedger).Reason
	l.Backends[EdgeBranch].SetConnected(false)
	if _, err := l.Revoke(kiran, request.ID); err != nil {
		return report, err
	}
	report.RevokeWhilePartition = l.Authorize(EdgeBranch, l.Token("jules"), "admin", DBLedger).Reason
	l.Backends[EdgeBranch].SetConnected(true)
	if err := l.SyncEdge(EdgeBranch); err != nil {
		return report, err
	}
	report.RevokeAfterReconnect = l.Authorize(EdgeBranch, l.Token("jules"), "admin", DBLedger).Reason
	secondRequest, err := l.RequestAccess(jules, DBLedger, "admin", "follow-up")
	if err != nil {
		return report, err
	}
	if _, err := l.Approve(kiran, secondRequest.ID); err != nil {
		return report, err
	}
	l.Clock.Advance(6 * time.Minute)
	report.PrivilegedAfterExpiry = l.Authorize(EdgeBranch, l.Token("jules"), "admin", DBLedger).Reason

	l.Backends[EdgeBranch].SetConnected(false)
	l.Store.SetDown(true)
	report.OfflineRead = l.Authorize(EdgeBranch, l.Token("ada"), "read", AppLedger).Reason
	l.Clock.Advance(25 * time.Minute)
	report.ExpiredOffline = l.Authorize(EdgeBranch, l.Token("ada"), "read", AppLedger).Reason
	l.Store.SetDown(false)

	for _, edgeID := range EdgeIDs {
		report.InvalidBundlesAccepted += l.Backends[edgeID].InvalidAccepted()
		report.RejectedUpdates += l.Backends[edgeID].Rejected()
	}
	events, err := l.Audit(ada, "")
	if err != nil {
		return report, err
	}
	seen := map[string]bool{}
	for _, event := range events {
		seen[event.Decision] = true
	}
	for _, decision := range []string{
		"tenant_forbidden", "signature_invalid", "revision_replayed", "permit",
		"grant_permit", "self_approval", "revoked", "grant_revoked", "grant_expired", "policy_expired",
	} {
		if !seen[decision] {
			report.AuditMissing++
		}
	}
	return report, nil
}

func (l *Lab) Present(edgeID string, payload, signature []byte) error {
	backend, ok := l.Backends[edgeID]
	if !ok {
		return errNotFound()
	}
	err := backend.Apply(payload, signature)
	decision := "activated"
	if err != nil {
		decision = codeOf(err)
	}
	l.record(backend.TenantID, edgeID, "present_bundle", decision, "")
	return err
}

func errNotFound() error {
	return apperr.New("not_found", "edge was not found", 404)
}
