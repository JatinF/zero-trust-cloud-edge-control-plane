package security_test

import (
	"context"
	"strings"
	"testing"
	"time"

	endpointv1 "github.com/JatinF/zero-trust-cloud-edge-control-plane/gen/endpoint/v1"
	policyv1 "github.com/JatinF/zero-trust-cloud-edge-control-plane/gen/policy/v1"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/edge"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/identity"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/platform"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCrossTenantReadIsNotFound(t *testing.T) {
	lab := newLab(t)
	publish(t, lab, "low", false)
	birch, err := lab.Identity("birch")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lab.Versions(birch, platform.PolicyAccess); code(err) != "not_found" {
		t.Fatal(err)
	}
}

func TestExpiredAndForeignWorkloadCertificates(t *testing.T) {
	lab := newLab(t)
	publish(t, lab, "low", false)
	if err := lab.SyncEdge(platform.EdgeHQ); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	expired, err := lab.Issuer.Leaf(identity.EdgeSPIFFE(platform.EdgeHQ), platform.EdgeHQ, now.Add(-2*time.Hour), now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	saved := lab.Certs[identity.EdgeSPIFFE(platform.EdgeHQ)]
	lab.Certs[identity.EdgeSPIFFE(platform.EdgeHQ)] = expired
	if err := subscribe(t, lab, identity.EdgeSPIFFE(platform.EdgeHQ), platform.EdgeHQ); err == nil {
		t.Fatal("expired certificate was accepted")
	}
	other, err := identity.NewIssuer(now)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := other.Leaf(identity.EdgeSPIFFE(platform.EdgeHQ), platform.EdgeHQ, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	lab.Certs[identity.EdgeSPIFFE(platform.EdgeHQ)] = foreign
	if err := subscribe(t, lab, identity.EdgeSPIFFE(platform.EdgeHQ), platform.EdgeHQ); err == nil {
		t.Fatal("foreign certificate was accepted")
	}
	lab.Certs[identity.EdgeSPIFFE(platform.EdgeHQ)] = saved
}

func TestUnauthorizedActionAndGrantExpiry(t *testing.T) {
	lab := newLab(t)
	publish(t, lab, "low", false)
	if err := lab.SyncAll(); err != nil {
		t.Fatal(err)
	}
	readDB := lab.Authorize(platform.EdgeBranch, lab.Token("ada"), "read", platform.DBLedger)
	if readDB.Allow || readDB.Reason != "denied" {
		t.Fatalf("database read = %+v", readDB)
	}
	admin := lab.Authorize(platform.EdgeBranch, lab.Token("jules"), "admin", platform.DBLedger)
	if admin.Allow || admin.Reason != "grant_invalid" {
		t.Fatalf("ungranted admin = %+v", admin)
	}
	if lab.Store.GrantCount() != 0 {
		t.Fatal("unauthorized path created a grant")
	}
	jules, _ := lab.Identity("jules")
	kiran, _ := lab.Identity("kiran")
	request, err := lab.RequestAccess(jules, platform.DBLedger, "admin", "window")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lab.Approve(kiran, request.ID); err != nil {
		t.Fatal(err)
	}
	lab.Clock.Advance(6 * time.Minute)
	expired := lab.Authorize(platform.EdgeBranch, lab.Token("jules"), "admin", platform.DBLedger)
	if expired.Allow || expired.Reason != "grant_expired" {
		t.Fatalf("expired grant = %+v", expired)
	}
}

func TestBundleRejection(t *testing.T) {
	lab := newLab(t)
	first := publish(t, lab, "low", false)
	if err := lab.SyncAll(); err != nil {
		t.Fatal(err)
	}
	second := publish(t, lab, "low", false)
	if err := lab.SyncEdge(platform.EdgeHQ); err != nil {
		t.Fatal(err)
	}
	if code(lab.Present(platform.EdgeHQ, first.Payload, first.SignatureBytes)) != "revision_replayed" {
		t.Fatal("older revision was not rejected")
	}
	tampered := append([]byte(nil), second.Payload...)
	tampered[len(tampered)-1] ^= 0x01
	if code(lab.Present(platform.EdgeHQ, tampered, second.SignatureBytes)) != "signature_invalid" {
		t.Fatal("tampered bundle was not rejected")
	}
	if code(lab.Present(platform.EdgeHQ, second.Payload, nil)) != "signature_missing" {
		t.Fatal("missing signature was not rejected")
	}
	active, _ := lab.Backends[platform.EdgeHQ].Active()
	if active.Revision != second.Revision || lab.Backends[platform.EdgeHQ].InvalidAccepted() != 0 {
		t.Fatalf("active revision changed after rejected updates: %+v", active)
	}
	short := edge.New(platform.EdgeBranch, platform.TenantCedar, "branch", lab.Public, lab.Clock, time.Minute, time.Minute)
	if code(short.Apply(second.Payload, second.SignatureBytes)) != "policy_window" {
		t.Fatal("over-long offline window was accepted")
	}
}

func TestEdgeAndEndpointImpersonation(t *testing.T) {
	lab := newLab(t)
	publish(t, lab, "low", false)
	err := subscribe(t, lab, identity.EdgeSPIFFE(platform.EdgeHQ), platform.EdgeBranch)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("edge impersonation = %v", err)
	}
	conn, err := lab.Dial(identity.EndpointSPIFFE("SYN-EP-001"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = endpointv1.NewEndpointServiceClient(conn).ReportStatus(context.Background(), &endpointv1.StatusReport{
		EndpointId: "SYN-EP-002", EdgeId: platform.EdgeHQ, ActiveRevision: 1, Digest: "none",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("endpoint impersonation = %v", err)
	}
}

func TestInactiveAndRevokedIdentity(t *testing.T) {
	lab := newLab(t)
	publish(t, lab, "low", false)
	if err := lab.SyncAll(); err != nil {
		t.Fatal(err)
	}
	if err := lab.Store.SetIdentityStatus(platform.UserAda, "inactive"); err != nil {
		t.Fatal(err)
	}
	inactive := lab.Authorize(platform.EdgeBranch, lab.Token("ada"), "read", platform.AppLedger)
	if inactive.Allow || inactive.Reason != "identity_inactive" {
		t.Fatalf("inactive = %+v", inactive)
	}
	if err := lab.Store.SetIdentityStatus(platform.UserAda, "revoked"); err != nil {
		t.Fatal(err)
	}
	revoked := lab.Authorize(platform.EdgeBranch, lab.Token("ada"), "read", platform.AppLedger)
	if revoked.Allow || revoked.Reason != "identity_revoked" {
		t.Fatalf("revoked = %+v", revoked)
	}
	if err := lab.Store.SetEdgeStatus(platform.EdgeHQ, "revoked"); err != nil {
		t.Fatal(err)
	}
	if err := subscribe(t, lab, identity.EdgeSPIFFE(platform.EdgeHQ), platform.EdgeHQ); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked workload = %v", err)
	}
}

func TestCacheCannotPermit(t *testing.T) {
	lab := newLab(t)
	publish(t, lab, "low", false)
	if err := lab.SyncAll(); err != nil {
		t.Fatal(err)
	}
	lab.Cache.Set("decision", "allow")
	denied := lab.Authorize(platform.EdgeBranch, lab.Token("ada"), "read", platform.DBLedger)
	if denied.Allow {
		t.Fatal("poisoned cache turned a deny into an allow")
	}
	lab.Cache.SetDown(true)
	allowed := lab.Authorize(platform.EdgeBranch, lab.Token("ada"), "read", platform.AppLedger)
	if !allowed.Allow {
		t.Fatalf("cache outage changed a permitted read: %+v", allowed)
	}
	lab.Cache.SetDown(false)
	stillDenied := lab.Authorize(platform.EdgeBranch, lab.Token("ada"), "read", platform.DBLedger)
	if stillDenied.Allow {
		t.Fatal("cache recovery turned a deny into an allow")
	}
}

func TestReasonRedaction(t *testing.T) {
	lab := newLab(t)
	jules, err := lab.Identity("jules")
	if err != nil {
		t.Fatal(err)
	}
	request, err := lab.RequestAccess(jules, platform.DBLedger, "admin", "token lab-token-harbor-secret")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(request.Reason, "lab-token-harbor") {
		t.Fatalf("reason stored a token: %s", request.Reason)
	}
	ada, _ := lab.Identity("ada")
	events, err := lab.Audit(ada, "")
	if err != nil {
		t.Fatal(err)
	}
	blob := ""
	for _, event := range events {
		blob += event.Detail + event.Decision
	}
	if strings.Contains(blob, "lab-token-harbor") || strings.Contains(blob, lab.Token("ada")) {
		t.Fatal("audit contains a raw token")
	}
}

func subscribe(t *testing.T, lab *platform.Lab, spiffeID, edgeID string) error {
	t.Helper()
	conn, err := lab.Dial(spiffeID)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := policyv1.NewPolicySyncServiceClient(conn).Subscribe(ctx, &policyv1.SubscribeRequest{
		TenantId: platform.TenantCedar, EdgeId: edgeID,
	})
	if err != nil {
		return err
	}
	_, err = stream.Recv()
	return err
}

func newLab(t *testing.T) *platform.Lab {
	t.Helper()
	lab, err := platform.NewLab()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lab.Close)
	return lab
}

func publish(t *testing.T, lab *platform.Lab, risk string, rollback bool) model.PolicyVersion {
	t.Helper()
	ada, err := lab.Identity("ada")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lab.CreatePolicy(ada, platform.PolicyAccess, "edge", risk); err != nil && code(err) != "conflict" {
		t.Fatal(err)
	}
	version, err := lab.Publish(ada, platform.PolicyAccess, risk, "", "", rollback)
	if err != nil {
		t.Fatal(err)
	}
	if err := lab.Dispatch(); err != nil {
		t.Fatal(err)
	}
	return version
}

func code(err error) string {
	item, ok := apperr.As(err)
	if !ok {
		return ""
	}
	return item.Code
}
