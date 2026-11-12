package security_test

import (
	"testing"
	"time"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/platform"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/policy"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/policies"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestHighRiskPolicyExpires(t *testing.T) {
	lab := newLab(t)
	publish(t, lab, "high", false)
	if err := lab.SyncAll(); err != nil {
		t.Fatal(err)
	}
	before := lab.Authorize(platform.EdgeBranch, lab.Token("ada"), "read", platform.AppLedger)
	if !before.Allow || before.Reason != "permit" {
		t.Fatalf("before expiry: %+v", before)
	}
	lab.Clock.Advance(6 * time.Minute)
	after := lab.Authorize(platform.EdgeBranch, lab.Token("ada"), "read", platform.AppLedger)
	if after.Allow || after.Reason != "policy_expired" {
		t.Fatalf("after high-risk window: %+v", after)
	}
}

func TestSignedRollbackIsANewerRevision(t *testing.T) {
	lab := newLab(t)
	publish(t, lab, "low", false)
	if err := lab.SyncAll(); err != nil {
		t.Fatal(err)
	}
	rollback := publish(t, lab, "low", true)
	if rollback.Revision != 2 || !rollback.Rollback {
		t.Fatalf("rollback revision: %+v", rollback)
	}
	if err := lab.SyncAll(); err != nil {
		t.Fatal(err)
	}
	active, ok := lab.Backends[platform.EdgeHQ].Active()
	if !ok || active.Revision != 2 || !active.Rollback {
		t.Fatalf("active rollback: %+v %v", active, ok)
	}
	now := lab.Clock.Now().Unix()
	older, err := lab.Signer.Sign(policy.Bundle{
		TenantID:       platform.TenantCedar,
		PolicyID:       platform.PolicyAccess,
		Revision:       1,
		Risk:           "low",
		NotBeforeUnix:  now,
		NotAfterUnix:   now + 60,
		AccessRego:     policies.Access,
		PrivilegedRego: policies.Privileged,
		Rollback:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = lab.Backends[platform.EdgeHQ].Apply(older.Payload, older.Signature)
	if code(err) != "revision_replayed" {
		t.Fatal(err)
	}
	still, ok := lab.Backends[platform.EdgeHQ].Active()
	if !ok || still.Revision != 2 {
		t.Fatalf("active after replay: %+v", still)
	}
	if lab.Backends[platform.EdgeHQ].InvalidAccepted() != 0 {
		t.Fatal("replay was counted as accepted")
	}
}

func TestBundleStreamLimit(t *testing.T) {
	limits := platform.DefaultLimits()
	limits.MaxBundleBytes = 64
	lab, err := platform.New(platform.Options{Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lab.Close)
	publish(t, lab, "low", false)
	err = lab.SyncEdge(platform.EdgeHQ)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("sync error: %v", err)
	}
	if _, ok := lab.Backends[platform.EdgeHQ].Active(); ok {
		t.Fatal("oversized bundle was activated")
	}
	if lab.Backends[platform.EdgeHQ].InvalidAccepted() != 0 {
		t.Fatal("rejected bundle was counted as accepted")
	}
}
