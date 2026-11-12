package chaos_test

import (
	"context"
	"testing"
	"time"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/discovery"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/edge"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/platform"
)

func TestRestartDuringActivation(t *testing.T) {
	lab := newLab(t)
	first := publish(t, lab, "low")
	if err := lab.SyncEdge(platform.EdgeBranch); err != nil {
		t.Fatal(err)
	}
	snap := lab.Backends[platform.EdgeBranch].Export()
	second := publish(t, lab, "low")
	if code(lab.Backends[platform.EdgeBranch].StageStoppingBeforeActivate(second.Payload, second.SignatureBytes)) != "activation_interrupted" {
		t.Fatal("stage did not stop")
	}
	active, _ := lab.Backends[platform.EdgeBranch].Active()
	if active.Revision != first.Revision {
		t.Fatalf("active changed during interrupted activation: %d", active.Revision)
	}
	fresh := edge.New(platform.EdgeBranch, platform.TenantCedar, "branch", lab.Public, lab.Clock, 30*time.Minute, 5*time.Minute)
	if err := fresh.Recover(snap); err != nil {
		t.Fatal(err)
	}
	recovered, ok := fresh.Active()
	if !ok || recovered.Revision != first.Revision {
		t.Fatalf("recovered revision = %+v", recovered)
	}
	snap.Payload[0] ^= 0x01
	damaged := edge.New(platform.EdgeBranch, platform.TenantCedar, "branch", lab.Public, lab.Clock, 30*time.Minute, 5*time.Minute)
	if err := damaged.Recover(snap); err == nil {
		t.Fatal("tampered snapshot was recovered")
	}
	if _, ok := damaged.Active(); ok {
		t.Fatal("tampered snapshot became active")
	}
}

func TestEndpointDisconnectAndReconcile(t *testing.T) {
	lab := newLab(t)
	first := publish(t, lab, "low")
	if err := lab.SyncAll(); err != nil {
		t.Fatal(err)
	}
	if err := lab.SetEndpointConnected("SYN-EP-001", false); err != nil {
		t.Fatal(err)
	}
	lab.Backends[platform.EdgeBranch].SetConnected(false)
	second := publish(t, lab, "low")
	third := publish(t, lab, "low")
	if err := lab.SyncEdge(platform.EdgeHQ); err != nil {
		t.Fatal(err)
	}
	if err := lab.SyncEdge(platform.EdgeBranch); code(err) != "edge_offline" {
		t.Fatalf("offline sync = %v", err)
	}
	lab.Backends[platform.EdgeBranch].SetConnected(true)
	if err := lab.SyncEdge(platform.EdgeBranch); err != nil {
		t.Fatal(err)
	}
	active, _ := lab.Backends[platform.EdgeBranch].Active()
	if active.Revision != third.Revision {
		t.Fatalf("reconciled revision = %d, want %d", active.Revision, third.Revision)
	}
	var sawSuperseded, sawAck bool
	for _, item := range lab.Store.Deployments(platform.EdgeBranch) {
		if item.Revision == second.Revision && item.Status == "superseded" {
			sawSuperseded = true
		}
		if item.Revision == third.Revision && item.Status == "acknowledged" {
			sawAck = true
		}
	}
	if !sawSuperseded || !sawAck {
		t.Fatalf("deployments = %+v", lab.Store.Deployments(platform.EdgeBranch))
	}
	ep, _ := lab.Store.Endpoint("SYN-EP-001")
	if ep.ActiveRevision != first.Revision {
		t.Fatalf("disconnected endpoint moved to %d", ep.ActiveRevision)
	}
	_ = first
}

func TestOutOfOrderDuplicateAndLostAck(t *testing.T) {
	lab := newLab(t)
	first := publish(t, lab, "low")
	if err := lab.ApplyStored(platform.EdgeHQ, platform.PolicyAccess, first.Revision, false); err != nil {
		t.Fatal(err)
	}
	pending := false
	for _, item := range lab.Store.Deployments(platform.EdgeHQ) {
		if item.Revision == first.Revision && item.Status == "pending" {
			pending = true
		}
	}
	if !pending {
		t.Fatal("acknowledgment was recorded before it was sent")
	}
	if err := lab.ApplyStored(platform.EdgeHQ, platform.PolicyAccess, first.Revision, true); err != nil {
		t.Fatal(err)
	}
	if lab.Backends[platform.EdgeHQ].ActivationCount(first.Revision) != 1 {
		t.Fatal("duplicate delivery activated twice")
	}
	second := publish(t, lab, "low")
	third := publish(t, lab, "low")
	if err := lab.ApplyStored(platform.EdgeRegion, platform.PolicyAccess, third.Revision, true); err != nil {
		t.Fatal(err)
	}
	if code(lab.ApplyStored(platform.EdgeRegion, platform.PolicyAccess, second.Revision, false)) != "revision_replayed" {
		t.Fatal("out-of-order older revision was accepted")
	}
	active, _ := lab.Backends[platform.EdgeRegion].Active()
	if active.Revision != third.Revision {
		t.Fatalf("region revision = %d", active.Revision)
	}
}

func TestStoreAndBusOutage(t *testing.T) {
	lab := newLab(t)
	ada, err := lab.Identity("ada")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lab.CreatePolicy(ada, platform.PolicyAccess, "edge", "low"); err != nil {
		t.Fatal(err)
	}
	version, err := lab.Publish(ada, platform.PolicyAccess, "low", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	lab.Bus.SetDown(true)
	if code(lab.Dispatch()) != "dependency_unavailable" {
		t.Fatal("bus outage did not stop dispatch")
	}
	events, err := lab.Store.Unpublished()
	if err != nil || len(events) != 1 {
		t.Fatalf("unpublished = %+v %v", events, err)
	}
	lab.Bus.SetDown(false)
	if err := lab.Dispatch(); err != nil {
		t.Fatal(err)
	}
	lab.Bus.Redeliver()
	msg, ok := lab.Bus.Receive()
	if !ok || msg.EventID == "" {
		t.Fatal("redelivery lost the committed event")
	}
	if err := lab.SyncAll(); err != nil {
		t.Fatal(err)
	}
	lab.Store.SetDown(true)
	decision := lab.Authorize(platform.EdgeBranch, lab.Token("ada"), "read", platform.AppLedger)
	if !decision.Allow {
		t.Fatalf("store outage denied a valid local policy: %+v", decision)
	}
	if _, err := lab.Publish(ada, platform.PolicyAccess, "low", "", "", false); code(err) != "dependency_unavailable" {
		t.Fatalf("publish during store outage = %v", err)
	}
	_ = version
}

func TestWorkerPoolSaturation(t *testing.T) {
	pool := discovery.NewPool(2)
	release := make(chan struct{})
	for i := 0; i < 2; i++ {
		if err := pool.Submit(context.Background(), func() { <-release }); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := pool.Submit(ctx, func() {})
	close(release)
	if code(err) != "worker_pool_saturated" {
		t.Fatalf("saturation = %v", err)
	}
	if pool.MaxSeen() > 2 {
		t.Fatalf("in-flight = %d", pool.MaxSeen())
	}
}

func TestUnknownConnectorIsNotAScan(t *testing.T) {
	if _, err := discovery.Scan("http://10.0.0.1/"); code(err) != "unknown_connector" {
		t.Fatal(err)
	}
	lab := newLab(t)
	ada, _ := lab.Identity("ada")
	if _, err := lab.StartDiscovery(ada, "sim-cmdb"); err != nil {
		t.Fatal(err)
	}
	assets, err := lab.Assets(ada, "database")
	if err != nil || len(assets) != 1 || assets[0].ID != "SYN-ASSET-DB-1" {
		t.Fatalf("assets = %+v %v", assets, err)
	}
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

func publish(t *testing.T, lab *platform.Lab, risk string) model.PolicyVersion {
	t.Helper()
	ada, err := lab.Identity("ada")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lab.CreatePolicy(ada, platform.PolicyAccess, "edge", risk); err != nil && code(err) != "conflict" {
		t.Fatal(err)
	}
	version, err := lab.Publish(ada, platform.PolicyAccess, risk, "", "", false)
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
	if !ok || err == nil {
		return ""
	}
	return item.Code
}
