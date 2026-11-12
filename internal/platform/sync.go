package platform

import (
	"context"
	"io"
	"time"

	policyv1 "github.com/JatinF/zero-trust-cloud-edge-control-plane/gen/policy/v1"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/edge"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/identity"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/policy"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/syncgrpc"
	"google.golang.org/grpc"
)

func (l *Lab) SyncAll() error {
	for _, edgeID := range EdgeIDs {
		if err := l.SyncEdge(edgeID); err != nil {
			return err
		}
	}
	return nil
}

func (l *Lab) SyncEdge(edgeID string) error {
	backend, ok := l.Backends[edgeID]
	if !ok {
		return apperr.New("not_found", "edge was not found", 404)
	}
	if !backend.Connected() {
		return apperr.New("edge_offline", "edge is disconnected", 503)
	}
	l.refresh(backend)
	current := uint64(0)
	if active, ok := backend.Active(); ok {
		current = active.Revision
	}
	conn, err := l.dial(identity.EdgeSPIFFE(edgeID))
	if err != nil {
		return err
	}
	defer conn.Close()
	client := policyv1.NewPolicySyncServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.Subscribe(ctx, &policyv1.SubscribeRequest{
		TenantId: backend.TenantID, EdgeId: edgeID, ActiveRevision: current,
	})
	if err != nil {
		return err
	}
	for {
		note, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		payload, signature, chunks, err := fetchBundle(ctx, client, note)
		if err != nil {
			return err
		}
		l.mu.Lock()
		l.chunks = chunks
		l.mu.Unlock()
		if err := backend.Apply(payload, signature); err != nil {
			return err
		}
		ack, err := client.Acknowledge(ctx, &policyv1.AckRequest{
			EdgeId: edgeID, PolicyId: note.GetPolicyId(), Revision: note.GetRevision(),
			ActivatedDigest: note.GetBundleDigest(),
		})
		if err != nil {
			return err
		}
		if ack == nil || !ack.GetAccepted() {
			return apperr.New("acknowledge_rejected", "control plane rejected the acknowledgment", 409)
		}
	}
	return l.syncEndpoints(backend)
}

func fetchBundle(ctx context.Context, client policyv1.PolicySyncServiceClient, note *policyv1.PolicyNotification) ([]byte, []byte, int, error) {
	stream, err := client.FetchBundle(ctx, &policyv1.BundleRequest{
		PolicyId: note.GetPolicyId(), Revision: note.GetRevision(),
	})
	if err != nil {
		return nil, nil, 0, err
	}
	var chunks [][]byte
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, len(chunks), err
		}
		chunks = append(chunks, append([]byte(nil), chunk.GetPayload()...))
	}
	payload, signature, err := syncgrpc.Assemble(chunks, note.GetBundleDigest())
	return payload, signature, len(chunks), err
}

func (l *Lab) Chunks() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.chunks
}

func (l *Lab) ApplyStored(edgeID, policyID string, revision uint64, ack bool) error {
	backend, ok := l.Backends[edgeID]
	if !ok {
		return apperr.New("not_found", "edge was not found", 404)
	}
	version, err := l.Store.Version(backend.TenantID, policyID, revision)
	if err != nil {
		return err
	}
	if err := backend.Apply(version.Payload, version.SignatureBytes); err != nil {
		return err
	}
	if !ack {
		return nil
	}
	return l.Store.AckDeployment(edgeID, policyID, revision, version.Digest, l.Clock.Now().Unix())
}

func (l *Lab) syncEndpoints(backend *edge.Backend) error {
	active, ok := backend.Active()
	if !ok {
		return nil
	}
	digest := policy.Digest(backend.Export().Payload)
	endpoints, err := l.Store.Endpoints(backend.TenantID, backend.ID)
	if err != nil {
		return err
	}
	for _, ep := range endpoints {
		if !ep.Connected {
			continue
		}
		if err := l.Store.UpdateEndpoint(ep.ID, active.Revision, digest, true); err != nil {
			return err
		}
	}
	return nil
}

func (l *Lab) SetEndpointConnected(id string, connected bool) error {
	ep, ok := l.Store.Endpoint(id)
	if !ok {
		return apperr.New("not_found", "endpoint was not found", 404)
	}
	return l.Store.UpdateEndpoint(id, ep.ActiveRevision, ep.ActiveDigest, connected)
}

func (l *Lab) Dial(spiffeID string) (*grpc.ClientConn, error) {
	return l.dial(spiffeID)
}

func (l *Lab) lookup(spiffeID string) (syncgrpc.Verified, bool) {
	if spiffeID == DiscoveryID {
		return syncgrpc.Verified{Kind: "discovery", ID: "discovery", TenantID: TenantCedar, SPIFFEID: spiffeID, Status: "active"}, true
	}
	if site, ok := l.Store.EdgeBySPIFFE(spiffeID); ok {
		return syncgrpc.Verified{
			Kind: "edge", ID: site.ID, TenantID: site.TenantID, EdgeID: site.ID,
			SPIFFEID: spiffeID, Status: site.Status,
		}, true
	}
	if ep, ok := l.Store.EndpointBySPIFFE(spiffeID); ok {
		return syncgrpc.Verified{
			Kind: "endpoint", ID: ep.ID, TenantID: ep.TenantID, EdgeID: ep.EdgeID,
			SPIFFEID: spiffeID, Status: "active",
		}, true
	}
	return syncgrpc.Verified{}, false
}

func (l *Lab) auditRPC(tenant, principal, action, decision, detail string) {
	l.record(tenant, principal, action, decision, detail)
}

func (l *Lab) policyList(tenant string) ([]model.Policy, error) {
	items, err := l.Store.Policies(tenant)
	if err != nil {
		return nil, err
	}
	sortBy(items, func(item model.Policy) string { return item.ID })
	return items, nil
}

func (l *Lab) versionList(tenant, policyID string) ([]model.PolicyVersion, error) {
	return l.Store.Versions(tenant, policyID)
}

func (l *Lab) ackDeployment(edgeID, policyID string, revision uint64, digest string) error {
	return l.Store.AckDeployment(edgeID, policyID, revision, digest, l.Clock.Now().Unix())
}

func (l *Lab) saveEndpoint(endpointID, edgeID string, revision uint64, digest string) error {
	ep, ok := l.Store.Endpoint(endpointID)
	if !ok || ep.EdgeID != edgeID {
		return apperr.New("not_found", "endpoint was not found", 404)
	}
	version, err := l.Store.Version(ep.TenantID, PolicyAccess, revision)
	if err != nil {
		return err
	}
	if version.Digest != digest {
		return apperr.New("digest_mismatch", "endpoint digest does not match the committed revision", 409)
	}
	return l.Store.UpdateEndpoint(endpointID, revision, digest, true)
}

func (l *Lab) Edges(caller model.Identity) ([]model.EdgeStatus, error) {
	if caller.TenantID == "" || !model.HasRole(caller, RoleAdmin) {
		l.record(caller.TenantID, caller.ID, "list_edges", "forbidden", "")
		return nil, apperr.New("forbidden", "policy-admin role is required", 403)
	}
	sites, err := l.Store.Edges(caller.TenantID)
	if err != nil {
		return nil, err
	}
	sortBy(sites, func(item model.EdgeSite) string { return item.ID })
	desired := uint64(0)
	if revision, err := l.Store.LatestRevision(caller.TenantID, PolicyAccess); err == nil {
		desired = revision
	}
	out := make([]model.EdgeStatus, 0, len(sites))
	for _, site := range sites {
		backend := l.Backends[site.ID]
		active := uint64(0)
		if bundle, ok := backend.Active(); ok {
			active = bundle.Revision
		}
		lag := uint64(0)
		if desired > active {
			lag = desired - active
		}
		deployment := "none"
		for _, item := range l.Store.Deployments(site.ID) {
			if item.Revision == desired && desired > 0 {
				deployment = item.Status
			}
		}
		syncStatus := "in_sync"
		if !backend.Connected() {
			syncStatus = "offline"
		} else if lag > 0 && backend.LastError() != "" {
			syncStatus = "failed"
		} else if lag > 0 {
			syncStatus = "behind"
		}
		out = append(out, model.EdgeStatus{
			EdgeID: site.ID, Location: site.Location, ActiveRevision: active, DesiredRevision: desired,
			Lag: lag, SyncStatus: syncStatus, Connected: backend.Connected(), LastError: backend.LastError(),
			DeploymentStatus: deployment,
		})
	}
	return out, nil
}

func (l *Lab) Endpoints(caller model.Identity, edgeID string) ([]model.Endpoint, error) {
	if caller.TenantID == "" || !model.HasRole(caller, RoleAdmin) {
		return nil, apperr.New("forbidden", "policy-admin role is required", 403)
	}
	items, err := l.Store.Endpoints(caller.TenantID, edgeID)
	if err != nil {
		return nil, err
	}
	sortBy(items, func(item model.Endpoint) string { return item.ID })
	return items, nil
}
