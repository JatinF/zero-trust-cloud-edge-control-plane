package platform

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	discoveryv1 "github.com/JatinF/zero-trust-cloud-edge-control-plane/gen/discovery/v1"
	endpointv1 "github.com/JatinF/zero-trust-cloud-edge-control-plane/gen/endpoint/v1"
	policyv1 "github.com/JatinF/zero-trust-cloud-edge-control-plane/gen/policy/v1"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/cache"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/clock"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/config"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/discovery"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/edge"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/gates"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/httpapi"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/identity"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/messaging"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/policy"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/storage/memory"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/syncgrpc"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/telemetry"
	simendpoints "github.com/JatinF/zero-trust-cloud-edge-control-plane/simulators/endpoints"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

type Options struct {
	Now    time.Time
	Limits config.Limits
	Env    map[string]string
}

type Lab struct {
	Clock      *clock.Clock
	Store      *memory.Store
	Bus        *messaging.Log
	Cache      *cache.Cache
	Signer     *policy.Signer
	Limits     config.Limits
	Issuer     *identity.Issuer
	Backends   map[string]*edge.Backend
	Tokens     map[string]string
	Certs      map[string]tls.Certificate
	Telemetry  *telemetry.Hub
	Pool       *discovery.Pool
	Handler    http.Handler
	Public     ed25519.PublicKey
	grpcServer *grpc.Server
	listener   *bufconn.Listener
	env        map[string]string
	mu         sync.Mutex
	spool      []model.AuditEvent
	chunks     int
}

func DefaultLimits() config.Limits {
	limits, err := (config.File{
		GrantTTL:           "5m",
		LowRiskOfflineTTL:  "30m",
		HighRiskOfflineTTL: "5m",
		ChunkBytes:         128,
		MaxBundleBytes:     1 << 20,
		WorkerPool:         4,
		SimulatedEndpoints: 300,
	}).Limits()
	if err != nil {
		panic(err)
	}
	return limits
}

func NewLab() (*Lab, error) {
	return New(Options{
		Now:    time.Date(2026, 11, 11, 18, 0, 0, 0, time.UTC),
		Limits: DefaultLimits(),
	})
}

func New(opts Options) (*Lab, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Date(2026, 11, 11, 18, 0, 0, 0, time.UTC)
	}
	if opts.Limits.GrantTTL == 0 {
		opts.Limits = DefaultLimits()
	}
	signer, err := policy.NewSigner()
	if err != nil {
		return nil, err
	}
	issuer, err := identity.NewIssuer(time.Now().UTC())
	if err != nil {
		return nil, err
	}
	clk := clock.New(opts.Now)
	lab := &Lab{
		Clock:     clk,
		Store:     memory.New(clk),
		Bus:       messaging.New(),
		Cache:     cache.New(),
		Signer:    signer,
		Limits:    opts.Limits,
		Issuer:    issuer,
		Backends:  map[string]*edge.Backend{},
		Tokens:    map[string]string{},
		Certs:     map[string]tls.Certificate{},
		Telemetry: telemetry.New("control-plane"),
		Pool:      discovery.NewPool(opts.Limits.WorkerPool),
		Public:    signer.Public(),
		env:       map[string]string{},
	}
	for key, value := range opts.Env {
		lab.env[key] = value
	}
	if err := lab.seed(); err != nil {
		return nil, err
	}
	if err := lab.serveRPC(); err != nil {
		return nil, err
	}
	lab.Handler = httpapi.New(lab, lab.Telemetry.Handler(), "control-plane")
	return lab, nil
}

func (l *Lab) Close() {
	if l.grpcServer != nil {
		l.grpcServer.GracefulStop()
	}
	if l.listener != nil {
		_ = l.listener.Close()
	}
}

func (l *Lab) SetEnv(key, value string) {
	l.mu.Lock()
	l.env[key] = value
	l.mu.Unlock()
}

func (l *Lab) Authenticate(raw string) (model.Identity, error) {
	id, _, err := l.Store.Authenticate(raw, l.Clock.Now().Unix())
	if err != nil {
		l.record("", "anonymous", "authenticate", codeOf(err), "")
		return model.Identity{}, err
	}
	return id, nil
}

func (l *Lab) Gates(model.Identity) ([]gates.Gate, error) {
	l.mu.Lock()
	env := map[string]string{}
	for key, value := range l.env {
		env[key] = value
	}
	l.mu.Unlock()
	return gates.Evaluate(env), nil
}

func (l *Lab) seed() error {
	now := time.Now().UTC()
	if err := l.Store.PutTenant(model.Tenant{ID: TenantCedar, Name: "Cedar", Status: "active"}); err != nil {
		return err
	}
	if err := l.Store.PutTenant(model.Tenant{ID: TenantBirch, Name: "Birch", Status: "active"}); err != nil {
		return err
	}
	people := []struct {
		name, tenant, role string
	}{
		{"platform", "", RolePlatform},
		{"ada", TenantCedar, RoleAdmin},
		{"jules", TenantCedar, RoleRequester},
		{"kiran", TenantCedar, RoleApprover},
		{"birch", TenantBirch, RoleAdmin},
	}
	ids := map[string]string{
		"platform": UserPlatform,
		"ada":      UserAda,
		"jules":    UserJules,
		"kiran":    UserKiran,
		"birch":    UserBirch,
	}
	expires := l.Clock.Now().Add(24 * time.Hour).Unix()
	for _, person := range people {
		id := model.Identity{
			ID: ids[person.name], TenantID: person.tenant, Type: "human", Owner: person.name,
			Status: "active", Roles: []string{person.role},
		}
		if err := l.Store.PutIdentity(id); err != nil {
			return err
		}
		raw, err := newToken(person.name)
		if err != nil {
			return err
		}
		l.Tokens[person.name] = raw
		if err := l.Store.PutToken(raw, model.TokenRecord{IdentityID: id.ID, ExpiresAtUnix: expires}); err != nil {
			return err
		}
	}
	resources := []model.Resource{
		{ID: AppLedger, TenantID: TenantCedar, Kind: "app", Location: "branch"},
		{ID: DBLedger, TenantID: TenantCedar, Kind: "database", Location: "branch"},
	}
	for _, resource := range resources {
		if err := l.Store.PutResource(resource); err != nil {
			return err
		}
	}
	locations := map[string]string{EdgeHQ: "headquarters", EdgeRegion: "regional", EdgeBranch: "branch"}
	for _, edgeID := range EdgeIDs {
		spiffeID := identity.EdgeSPIFFE(edgeID)
		site := model.EdgeSite{ID: edgeID, TenantID: TenantCedar, Location: locations[edgeID], Status: "active", SPIFFEID: spiffeID}
		if err := l.Store.PutEdge(site); err != nil {
			return err
		}
		cert, err := l.Issuer.Leaf(spiffeID, edgeID, now.Add(-time.Hour), now.Add(24*time.Hour))
		if err != nil {
			return err
		}
		l.Certs[spiffeID] = cert
		l.Backends[edgeID] = edge.New(edgeID, TenantCedar, locations[edgeID], l.Public, l.Clock, l.Limits.LowRiskOfflineTTL, l.Limits.HighRiskOfflineTTL)
	}
	for _, ep := range simendpoints.Generate(TenantCedar, EdgeIDs, l.Limits.SimulatedEndpoints) {
		if err := l.Store.PutEndpoint(ep); err != nil {
			return err
		}
	}
	for _, epID := range []string{"SYN-EP-001", "SYN-EP-002"} {
		spiffeID := identity.EndpointSPIFFE(epID)
		cert, err := l.Issuer.Leaf(spiffeID, epID, now.Add(-time.Hour), now.Add(24*time.Hour))
		if err != nil {
			return err
		}
		l.Certs[spiffeID] = cert
	}
	discoveryCert, err := l.Issuer.Leaf(DiscoveryID, "discovery", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		return err
	}
	l.Certs[DiscoveryID] = discoveryCert
	for _, backend := range l.Backends {
		l.refresh(backend)
	}
	return nil
}

func (l *Lab) serveRPC() error {
	serverCert, err := l.Issuer.ServerCertificate(time.Now().UTC())
	if err != nil {
		return err
	}
	rpc := syncgrpc.New(
		l.lookup, l.auditRPC, l.policyList, l.versionList, l.ackDeployment, l.saveEndpoint, l.saveAssets,
		l.Limits.ChunkBytes, l.Limits.MaxBundleBytes,
	)
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(identity.ServerTLS(serverCert, l.Issuer.Pool))),
		grpc.MaxRecvMsgSize(l.Limits.MaxBundleBytes),
		grpc.ChainUnaryInterceptor(rpc.Unary),
		grpc.ChainStreamInterceptor(rpc.Stream),
	)
	policyv1.RegisterPolicySyncServiceServer(srv, rpc)
	endpointv1.RegisterEndpointServiceServer(srv, rpc)
	discoveryv1.RegisterDiscoveryServiceServer(srv, rpc)
	lis := bufconn.Listen(2 << 20)
	l.grpcServer = srv
	l.listener = lis
	go func() { _ = srv.Serve(lis) }()
	return nil
}

func (l *Lab) dial(spiffeID string) (*grpc.ClientConn, error) {
	cert, ok := l.Certs[spiffeID]
	if !ok {
		return nil, apperr.New("unauthenticated", "workload certificate was not issued", 401)
	}
	return grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return l.listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(identity.ClientTLS(cert, l.Issuer.Pool))),
	)
}

func newToken(name string) (string, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return "lab-token-" + name + "-" + hex.EncodeToString(buf), nil
}

func (l *Lab) Token(name string) string {
	return l.Tokens[name]
}

func (l *Lab) Identity(name string) (model.Identity, error) {
	raw := l.Tokens[name]
	id, _, err := l.Store.Authenticate(raw, l.Clock.Now().Unix())
	return id, err
}

func (l *Lab) refresh(backend *edge.Backend) {
	if !l.Store.Available() {
		return
	}
	backend.ReplaceDirectory(edge.Directory{
		Identities: l.Store.Identities(backend.TenantID),
		Tokens:     l.Store.TokensForTenant(backend.TenantID),
		Resources:  l.Store.Resources(backend.TenantID),
	})
	backend.ReplaceGrants(l.Store.Grants(backend.TenantID))
}

func (l *Lab) record(tenant, principal, action, decision, detail string) {
	event := model.AuditEvent{
		TenantID: tenant, Principal: principal, Action: action, Decision: decision,
		Detail: detail, AtUnix: l.Clock.Now().Unix(),
	}
	if decision == "permit" || decision == "grant_permit" {
		l.Telemetry.Decision("allow")
	} else if action == "authorize" {
		l.Telemetry.Decision("deny")
	}
	l.mu.Lock()
	if !l.Store.Available() {
		l.spool = append(l.spool, event)
		l.mu.Unlock()
		return
	}
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
	if _, err := l.Store.AddAudit(event); err != nil {
		l.mu.Lock()
		l.spool = append(l.spool, event)
		l.mu.Unlock()
	}
}

func (l *Lab) SpoolLen() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.spool)
}

func codeOf(err error) string {
	if item, ok := apperr.As(err); ok {
		return item.Code
	}
	return "error"
}

func sortBy[T any](items []T, key func(T) string) {
	sort.Slice(items, func(i, j int) bool { return key(items[i]) < key(items[j]) })
}
