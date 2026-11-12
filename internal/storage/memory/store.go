// Package memory is the tested store.
// It enforces tenant scope, monotonic revisions, and a transactional outbox.
// The PostgreSQL migrations describe the same constraints and were not applied.
package memory

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"sync"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/clock"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/redact"
)

type state struct {
	tenants     map[string]model.Tenant
	identities  map[string]model.Identity
	tokens      map[string]model.TokenRecord
	resources   map[string]model.Resource
	policies    map[string]model.Policy
	versions    map[string][]model.PolicyVersion
	edges       map[string]model.EdgeSite
	endpoints   map[string]model.Endpoint
	deployments []model.Deployment
	jobs        map[string]model.DiscoveryJob
	assets      map[string]model.Asset
	requests    map[string]model.AccessRequest
	grants      map[string]model.Grant
	audit       []model.AuditEvent
	outbox      []model.OutboxEvent
	seq         int
}

type Store struct {
	mu    sync.Mutex
	down  bool
	clock *clock.Clock
	st    state
}

func New(clk *clock.Clock) *Store {
	return &Store{
		clock: clk,
		st: state{
			tenants:    map[string]model.Tenant{},
			identities: map[string]model.Identity{},
			tokens:     map[string]model.TokenRecord{},
			resources:  map[string]model.Resource{},
			policies:   map[string]model.Policy{},
			versions:   map[string][]model.PolicyVersion{},
			edges:      map[string]model.EdgeSite{},
			endpoints:  map[string]model.Endpoint{},
			jobs:       map[string]model.DiscoveryJob{},
			assets:     map[string]model.Asset{},
			requests:   map[string]model.AccessRequest{},
			grants:     map[string]model.Grant{},
		},
	}
}

func (s *Store) SetDown(down bool) {
	s.mu.Lock()
	s.down = down
	s.mu.Unlock()
}

func (s *Store) Available() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.down
}

func (s *Store) commit(fn func(*state) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return apperr.New("dependency_unavailable", "store is unavailable", 503)
	}
	draft := s.st.clone()
	if err := fn(&draft); err != nil {
		return err
	}
	s.st = draft
	return nil
}

func (s state) clone() state {
	out := s
	out.tenants = maps.Clone(s.tenants)
	out.identities = maps.Clone(s.identities)
	out.tokens = maps.Clone(s.tokens)
	out.resources = maps.Clone(s.resources)
	out.policies = maps.Clone(s.policies)
	out.edges = maps.Clone(s.edges)
	out.endpoints = maps.Clone(s.endpoints)
	out.jobs = maps.Clone(s.jobs)
	out.assets = maps.Clone(s.assets)
	out.requests = maps.Clone(s.requests)
	out.grants = maps.Clone(s.grants)
	out.versions = make(map[string][]model.PolicyVersion, len(s.versions))
	for key, value := range s.versions {
		out.versions[key] = append([]model.PolicyVersion(nil), value...)
	}
	out.deployments = append([]model.Deployment(nil), s.deployments...)
	out.audit = append([]model.AuditEvent(nil), s.audit...)
	out.outbox = append([]model.OutboxEvent(nil), s.outbox...)
	return out
}

func (st *state) next(prefix string) string {
	st.seq++
	return prefix + "-" + pad(st.seq)
}

func pad(n int) string {
	digits := []byte("0000")
	raw := []byte{}
	if n == 0 {
		raw = []byte{'0'}
	}
	for value := n; value > 0; value /= 10 {
		raw = append([]byte{byte('0' + value%10)}, raw...)
	}
	if len(raw) >= len(digits) {
		return string(raw)
	}
	copy(digits[len(digits)-len(raw):], raw)
	return string(digits)
}

func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Store) PutTenant(t model.Tenant) error {
	return s.commit(func(st *state) error {
		if _, ok := st.tenants[t.ID]; ok {
			return apperr.New("conflict", "tenant already exists", 409)
		}
		st.tenants[t.ID] = t
		return nil
	})
}

func (s *Store) PutIdentity(id model.Identity) error {
	return s.commit(func(st *state) error {
		st.identities[id.ID] = id
		return nil
	})
}

func (s *Store) PutToken(raw string, rec model.TokenRecord) error {
	rec.Hash = HashToken(raw)
	return s.commit(func(st *state) error {
		st.tokens[rec.Hash] = rec
		return nil
	})
}

func (s *Store) PutResource(r model.Resource) error {
	return s.commit(func(st *state) error {
		st.resources[r.ID] = r
		return nil
	})
}

func (s *Store) PutEdge(edge model.EdgeSite) error {
	return s.commit(func(st *state) error {
		st.edges[edge.ID] = edge
		return nil
	})
}

func (s *Store) PutEndpoint(ep model.Endpoint) error {
	return s.commit(func(st *state) error {
		st.endpoints[ep.ID] = ep
		return nil
	})
}

func (s *Store) CreatePolicy(p model.Policy) error {
	return s.commit(func(st *state) error {
		if _, ok := st.tenants[p.TenantID]; !ok {
			return apperr.New("not_found", "tenant was not found", 404)
		}
		if existing, ok := st.policies[p.ID]; ok {
			if existing.TenantID != p.TenantID {
				return apperr.New("not_found", "policy was not found", 404)
			}
			return apperr.New("conflict", "policy already exists", 409)
		}
		st.policies[p.ID] = p
		return nil
	})
}

// AddVersion stores one immutable revision and its outbox row together.
func (s *Store) AddVersion(v model.PolicyVersion, eventType, payload string) (model.OutboxEvent, error) {
	var event model.OutboxEvent
	err := s.commit(func(st *state) error {
		policy, ok := st.policies[v.PolicyID]
		if !ok || policy.TenantID != v.TenantID {
			return apperr.New("not_found", "policy was not found", 404)
		}
		current := st.versions[v.PolicyID]
		if len(current) == 0 && v.Revision != 1 {
			return apperr.New("conflict", "first revision must be 1", 409)
		}
		if len(current) > 0 && v.Revision != current[len(current)-1].Revision+1 {
			return apperr.New("conflict", "revision is not the next immutable version", 409)
		}
		for _, existing := range current {
			if existing.Revision == v.Revision {
				return apperr.New("revision_replayed", "revision already exists", 409)
			}
		}
		st.versions[v.PolicyID] = append(current, v)
		event = model.OutboxEvent{
			ID:          st.next("obx"),
			AggregateID: v.PolicyID,
			Type:        eventType,
			Payload:     payload,
		}
		st.outbox = append(st.outbox, event)
		for _, edge := range st.edges {
			if edge.TenantID != v.TenantID {
				continue
			}
			st.deployments = append(st.deployments, model.Deployment{
				EdgeID:   edge.ID,
				PolicyID: v.PolicyID,
				Revision: v.Revision,
				Status:   "pending",
				Digest:   v.Digest,
			})
		}
		return nil
	})
	return event, err
}

func (s *Store) MarkPublished(eventID string, at int64) error {
	return s.commit(func(st *state) error {
		for i := range st.outbox {
			if st.outbox[i].ID == eventID {
				st.outbox[i].PublishedAtUnix = at
				return nil
			}
		}
		return apperr.New("not_found", "outbox event was not found", 404)
	})
}

func (s *Store) Unpublished() ([]model.OutboxEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return nil, apperr.New("dependency_unavailable", "store is unavailable", 503)
	}
	var out []model.OutboxEvent
	for _, event := range s.st.outbox {
		if event.PublishedAtUnix == 0 {
			out = append(out, event)
		}
	}
	return out, nil
}

func (s *Store) AckDeployment(edgeID, policyID string, revision uint64, digest string, at int64) error {
	return s.commit(func(st *state) error {
		found := false
		for i := range st.deployments {
			item := &st.deployments[i]
			if item.EdgeID != edgeID || item.PolicyID != policyID || item.Revision != revision {
				continue
			}
			if item.Digest != digest {
				return apperr.New("digest_mismatch", "activated digest does not match the committed revision", 409)
			}
			found = true
			if item.Status != "acknowledged" {
				item.Status = "acknowledged"
				item.AckedAtUnix = at
			}
		}
		if !found {
			return apperr.New("not_found", "deployment was not found", 404)
		}
		for i := range st.deployments {
			item := &st.deployments[i]
			if item.EdgeID == edgeID && item.PolicyID == policyID && item.Revision < revision && item.Status == "pending" {
				item.Status = "superseded"
			}
		}
		return nil
	})
}

func (s *Store) UpdateEndpoint(id string, revision uint64, digest string, connected bool) error {
	return s.commit(func(st *state) error {
		ep, ok := st.endpoints[id]
		if !ok {
			return apperr.New("not_found", "endpoint was not found", 404)
		}
		ep.ActiveRevision = revision
		ep.ActiveDigest = digest
		ep.Connected = connected
		st.endpoints[id] = ep
		return nil
	})
}

func (s *Store) AddAudit(event model.AuditEvent) (model.AuditEvent, error) {
	event.Detail = redact.Secret(event.Detail)
	err := s.commit(func(st *state) error {
		event.ID = st.next("aud")
		if event.AtUnix == 0 && s.clock != nil {
			event.AtUnix = s.clock.Now().Unix()
		}
		st.audit = append(st.audit, event)
		return nil
	})
	return event, err
}

func (s *Store) Authenticate(raw string, nowUnix int64) (model.Identity, model.TokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return model.Identity{}, model.TokenRecord{}, apperr.New("dependency_unavailable", "store is unavailable", 503)
	}
	rec, ok := s.st.tokens[HashToken(raw)]
	if !ok {
		return model.Identity{}, model.TokenRecord{}, apperr.New("unauthenticated", "token was not recognized", 401)
	}
	if nowUnix >= rec.ExpiresAtUnix {
		return model.Identity{}, model.TokenRecord{}, apperr.New("token_expired", "token is expired", 401)
	}
	id, ok := s.st.identities[rec.IdentityID]
	if !ok {
		return model.Identity{}, model.TokenRecord{}, apperr.New("unauthenticated", "identity was not found", 401)
	}
	if id.Status == "inactive" {
		return id, rec, apperr.New("identity_inactive", "identity is inactive", 403)
	}
	if id.Status == "revoked" {
		return id, rec, apperr.New("identity_revoked", "identity is revoked", 403)
	}
	if id.Status != "active" {
		return id, rec, apperr.New("unauthenticated", "identity is not active", 401)
	}
	return id, rec, nil
}

func (s *Store) Policy(tenant, id string) (model.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return model.Policy{}, apperr.New("dependency_unavailable", "store is unavailable", 503)
	}
	item, ok := s.st.policies[id]
	if !ok || item.TenantID != tenant {
		return model.Policy{}, apperr.New("not_found", "policy was not found", 404)
	}
	return item, nil
}

func (s *Store) Versions(tenant, policyID string) ([]model.PolicyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return nil, apperr.New("dependency_unavailable", "store is unavailable", 503)
	}
	item, ok := s.st.policies[policyID]
	if !ok || item.TenantID != tenant {
		return nil, apperr.New("not_found", "policy was not found", 404)
	}
	return append([]model.PolicyVersion(nil), s.st.versions[policyID]...), nil
}

func (s *Store) Version(tenant, policyID string, revision uint64) (model.PolicyVersion, error) {
	versions, err := s.Versions(tenant, policyID)
	if err != nil {
		return model.PolicyVersion{}, err
	}
	for _, item := range versions {
		if item.Revision == revision {
			return item, nil
		}
	}
	return model.PolicyVersion{}, apperr.New("not_found", "revision was not found", 404)
}

func (s *Store) LatestRevision(tenant, policyID string) (uint64, error) {
	versions, err := s.Versions(tenant, policyID)
	if err != nil {
		return 0, err
	}
	if len(versions) == 0 {
		return 0, nil
	}
	return versions[len(versions)-1].Revision, nil
}

func (s *Store) Edges(tenant string) ([]model.EdgeSite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return nil, apperr.New("dependency_unavailable", "store is unavailable", 503)
	}
	var out []model.EdgeSite
	for _, edge := range s.st.edges {
		if edge.TenantID == tenant {
			out = append(out, edge)
		}
	}
	return out, nil
}

func (s *Store) EdgeBySPIFFE(spiffeID string) (model.EdgeSite, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, edge := range s.st.edges {
		if edge.SPIFFEID == spiffeID {
			return edge, true
		}
	}
	return model.EdgeSite{}, false
}

func (s *Store) Endpoints(tenant, edgeID string) ([]model.Endpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return nil, apperr.New("dependency_unavailable", "store is unavailable", 503)
	}
	edge, ok := s.st.edges[edgeID]
	if !ok || edge.TenantID != tenant {
		return nil, apperr.New("not_found", "edge was not found", 404)
	}
	var out []model.Endpoint
	for _, ep := range s.st.endpoints {
		if ep.TenantID == tenant && ep.EdgeID == edgeID {
			out = append(out, ep)
		}
	}
	return out, nil
}

func (s *Store) Endpoint(id string) (model.Endpoint, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ep, ok := s.st.endpoints[id]
	return ep, ok
}

func (s *Store) Identity(id string) (model.Identity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.st.identities[id]
	return item, ok
}

func (s *Store) SetIdentityStatus(id, status string) error {
	return s.commit(func(st *state) error {
		item, ok := st.identities[id]
		if !ok {
			return apperr.New("not_found", "identity was not found", 404)
		}
		item.Status = status
		st.identities[id] = item
		return nil
	})
}

func (s *Store) Resource(tenant, id string) (model.Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return model.Resource{}, apperr.New("dependency_unavailable", "store is unavailable", 503)
	}
	item, ok := s.st.resources[id]
	if !ok || item.TenantID != tenant {
		return model.Resource{}, apperr.New("not_found", "resource was not found", 404)
	}
	return item, nil
}

func (s *Store) Resources(tenant string) []model.Resource {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.Resource
	for _, item := range s.st.resources {
		if item.TenantID == tenant {
			out = append(out, item)
		}
	}
	return out
}

func (s *Store) Identities(tenant string) []model.Identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.Identity
	for _, item := range s.st.identities {
		if item.TenantID == tenant {
			out = append(out, item)
		}
	}
	return out
}

func (s *Store) TokensForTenant(tenant string) []model.TokenRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.TokenRecord
	for _, token := range s.st.tokens {
		id, ok := s.st.identities[token.IdentityID]
		if ok && id.TenantID == tenant {
			out = append(out, token)
		}
	}
	return out
}

func (s *Store) Deployments(edgeID string) []model.Deployment {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.Deployment
	for _, item := range s.st.deployments {
		if item.EdgeID == edgeID {
			out = append(out, item)
		}
	}
	return out
}

func (s *Store) AddJob(job model.DiscoveryJob) (model.DiscoveryJob, error) {
	err := s.commit(func(st *state) error {
		job.ID = st.next("job")
		st.jobs[job.ID] = job
		return nil
	})
	return job, err
}

func (s *Store) FinishJob(id, status string) error {
	return s.commit(func(st *state) error {
		job, ok := st.jobs[id]
		if !ok {
			return apperr.New("not_found", "job was not found", 404)
		}
		job.Status = status
		st.jobs[id] = job
		return nil
	})
}

func (s *Store) AddAssets(items []model.Asset) error {
	return s.commit(func(st *state) error {
		for _, item := range items {
			st.assets[item.ID] = item
		}
		return nil
	})
}

func (s *Store) Assets(tenant, kind string) ([]model.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return nil, apperr.New("dependency_unavailable", "store is unavailable", 503)
	}
	var out []model.Asset
	for _, item := range s.st.assets {
		if item.TenantID != tenant {
			continue
		}
		if kind != "" && item.Type != kind {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

func (s *Store) AddRequest(req model.AccessRequest) (model.AccessRequest, error) {
	req.Reason = redact.Secret(req.Reason)
	err := s.commit(func(st *state) error {
		req.ID = st.next("req")
		st.requests[req.ID] = req
		return nil
	})
	return req, err
}

func (s *Store) Request(tenant, id string) (model.AccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return model.AccessRequest{}, apperr.New("dependency_unavailable", "store is unavailable", 503)
	}
	item, ok := s.st.requests[id]
	if !ok || item.TenantID != tenant {
		return model.AccessRequest{}, apperr.New("not_found", "request was not found", 404)
	}
	return item, nil
}

func (s *Store) AddGrant(grant model.Grant, requestState string) (model.Grant, error) {
	err := s.commit(func(st *state) error {
		req, ok := st.requests[grant.RequestID]
		if !ok || req.TenantID != grant.TenantID {
			return apperr.New("not_found", "request was not found", 404)
		}
		grant.ID = st.next("grn")
		req.State = requestState
		st.requests[req.ID] = req
		st.grants[grant.ID] = grant
		return nil
	})
	return grant, err
}

func (s *Store) RevokeGrant(tenant, requestID string, at int64) (model.Grant, error) {
	var updated model.Grant
	err := s.commit(func(st *state) error {
		req, ok := st.requests[requestID]
		if !ok || req.TenantID != tenant {
			return apperr.New("not_found", "request was not found", 404)
		}
		req.State = "revoked"
		st.requests[requestID] = req
		found := false
		for id, grant := range st.grants {
			if grant.RequestID == requestID && grant.TenantID == tenant {
				grant.RevokedAtUnix = at
				st.grants[id] = grant
				updated = grant
				found = true
			}
		}
		if !found {
			return apperr.New("not_found", "grant was not found", 404)
		}
		return nil
	})
	return updated, err
}

func (s *Store) Grants(tenant string) []model.Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.Grant
	for _, grant := range s.st.grants {
		if grant.TenantID == tenant {
			out = append(out, grant)
		}
	}
	return out
}

func (s *Store) Audit(tenant, decision string) ([]model.AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return nil, apperr.New("dependency_unavailable", "store is unavailable", 503)
	}
	var out []model.AuditEvent
	for _, event := range s.st.audit {
		if event.TenantID != tenant {
			continue
		}
		if decision != "" && event.Decision != decision {
			continue
		}
		out = append(out, event)
	}
	return out, nil
}

func (s *Store) GrantCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.st.grants)
}

func (s *Store) Policies(tenant string) ([]model.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return nil, apperr.New("dependency_unavailable", "store is unavailable", 503)
	}
	var out []model.Policy
	for _, item := range s.st.policies {
		if item.TenantID == tenant {
			out = append(out, item)
		}
	}
	return out, nil
}

func (s *Store) PolicyAny(id string) (model.Policy, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.st.policies[id]
	return item, ok
}

func (s *Store) EndpointBySPIFFE(spiffeID string) (model.Endpoint, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ep := range s.st.endpoints {
		if ep.SPIFFEID == spiffeID {
			return ep, true
		}
	}
	return model.Endpoint{}, false
}

func (s *Store) SetEdgeStatus(id, status string) error {
	return s.commit(func(st *state) error {
		edge, ok := st.edges[id]
		if !ok {
			return apperr.New("not_found", "edge was not found", 404)
		}
		edge.Status = status
		st.edges[id] = edge
		return nil
	})
}

func (s *Store) Job(id string) (model.DiscoveryJob, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.st.jobs[id]
	return job, ok
}
