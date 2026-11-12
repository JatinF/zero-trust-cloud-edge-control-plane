// Package edge is the offline-capable authorizer.
// A failed update leaves the previous verified policy in place.
// A disconnected edge cannot observe a cloud revocation until it reconciles.
// Short grant and policy lifetimes bound that window. Revocation is not instant.
package edge

import (
	"context"
	"crypto/ed25519"
	"sync"
	"time"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/authz"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/clock"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/policy"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/storage/memory"
)

type Snapshot struct {
	Payload   []byte
	Signature []byte
	Grants    []model.Grant
	Directory Directory
}

type Directory struct {
	Identities []model.Identity
	Tokens     []model.TokenRecord
	Resources  []model.Resource
}

type Backend struct {
	ID       string
	TenantID string
	Location string
	Pub      ed25519.PublicKey
	Clock    *clock.Clock
	MaxLow   time.Duration
	MaxHigh  time.Duration

	mu              sync.Mutex
	active          *policy.Bundle
	payload         []byte
	signature       []byte
	connected       bool
	grants          []model.Grant
	identities      map[string]model.Identity
	tokens          map[string]model.TokenRecord
	resources       map[string]model.Resource
	rejected        int
	invalidAccepted int
	activations     map[uint64]int
	lastError       string
}

func New(id, tenant, location string, pub ed25519.PublicKey, clk *clock.Clock, maxLow, maxHigh time.Duration) *Backend {
	return &Backend{
		ID:          id,
		TenantID:    tenant,
		Location:    location,
		Pub:         pub,
		Clock:       clk,
		MaxLow:      maxLow,
		MaxHigh:     maxHigh,
		connected:   true,
		identities:  map[string]model.Identity{},
		tokens:      map[string]model.TokenRecord{},
		resources:   map[string]model.Resource{},
		activations: map[uint64]int{},
	}
}

func (b *Backend) SetConnected(connected bool) {
	b.mu.Lock()
	b.connected = connected
	b.mu.Unlock()
}

func (b *Backend) Connected() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.connected
}

func (b *Backend) LastError() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastError
}

func (b *Backend) Rejected() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rejected
}

func (b *Backend) InvalidAccepted() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.invalidAccepted
}

func (b *Backend) ActivationCount(revision uint64) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.activations[revision]
}

func (b *Backend) Active() (policy.Bundle, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active == nil {
		return policy.Bundle{}, false
	}
	return *b.active, true
}

func (b *Backend) ReplaceDirectory(dir Directory) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.identities = map[string]model.Identity{}
	b.tokens = map[string]model.TokenRecord{}
	b.resources = map[string]model.Resource{}
	for _, item := range dir.Identities {
		b.identities[item.ID] = item
	}
	for _, item := range dir.Tokens {
		b.tokens[item.Hash] = item
	}
	for _, item := range dir.Resources {
		b.resources[item.ID] = item
	}
}

func (b *Backend) ReplaceGrants(grants []model.Grant) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.grants = append([]model.Grant(nil), grants...)
}

func (b *Backend) Remember(id model.Identity, token model.TokenRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.identities[id.ID] = id
	b.tokens[token.Hash] = token
}

// Apply verifies a snapshot and swaps it in only after every check succeeds.
// An equal revision and digest is an idempotent duplicate.
// An older revision is rejected, including one marked as a rollback.
func (b *Backend) Apply(payload, signature []byte) error {
	bundle, err := b.check(payload, signature)
	if err != nil {
		b.mu.Lock()
		b.rejected++
		b.lastError = codeOf(err)
		b.mu.Unlock()
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active != nil && bundle.Revision < b.active.Revision {
		b.rejected++
		b.lastError = "revision_replayed"
		return apperr.New("revision_replayed", "older revision was rejected", 409)
	}
	if b.active != nil && bundle.Revision == b.active.Revision {
		if policy.Digest(payload) != policy.Digest(b.payload) {
			b.rejected++
			b.lastError = "digest_mismatch"
			return apperr.New("digest_mismatch", "revision digest changed", 409)
		}
		b.lastError = ""
		return nil
	}
	// Staged bytes become active only after the checks above.
	next := bundle
	b.active = &next
	b.payload = append([]byte(nil), payload...)
	b.signature = append([]byte(nil), signature...)
	b.activations[bundle.Revision]++
	b.lastError = ""
	return nil
}

// StageStoppingBeforeActivate keeps the previous active policy.
func (b *Backend) StageStoppingBeforeActivate(payload, signature []byte) error {
	if _, err := b.check(payload, signature); err != nil {
		return err
	}
	return apperr.New("activation_interrupted", "edge stopped before activation", 503)
}

func (b *Backend) check(payload, signature []byte) (policy.Bundle, error) {
	bundle, err := policy.Verify(b.Pub, payload, signature)
	if err != nil {
		return policy.Bundle{}, err
	}
	if bundle.TenantID != b.TenantID {
		return policy.Bundle{}, apperr.New("tenant_forbidden", "bundle tenant does not match this edge", 403)
	}
	if bundle.Revision == 0 {
		return policy.Bundle{}, apperr.New("policy_format", "revision must be positive", 422)
	}
	if err := policy.Validate(bundle.AccessRego, bundle.PrivilegedRego); err != nil {
		return policy.Bundle{}, err
	}
	window := time.Duration(bundle.NotAfterUnix-bundle.NotBeforeUnix) * time.Second
	max := b.MaxHigh
	if bundle.Risk == "low" {
		max = b.MaxLow
	} else if bundle.Risk != "high" {
		return policy.Bundle{}, apperr.New("policy_format", "risk must be low or high", 422)
	}
	if bundle.NotAfterUnix <= bundle.NotBeforeUnix || window > max {
		return policy.Bundle{}, apperr.New("policy_window", "validity period exceeds the offline bound", 422)
	}
	now := b.Clock.Now().Unix()
	if now < bundle.NotBeforeUnix || now >= bundle.NotAfterUnix {
		return policy.Bundle{}, apperr.New("policy_window", "bundle is outside its validity period", 422)
	}
	return bundle, nil
}

func (b *Backend) Export() Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	snap := Snapshot{
		Payload:   append([]byte(nil), b.payload...),
		Signature: append([]byte(nil), b.signature...),
		Grants:    append([]model.Grant(nil), b.grants...),
	}
	for _, item := range b.identities {
		snap.Directory.Identities = append(snap.Directory.Identities, item)
	}
	for _, item := range b.tokens {
		snap.Directory.Tokens = append(snap.Directory.Tokens, item)
	}
	for _, item := range b.resources {
		snap.Directory.Resources = append(snap.Directory.Resources, item)
	}
	return snap
}

// Recover installs a snapshot only when its signature verifies and it is still valid.
func (b *Backend) Recover(snap Snapshot) error {
	b.ReplaceDirectory(snap.Directory)
	b.ReplaceGrants(snap.Grants)
	if len(snap.Payload) == 0 {
		return nil
	}
	bundle, err := b.check(snap.Payload, snap.Signature)
	if err != nil {
		b.mu.Lock()
		b.active = nil
		b.payload = nil
		b.signature = nil
		b.lastError = codeOf(err)
		b.mu.Unlock()
		return err
	}
	b.mu.Lock()
	next := bundle
	b.active = &next
	b.payload = append([]byte(nil), snap.Payload...)
	b.signature = append([]byte(nil), snap.Signature...)
	b.lastError = ""
	b.mu.Unlock()
	return nil
}

func (b *Backend) Authorize(ctx context.Context, token, action, resourceID string) model.Decision {
	b.mu.Lock()
	active := b.active
	var bundle policy.Bundle
	if active != nil {
		bundle = *active
	}
	now := b.Clock.Now().Unix()
	identity, tokenOK, statusReason := b.localIdentity(token, now)
	resource, resourceOK := b.resources[resourceID]
	grantState, grantAction, grantResource := matchGrant(b.grants, identity.ID, resourceID, action, now)
	b.mu.Unlock()

	decision := model.Decision{Allow: false, Reason: "no_policy"}
	if active == nil {
		return decision
	}
	decision.PolicyID = bundle.PolicyID
	decision.Revision = bundle.Revision
	if now < bundle.NotBeforeUnix || now >= bundle.NotAfterUnix {
		decision.Reason = "policy_expired"
		return decision
	}
	if !tokenOK {
		decision.Reason = statusReason
		return decision
	}
	if !resourceOK || resource.TenantID != b.TenantID {
		decision.Reason = "denied"
		return decision
	}
	if action == authz.PrivilegedAction && grantState == grantExpired {
		decision.Reason = "grant_expired"
		return decision
	}
	if action == authz.PrivilegedAction && grantState == grantRevoked {
		decision.Reason = "grant_revoked"
		return decision
	}
	decided, err := authz.Decide(ctx, bundle.AccessRego, bundle.PrivilegedRego, authz.Request{
		Identity:      identity,
		Action:        action,
		Resource:      resource,
		GrantValid:    grantState == grantValid,
		GrantAction:   grantAction,
		GrantResource: grantResource,
	})
	if err != nil {
		decision.Reason = "policy_format"
		return decision
	}
	decided.PolicyID = bundle.PolicyID
	decided.Revision = bundle.Revision
	return decided
}

func (b *Backend) localIdentity(token string, now int64) (model.Identity, bool, string) {
	rec, ok := b.tokens[memory.HashToken(token)]
	if !ok {
		return model.Identity{}, false, "unauthenticated"
	}
	if now >= rec.ExpiresAtUnix {
		return model.Identity{}, false, "token_expired"
	}
	identity, ok := b.identities[rec.IdentityID]
	if !ok {
		return model.Identity{}, false, "unauthenticated"
	}
	if identity.Status == "inactive" {
		return identity, false, "identity_inactive"
	}
	if identity.Status == "revoked" {
		return identity, false, "identity_revoked"
	}
	if identity.Status != "active" {
		return identity, false, "unauthenticated"
	}
	return identity, true, ""
}

const (
	grantNone    = "none"
	grantValid   = "valid"
	grantExpired = "expired"
	grantRevoked = "revoked"
)

func matchGrant(grants []model.Grant, subject, resource, action string, now int64) (string, string, string) {
	sawRevoked := false
	sawExpired := false
	var sawAction, sawResource string
	for _, grant := range grants {
		if grant.SubjectID != subject || grant.ResourceID != resource || grant.Action != action {
			continue
		}
		sawAction, sawResource = grant.Action, grant.ResourceID
		if grant.RevokedAtUnix > 0 {
			sawRevoked = true
			continue
		}
		if now >= grant.ExpiresAtUnix {
			sawExpired = true
			continue
		}
		return grantValid, grant.Action, grant.ResourceID
	}
	if sawExpired {
		return grantExpired, sawAction, sawResource
	}
	if sawRevoked {
		return grantRevoked, sawAction, sawResource
	}
	return grantNone, sawAction, sawResource
}

func codeOf(err error) string {
	if item, ok := apperr.As(err); ok {
		return item.Code
	}
	return "rejected"
}
