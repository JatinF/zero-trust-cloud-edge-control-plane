// Package model holds the control-plane records.
// Tenant isolation is a property of every read, not only of the HTTP layer.
package model

type Tenant struct {
	ID     string `json:"tenant_id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type Identity struct {
	ID       string   `json:"identity_id"`
	TenantID string   `json:"tenant_id"`
	Type     string   `json:"type"`
	Owner    string   `json:"owner"`
	Status   string   `json:"status"`
	Roles    []string `json:"roles"`
	SPIFFEID string   `json:"spiffe_id,omitempty"`
}

type TokenRecord struct {
	Hash          string `json:"-"`
	IdentityID    string `json:"identity_id"`
	ExpiresAtUnix int64  `json:"expires_at"`
}

type Resource struct {
	ID       string `json:"resource_id"`
	TenantID string `json:"tenant_id"`
	Kind     string `json:"kind"`
	Location string `json:"location"`
}

type Policy struct {
	ID       string `json:"policy_id"`
	TenantID string `json:"tenant_id"`
	Scope    string `json:"scope"`
	Risk     string `json:"risk"`
}

type PolicyVersion struct {
	PolicyID       string `json:"policy_id"`
	TenantID       string `json:"tenant_id"`
	Revision       uint64 `json:"revision"`
	Digest         string `json:"digest"`
	Signature      string `json:"signature"`
	Risk           string `json:"risk"`
	NotBeforeUnix  int64  `json:"not_before_unix"`
	NotAfterUnix   int64  `json:"not_after_unix"`
	Rollback       bool   `json:"rollback"`
	Payload        []byte `json:"-"`
	SignatureBytes []byte `json:"-"`
}

type EdgeSite struct {
	ID       string `json:"edge_id"`
	TenantID string `json:"tenant_id"`
	Location string `json:"location"`
	Status   string `json:"status"`
	SPIFFEID string `json:"spiffe_id"`
}

type Endpoint struct {
	ID             string `json:"endpoint_id"`
	EdgeID         string `json:"edge_id"`
	TenantID       string `json:"tenant_id"`
	ActiveRevision uint64 `json:"active_revision"`
	ActiveDigest   string `json:"active_digest"`
	Connected      bool   `json:"connected"`
	SPIFFEID       string `json:"spiffe_id,omitempty"`
}

type Deployment struct {
	EdgeID      string `json:"edge_id"`
	PolicyID    string `json:"policy_id"`
	Revision    uint64 `json:"revision"`
	Status      string `json:"status"`
	Digest      string `json:"digest"`
	AckedAtUnix int64  `json:"acknowledged_at"`
}

type DiscoveryJob struct {
	ID        string `json:"job_id"`
	TenantID  string `json:"tenant_id"`
	Connector string `json:"connector"`
	Status    string `json:"status"`
}

type Asset struct {
	ID             string `json:"asset_id"`
	TenantID       string `json:"tenant_id"`
	Source         string `json:"source"`
	Type           string `json:"type"`
	ObservedAtUnix int64  `json:"observed_at"`
}

type AccessRequest struct {
	ID          string `json:"request_id"`
	TenantID    string `json:"tenant_id"`
	RequesterID string `json:"requester"`
	ResourceID  string `json:"resource"`
	Action      string `json:"action"`
	State       string `json:"state"`
	Reason      string `json:"reason"`
}

type Grant struct {
	ID            string `json:"grant_id"`
	TenantID      string `json:"tenant_id"`
	RequestID     string `json:"request_id"`
	SubjectID     string `json:"subject_id"`
	ResourceID    string `json:"resource_id"`
	Action        string `json:"action"`
	Scope         string `json:"scope"`
	ExpiresAtUnix int64  `json:"expiry"`
	RevokedAtUnix int64  `json:"revoked_at"`
}

type AuditEvent struct {
	ID        string `json:"event_id"`
	TenantID  string `json:"tenant_id"`
	Principal string `json:"principal"`
	Action    string `json:"action"`
	Decision  string `json:"decision"`
	PolicyID  string `json:"policy_id,omitempty"`
	Revision  uint64 `json:"policy_revision"`
	Detail    string `json:"detail,omitempty"`
	AtUnix    int64  `json:"at_unix"`
}

type OutboxEvent struct {
	ID              string `json:"event_id"`
	AggregateID     string `json:"aggregate_id"`
	Type            string `json:"event_type"`
	Payload         string `json:"payload"`
	PublishedAtUnix int64  `json:"published_at"`
}

type EdgeStatus struct {
	EdgeID           string `json:"edge_id"`
	Location         string `json:"location"`
	ActiveRevision   uint64 `json:"active_revision"`
	DesiredRevision  uint64 `json:"desired_revision"`
	Lag              uint64 `json:"lag"`
	SyncStatus       string `json:"sync_status"`
	Connected        bool   `json:"connected"`
	LastError        string `json:"last_error,omitempty"`
	DeploymentStatus string `json:"deployment_status"`
}

type Decision struct {
	Allow    bool   `json:"allow"`
	Reason   string `json:"reason"`
	Revision uint64 `json:"policy_revision"`
	PolicyID string `json:"policy_id,omitempty"`
}

func HasRole(id Identity, role string) bool {
	for _, item := range id.Roles {
		if item == role {
			return true
		}
	}
	return false
}
