package platform

const (
	TenantCedar   = "SYN-TENANT-CEDAR"
	TenantBirch   = "SYN-TENANT-BIRCH"
	UserPlatform  = "SYN-USER-PLATFORM"
	UserAda       = "SYN-USER-ADA"
	UserJules     = "SYN-USER-JULES"
	UserKiran     = "SYN-USER-KIRAN"
	UserBirch     = "SYN-USER-BIRCH"
	EdgeHQ        = "SYN-EDGE-HQ"
	EdgeRegion    = "SYN-EDGE-REGION"
	EdgeBranch    = "SYN-EDGE-BRANCH"
	AppLedger     = "SYN-APP-LEDGER"
	DBLedger      = "SYN-DB-LEDGER"
	PolicyAccess  = "SYN-POL-ACCESS"
	RolePlatform  = "platform"
	RoleAdmin     = "policy-admin"
	RoleApprover  = "approver"
	RoleRequester = "requester"
	DiscoveryID   = "spiffe://syn.lab/service/discovery"
)

var EdgeIDs = []string{EdgeHQ, EdgeRegion, EdgeBranch}
