package zt.authz_test

import data.zt.authz
import data.zt.privileged

test_read_same_tenant if {
	authz.allow with input as {
		"subject": {"status": "active", "tenant_id": "SYN-TENANT-CEDAR"},
		"action": "read",
		"resource": {"tenant_id": "SYN-TENANT-CEDAR", "kind": "app", "id": "SYN-APP-LEDGER"},
	}
}

test_default_deny if {
	not authz.allow with input as {}
}

test_cross_tenant_deny if {
	not authz.allow with input as {
		"subject": {"status": "active", "tenant_id": "SYN-TENANT-BIRCH"},
		"action": "read",
		"resource": {"tenant_id": "SYN-TENANT-CEDAR", "kind": "app", "id": "SYN-APP-LEDGER"},
	}
}

test_admin_without_grant_deny if {
	not privileged.allow with input as {
		"subject": {"status": "active", "tenant_id": "SYN-TENANT-CEDAR"},
		"action": "admin",
		"resource": {"tenant_id": "SYN-TENANT-CEDAR", "kind": "database", "id": "SYN-DB-LEDGER"},
		"grant_valid": false,
	}
}

test_admin_with_grant if {
	privileged.allow with input as {
		"subject": {"status": "active", "tenant_id": "SYN-TENANT-CEDAR"},
		"action": "admin",
		"resource": {"tenant_id": "SYN-TENANT-CEDAR", "kind": "database", "id": "SYN-DB-LEDGER"},
		"grant_valid": true,
		"grant_action": "admin",
		"grant_resource_id": "SYN-DB-LEDGER",
	}
}
