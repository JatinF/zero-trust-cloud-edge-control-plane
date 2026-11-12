package zt.authz

default allow := false

allow if {
	input.subject.status == "active"
	input.subject.tenant_id == input.resource.tenant_id
	input.action == "read"
	input.resource.kind == "app"
}
