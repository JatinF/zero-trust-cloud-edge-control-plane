package zt.privileged

default allow := false

allow if {
	input.subject.status == "active"
	input.subject.tenant_id == input.resource.tenant_id
	input.action == "admin"
	input.grant_valid == true
	input.grant_action == "admin"
	input.grant_resource_id == input.resource.id
	input.resource.kind == "database"
}
