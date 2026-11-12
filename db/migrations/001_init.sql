-- PostgreSQL schema for the control plane.
-- This file was not applied. PostgreSQL was not started on this workstation.
-- The in-memory store enforces the same tenant scope, unique revision, and outbox rules.

CREATE TABLE tenants (
    tenant_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE identities (
    identity_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
    identity_type TEXT NOT NULL,
    owner TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE INDEX identities_tenant_idx ON identities (tenant_id);

CREATE TABLE resources (
    resource_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
    kind TEXT NOT NULL,
    location TEXT NOT NULL
);

CREATE INDEX resources_tenant_idx ON resources (tenant_id);

CREATE TABLE policies (
    policy_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
    scope TEXT NOT NULL
);

CREATE INDEX policies_tenant_idx ON policies (tenant_id);

CREATE TABLE policy_versions (
    policy_id TEXT NOT NULL REFERENCES policies (policy_id),
    revision BIGINT NOT NULL,
    digest TEXT NOT NULL,
    signature TEXT NOT NULL,
    expiry BIGINT NOT NULL,
    payload BYTEA NOT NULL,
    UNIQUE (policy_id, revision)
);

CREATE TABLE edge_sites (
    edge_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
    location TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE INDEX edge_sites_tenant_idx ON edge_sites (tenant_id);

CREATE TABLE endpoint_agents (
    endpoint_id TEXT PRIMARY KEY,
    edge_id TEXT NOT NULL REFERENCES edge_sites (edge_id),
    active_revision BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE policy_deployments (
    edge_id TEXT NOT NULL REFERENCES edge_sites (edge_id),
    revision BIGINT NOT NULL,
    status TEXT NOT NULL,
    acknowledged_at BIGINT,
    PRIMARY KEY (edge_id, revision)
);

CREATE TABLE discovery_jobs (
    job_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
    connector TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE discovered_assets (
    asset_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    observed_at BIGINT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id)
);

CREATE INDEX discovered_assets_tenant_idx ON discovered_assets (tenant_id);

CREATE TABLE access_requests (
    request_id TEXT PRIMARY KEY,
    requester TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    action TEXT NOT NULL,
    state TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id)
);

CREATE TABLE access_grants (
    grant_id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    expiry BIGINT NOT NULL,
    revoked_at BIGINT,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id)
);

CREATE INDEX access_grants_tenant_idx ON access_grants (tenant_id);

CREATE TABLE audit_events (
    event_id TEXT PRIMARY KEY,
    principal TEXT NOT NULL,
    decision TEXT NOT NULL,
    policy_revision BIGINT NOT NULL DEFAULT 0,
    tenant_id TEXT NOT NULL
);

CREATE INDEX audit_events_tenant_idx ON audit_events (tenant_id, decision);

CREATE TABLE outbox_events (
    event_id TEXT PRIMARY KEY,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    published_at BIGINT,
    payload TEXT NOT NULL
);
