package unit_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/config"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/gates"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/httpapi"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/policy"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/policies"
)

func TestSignedBundleRejectsTamper(t *testing.T) {
	signer, err := policy.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(policy.Bundle{
		TenantID: "SYN-TENANT-CEDAR", PolicyID: "SYN-POL-ACCESS", Revision: 1, Risk: "low",
		NotBeforeUnix: 1, NotAfterUnix: 2, AccessRego: policies.Access, PrivilegedRego: policies.Privileged,
	})
	if err != nil {
		t.Fatal(err)
	}
	again, err := signer.Sign(signed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Digest != again.Digest {
		t.Fatal("canonical digest changed between signs")
	}
	bundle, err := policy.Verify(signer.Public(), signed.Payload, signed.Signature)
	if err != nil || bundle.Revision != 1 {
		t.Fatal(err)
	}
	signed.Payload[20] ^= 0x01
	if _, err := policy.Verify(signer.Public(), signed.Payload, signed.Signature); err == nil {
		t.Fatal("tampered payload verified")
	}
	if _, err := policy.Verify(signer.Public(), again.Payload, nil); err == nil {
		t.Fatal("missing signature verified")
	}
}

func TestRegoDecisions(t *testing.T) {
	allow, priv, err := policy.Eval(context.Background(), policies.Access, policies.Privileged, map[string]any{
		"subject":  map[string]any{"status": "active", "tenant_id": "SYN-TENANT-CEDAR"},
		"action":   "read",
		"resource": map[string]any{"id": "SYN-APP-LEDGER", "tenant_id": "SYN-TENANT-CEDAR", "kind": "app"},
	})
	if err != nil || !allow || priv {
		t.Fatalf("read = %v %v %v", allow, priv, err)
	}
	allow, priv, err = policy.Eval(context.Background(), policies.Access, policies.Privileged, map[string]any{})
	if err != nil || allow || priv {
		t.Fatalf("empty input = %v %v %v", allow, priv, err)
	}
	if err := policy.Validate("package zt.authz\ndefault allow := true\n", policies.Privileged); err == nil {
		t.Fatal("default allow was accepted")
	}
}

func TestConfigLimits(t *testing.T) {
	_, limits, err := config.Load(filepath.Join(root(t), "configs", "cloud.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if limits.GrantTTL.Minutes() != 5 || limits.LowRiskOfflineTTL.Minutes() != 30 || limits.SimulatedEndpoints != 300 {
		t.Fatalf("limits = %+v", limits)
	}
}

func TestMigrationDeclaresIsolation(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(root(t), "db", "migrations", "001_init.sql"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, table := range []string{
		"tenants", "identities", "resources", "policies", "policy_versions", "edge_sites",
		"endpoint_agents", "policy_deployments", "discovery_jobs", "discovered_assets",
		"access_requests", "access_grants", "audit_events", "outbox_events",
	} {
		if !strings.Contains(text, "CREATE TABLE "+table) {
			t.Fatalf("migration missing %s", table)
		}
	}
	if !strings.Contains(text, "UNIQUE (policy_id, revision)") || !strings.Contains(text, "tenant_id") {
		t.Fatal("migration is missing the revision constraint or tenant column")
	}
}

func TestOpenAPICoversRoutes(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(root(t), "docs", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, route := range httpapi.Routes {
		if !strings.Contains(text, route.Path) && !strings.Contains(text, strings.ReplaceAll(route.Path, "{id}", "{id}")) {
			t.Fatalf("openapi missing %s %s", route.Method, route.Path)
		}
		needle := strings.ReplaceAll(route.Path, "{id}", "{id}")
		if !strings.Contains(text, needle) {
			t.Fatalf("openapi missing %s", needle)
		}
	}
}

func TestGateDoesNotEchoSecret(t *testing.T) {
	secret := "postgres://synthetic-secret-value@localhost/db"
	items := gates.Evaluate(map[string]string{"ZT_POSTGRES_DSN": secret})
	for _, item := range items {
		if strings.Contains(item.Reason, "synthetic-secret-value") {
			t.Fatal(item.Reason)
		}
		if item.Name == "postgres" && item.Status != "blocked" {
			t.Fatalf("postgres gate = %+v", item)
		}
	}
}

func root(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("module root was not found")
		}
		dir = parent
	}
}
