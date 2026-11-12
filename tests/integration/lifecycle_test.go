package integration_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/platform"
)

func TestDemoLifecycle(t *testing.T) {
	lab := newLab(t)
	report, err := lab.Demo()
	if err != nil {
		t.Fatal(err)
	}
	if report.Revision != 2 || report.Edges != 3 || report.EndpointAcks != 300 {
		t.Fatalf("sync report = %+v", report)
	}
	if report.Read != "permit" || report.CrossTenant != "not_found" {
		t.Fatalf("access report = %+v", report)
	}
	if report.Tampered != "signature_invalid" || report.Replay != "revision_replayed" {
		t.Fatalf("bundle report = %+v", report)
	}
	if report.UnauthorizedGrants != 0 || report.InvalidBundlesAccepted != 0 || report.RejectedUpdates < 2 {
		t.Fatalf("invariant report = %+v", report)
	}
	if report.SelfApproval != "self_approval" || report.GrantTTLSeconds != 300 {
		t.Fatalf("grant issue report = %+v", report)
	}
	if report.PrivilegedBeforeExpiry != "grant_permit" || report.PrivilegedAfterExpiry != "grant_expired" {
		t.Fatalf("grant lifetime report = %+v", report)
	}
	if report.RevokeWhilePartition != "grant_permit" || report.RevokeAfterReconnect != "grant_revoked" {
		t.Fatalf("partition report = %+v", report)
	}
	if report.OfflineRead != "permit" || report.ExpiredOffline != "policy_expired" || report.AuditMissing != 0 {
		t.Fatalf("offline report = %+v", report)
	}
	if report.Price != "none" {
		t.Fatalf("price = %s", report.Price)
	}
	if lab.Chunks() < 2 {
		t.Fatalf("bundle chunks = %d, want multiple chunks", lab.Chunks())
	}
	names := lab.Telemetry.SpanNames()
	if len(names) == 0 {
		t.Fatal("publish did not record a span")
	}
}

func TestHTTPPublishAndGates(t *testing.T) {
	lab := newLab(t)
	status, body := do(lab, "", http.MethodPost, "/v1/policies", map[string]string{"policy_id": "SYN-POL-HTTP"})
	if status != http.StatusUnauthorized {
		t.Fatalf("status %d body %s", status, body)
	}
	status, body = do(lab, lab.Token("ada"), http.MethodPost, "/v1/policies", map[string]string{
		"policy_id": "SYN-POL-HTTP", "scope": "edge", "risk": "low",
	})
	if status != http.StatusOK {
		t.Fatalf("create status %d body %s", status, body)
	}
	status, body = do(lab, lab.Token("ada"), http.MethodPost, "/v1/policies/SYN-POL-HTTP/publish", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("publish status %d body %s", status, body)
	}
	status, body = do(lab, lab.Token("ada"), http.MethodGet, "/v1/policies/SYN-POL-HTTP/versions", nil)
	if status != http.StatusOK || !bytes.Contains([]byte(body), []byte(`"revision":1`)) {
		t.Fatalf("versions status %d body %s", status, body)
	}
	if bytes.Contains([]byte(body), []byte(lab.Token("ada"))) {
		t.Fatal("response contains a bearer token")
	}
	lab.SetEnv("ZT_POSTGRES_DSN", "postgres://synthetic-secret@localhost/db")
	status, body = do(lab, lab.Token("ada"), http.MethodGet, "/v1/gates", nil)
	if status != http.StatusOK || bytes.Contains([]byte(body), []byte("synthetic-secret")) {
		t.Fatalf("gates leaked a DSN: %s", body)
	}
	if !bytes.Contains([]byte(body), []byte(`"status":"blocked"`)) {
		t.Fatalf("gates body = %s", body)
	}
}

func newLab(t *testing.T) *platform.Lab {
	t.Helper()
	lab, err := platform.NewLab()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lab.Close)
	return lab
}

func do(lab *platform.Lab, token, method, path string, payload any) (int, string) {
	var reader io.Reader
	if payload != nil {
		raw, _ := json.Marshal(payload)
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	lab.Handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}
