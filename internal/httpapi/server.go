// Package httpapi is the administrative REST API.
// Every /v1 route authenticates the caller. Health is a process probe and returns no tenant data.
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/gates"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/redact"
)

type Core interface {
	Authenticate(raw string) (model.Identity, error)
	CreateTenant(caller model.Identity, id, name string) (model.Tenant, error)
	CreatePolicy(caller model.Identity, id, scope, risk string) (model.Policy, error)
	Publish(caller model.Identity, policyID, risk, accessRego, privilegedRego string, rollback bool) (model.PolicyVersion, error)
	Versions(caller model.Identity, policyID string) ([]model.PolicyVersion, error)
	Edges(caller model.Identity) ([]model.EdgeStatus, error)
	Endpoints(caller model.Identity, edgeID string) ([]model.Endpoint, error)
	StartDiscovery(caller model.Identity, connector string) (model.DiscoveryJob, error)
	Assets(caller model.Identity, kind string) ([]model.Asset, error)
	RequestAccess(caller model.Identity, resourceID, action, reason string) (model.AccessRequest, error)
	Approve(caller model.Identity, requestID string) (model.Grant, error)
	Revoke(caller model.Identity, requestID string) (model.Grant, error)
	Audit(caller model.Identity, decision string) ([]model.AuditEvent, error)
	Gates(caller model.Identity) ([]gates.Gate, error)
}

type route struct {
	Method string
	Path   string
}

var Routes = []route{
	{"POST", "/v1/tenants"},
	{"POST", "/v1/policies"},
	{"POST", "/v1/policies/{id}/publish"},
	{"GET", "/v1/policies/{id}/versions"},
	{"GET", "/v1/edges"},
	{"GET", "/v1/edges/{id}/endpoints"},
	{"POST", "/v1/discovery/jobs"},
	{"GET", "/v1/assets"},
	{"POST", "/v1/access-requests"},
	{"POST", "/v1/access-requests/{id}/approve"},
	{"POST", "/v1/access-requests/{id}/revoke"},
	{"GET", "/v1/audit/events"},
	{"GET", "/v1/gates"},
}

func New(core Core, metrics http.Handler, service string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"service": service, "status": "ok"})
	})
	mux.Handle("GET /metrics", metrics)
	mux.HandleFunc("POST /v1/tenants", func(w http.ResponseWriter, r *http.Request) {
		caller, body, ok := prepare(w, r, core)
		if !ok {
			return
		}
		var input struct {
			TenantID string `json:"tenant_id"`
			Name     string `json:"name"`
		}
		if !decode(w, body, &input) {
			return
		}
		item, err := core.CreateTenant(caller, input.TenantID, input.Name)
		finish(w, item, err)
	})
	mux.HandleFunc("POST /v1/policies", func(w http.ResponseWriter, r *http.Request) {
		caller, body, ok := prepare(w, r, core)
		if !ok {
			return
		}
		var input struct {
			PolicyID string `json:"policy_id"`
			Scope    string `json:"scope"`
			Risk     string `json:"risk"`
		}
		if !decode(w, body, &input) {
			return
		}
		item, err := core.CreatePolicy(caller, input.PolicyID, input.Scope, input.Risk)
		finish(w, item, err)
	})
	mux.HandleFunc("POST /v1/policies/{id}/publish", func(w http.ResponseWriter, r *http.Request) {
		caller, body, ok := prepare(w, r, core)
		if !ok {
			return
		}
		var input struct {
			Risk           string `json:"risk"`
			AccessRego     string `json:"access_rego"`
			PrivilegedRego string `json:"privileged_rego"`
			Rollback       bool   `json:"rollback"`
		}
		if !decode(w, body, &input) {
			return
		}
		item, err := core.Publish(caller, r.PathValue("id"), input.Risk, input.AccessRego, input.PrivilegedRego, input.Rollback)
		finish(w, item, err)
	})
	mux.HandleFunc("GET /v1/policies/{id}/versions", func(w http.ResponseWriter, r *http.Request) {
		caller, _, ok := prepare(w, r, core)
		if !ok {
			return
		}
		item, err := core.Versions(caller, r.PathValue("id"))
		finish(w, item, err)
	})
	mux.HandleFunc("GET /v1/edges", func(w http.ResponseWriter, r *http.Request) {
		caller, _, ok := prepare(w, r, core)
		if !ok {
			return
		}
		item, err := core.Edges(caller)
		finish(w, item, err)
	})
	mux.HandleFunc("GET /v1/edges/{id}/endpoints", func(w http.ResponseWriter, r *http.Request) {
		caller, _, ok := prepare(w, r, core)
		if !ok {
			return
		}
		item, err := core.Endpoints(caller, r.PathValue("id"))
		finish(w, item, err)
	})
	mux.HandleFunc("POST /v1/discovery/jobs", func(w http.ResponseWriter, r *http.Request) {
		caller, body, ok := prepare(w, r, core)
		if !ok {
			return
		}
		var input struct {
			Connector string `json:"connector"`
		}
		if !decode(w, body, &input) {
			return
		}
		item, err := core.StartDiscovery(caller, input.Connector)
		finish(w, item, err)
	})
	mux.HandleFunc("GET /v1/assets", func(w http.ResponseWriter, r *http.Request) {
		caller, _, ok := prepare(w, r, core)
		if !ok {
			return
		}
		item, err := core.Assets(caller, r.URL.Query().Get("type"))
		finish(w, item, err)
	})
	mux.HandleFunc("POST /v1/access-requests", func(w http.ResponseWriter, r *http.Request) {
		caller, body, ok := prepare(w, r, core)
		if !ok {
			return
		}
		var input struct {
			Resource string `json:"resource"`
			Action   string `json:"action"`
			Reason   string `json:"reason"`
		}
		if !decode(w, body, &input) {
			return
		}
		item, err := core.RequestAccess(caller, input.Resource, input.Action, input.Reason)
		finish(w, item, err)
	})
	mux.HandleFunc("POST /v1/access-requests/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		caller, _, ok := prepare(w, r, core)
		if !ok {
			return
		}
		item, err := core.Approve(caller, r.PathValue("id"))
		finish(w, item, err)
	})
	mux.HandleFunc("POST /v1/access-requests/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		caller, _, ok := prepare(w, r, core)
		if !ok {
			return
		}
		item, err := core.Revoke(caller, r.PathValue("id"))
		finish(w, item, err)
	})
	mux.HandleFunc("GET /v1/audit/events", func(w http.ResponseWriter, r *http.Request) {
		caller, _, ok := prepare(w, r, core)
		if !ok {
			return
		}
		item, err := core.Audit(caller, r.URL.Query().Get("decision"))
		finish(w, item, err)
	})
	mux.HandleFunc("GET /v1/gates", func(w http.ResponseWriter, r *http.Request) {
		caller, _, ok := prepare(w, r, core)
		if !ok {
			return
		}
		item, err := core.Gates(caller)
		finish(w, item, err)
	})
	return mux
}

func prepare(w http.ResponseWriter, r *http.Request, core Core) (model.Identity, []byte, bool) {
	raw := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(raw) <= len(prefix) || raw[:len(prefix)] != prefix {
		writeErr(w, apperr.New("unauthenticated", "bearer token is required", http.StatusUnauthorized))
		return model.Identity{}, nil, false
	}
	caller, err := core.Authenticate(raw[len(prefix):])
	if err != nil {
		writeErr(w, err)
		return model.Identity{}, nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeErr(w, apperr.New("policy_format", "request body is too large", http.StatusRequestEntityTooLarge))
		return model.Identity{}, nil, false
	}
	return caller, body, true
}

func decode(w http.ResponseWriter, body []byte, dest any) bool {
	if len(body) == 0 {
		return true
	}
	if err := json.Unmarshal(body, dest); err != nil {
		writeErr(w, apperr.New("policy_format", "request body is not valid JSON", http.StatusUnprocessableEntity))
		return false
	}
	return true
}

func finish(w http.ResponseWriter, payload any, err error) {
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

func writeErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	code := "error"
	message := "request failed"
	if item, ok := apperr.As(err); ok {
		if item.Status != 0 {
			status = item.Status
		}
		code = item.Code
		message = item.Message
	}
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": redact.Secret(message)}})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
