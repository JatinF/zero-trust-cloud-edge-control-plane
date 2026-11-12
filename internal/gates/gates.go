// Package gates reports integrations that were not executed.
// A set variable becomes blocked. This process does not dial it.
package gates

type Gate struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type item struct {
	name string
	env  string
	idle string
	busy string
}

var catalog = []item{
	{"postgres", "ZT_POSTGRES_DSN", "ZT_POSTGRES_DSN is unset. PostgreSQL was not started.", "ZT_POSTGRES_DSN is set. This process does not connect."},
	{"nats-jetstream", "ZT_NATS_URL", "ZT_NATS_URL is unset. No JetStream broker was started.", "ZT_NATS_URL is set. This process does not connect."},
	{"redis", "ZT_REDIS_URL", "ZT_REDIS_URL is unset. Redis was not started.", "ZT_REDIS_URL is set. This process does not connect."},
	{"spire", "ZT_SPIRE_SOCKET", "ZT_SPIRE_SOCKET is unset. SPIRE was not started.", "ZT_SPIRE_SOCKET is set. This process does not connect."},
	{"oidc-provider", "ZT_OIDC_ISSUER", "ZT_OIDC_ISSUER is unset. No OIDC provider was contacted.", "ZT_OIDC_ISSUER is set. This process does not connect."},
	{"docker-local", "ZT_DOCKER", "Docker is not installed on this workstation. A local image build was not run.", "ZT_DOCKER is set. This process does not run Docker."},
	{"kubernetes", "ZT_KUBECONFIG", "kubectl is not installed. No manifest was applied.", "ZT_KUBECONFIG is set. This process does not use it."},
	{"terraform-apply", "ZT_TF_APPLY", "The Terraform module was not applied.", "ZT_TF_APPLY is set. This process does not apply Terraform."},
	{"otlp-collector", "ZT_OTLP_ENDPOINT", "ZT_OTLP_ENDPOINT is unset. No collector was contacted.", "ZT_OTLP_ENDPOINT is set. This process does not export spans."},
	{"customer-deployment", "ZT_CUSTOMER", "SYN-TENANT-CEDAR is synthetic. No customer deployment was made.", "ZT_CUSTOMER is set. This process does not deploy."},
}

func Evaluate(env map[string]string) []Gate {
	out := make([]Gate, 0, len(catalog))
	for _, item := range catalog {
		if env[item.env] == "" {
			out = append(out, Gate{Name: item.name, Status: "not-run", Reason: item.idle})
			continue
		}
		out = append(out, Gate{Name: item.name, Status: "blocked", Reason: item.busy})
	}
	return out
}
