// Package endpoints builds the in-process endpoint inventory.
// These are records, not operating-system processes.
package endpoints

import (
	"fmt"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/identity"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"
)

func Generate(tenant string, edges []string, count int) []model.Endpoint {
	if len(edges) == 0 || count < 1 {
		return nil
	}
	out := make([]model.Endpoint, 0, count)
	for i := 1; i <= count; i++ {
		edgeID := edges[(i-1)%len(edges)]
		id := fmt.Sprintf("SYN-EP-%03d", i)
		out = append(out, model.Endpoint{
			ID:        id,
			EdgeID:    edgeID,
			TenantID:  tenant,
			Connected: true,
			SPIFFEID:  identity.EndpointSPIFFE(id),
		})
	}
	return out
}
