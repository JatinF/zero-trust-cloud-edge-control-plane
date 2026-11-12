package authorization_test

import (
	"testing"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/platform"
)

func BenchmarkLocalAuthorize(b *testing.B) {
	lab, err := platform.NewLab()
	if err != nil {
		b.Fatal(err)
	}
	defer lab.Close()
	ada, err := lab.Identity("ada")
	if err != nil {
		b.Fatal(err)
	}
	if _, err := lab.CreatePolicy(ada, platform.PolicyAccess, "edge", "low"); err != nil {
		b.Fatal(err)
	}
	if _, err := lab.Publish(ada, platform.PolicyAccess, "low", "", "", false); err != nil {
		b.Fatal(err)
	}
	if err := lab.Dispatch(); err != nil {
		b.Fatal(err)
	}
	if err := lab.SyncAll(); err != nil {
		b.Fatal(err)
	}
	token := lab.Token("ada")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision := lab.Authorize(platform.EdgeBranch, token, "read", platform.AppLedger)
		if !decision.Allow {
			b.Fatalf("%+v", decision)
		}
	}
}
