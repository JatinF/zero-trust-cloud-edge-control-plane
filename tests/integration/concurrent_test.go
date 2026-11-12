package integration_test

import (
	"sync"
	"testing"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/platform"
)

func TestConcurrentPublishKeepsUniqueRevisions(t *testing.T) {
	lab, err := platform.NewLab()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lab.Close)
	ada, err := lab.Identity("ada")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lab.CreatePolicy(ada, platform.PolicyAccess, "edge", "low"); err != nil {
		t.Fatal(err)
	}
	const n = 20
	var group sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := lab.Publish(ada, platform.PolicyAccess, "low", "", "", false)
			errs <- err
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	versions, err := lab.Versions(ada, platform.PolicyAccess)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != n {
		t.Fatalf("versions = %d", len(versions))
	}
	seen := map[uint64]bool{}
	for _, version := range versions {
		if seen[version.Revision] {
			t.Fatalf("duplicate revision %d", version.Revision)
		}
		seen[version.Revision] = true
	}
	for revision := uint64(1); revision <= n; revision++ {
		if !seen[revision] {
			t.Fatalf("missing revision %d", revision)
		}
	}
}
