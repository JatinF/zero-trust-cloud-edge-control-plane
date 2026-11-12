package platform

import (
	"runtime"
	"sort"
	"time"
)

type BenchReport struct {
	Go           string  `json:"go"`
	OS           string  `json:"os"`
	Arch         string  `json:"arch"`
	CPUs         int     `json:"cpus"`
	AuthzSamples int     `json:"authz_samples"`
	AuthzP50Us   float64 `json:"authz_p50_us"`
	AuthzP95Us   float64 `json:"authz_p95_us"`
	AuthzMaxUs   float64 `json:"authz_max_us"`
	SyncSamples  int     `json:"sync_samples"`
	SyncP50Ms    float64 `json:"sync_p50_ms"`
	SyncP95Ms    float64 `json:"sync_p95_ms"`
	Endpoints    int     `json:"endpoints"`
	Price        string  `json:"price"`
	Measurement  string  `json:"measurement"`
}

// Bench measures the in-process lab. It is not a multi-node service-level objective.
func (l *Lab) Bench() (BenchReport, error) {
	report := BenchReport{
		Go: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU(),
		Price: "none", Endpoints: l.Limits.SimulatedEndpoints,
		Measurement: "In-process on this workstation. Not a network deployment and not a pass gate.",
	}
	ada, err := l.Identity("ada")
	if err != nil {
		return report, err
	}
	if _, err := l.CreatePolicy(ada, PolicyAccess, "edge", "low"); err != nil {
		return report, err
	}
	if _, err := l.Publish(ada, PolicyAccess, "low", "", "", false); err != nil {
		return report, err
	}
	if err := l.Dispatch(); err != nil {
		return report, err
	}
	if err := l.SyncAll(); err != nil {
		return report, err
	}
	const samples = 2000
	authz := make([]time.Duration, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		decision := l.Authorize(EdgeBranch, l.Token("ada"), "read", AppLedger)
		authz[i] = time.Since(start)
		if !decision.Allow {
			return report, errNotFound()
		}
	}
	sort.Slice(authz, func(i, j int) bool { return authz[i] < authz[j] })
	report.AuthzSamples = samples
	report.AuthzP50Us = us(percentile(authz, 0.50))
	report.AuthzP95Us = us(percentile(authz, 0.95))
	report.AuthzMaxUs = us(authz[len(authz)-1])

	const syncSamples = 8
	syncs := make([]time.Duration, syncSamples)
	for i := 0; i < syncSamples; i++ {
		start := time.Now()
		if _, err := l.Publish(ada, PolicyAccess, "low", "", "", false); err != nil {
			return report, err
		}
		if err := l.Dispatch(); err != nil {
			return report, err
		}
		if err := l.SyncAll(); err != nil {
			return report, err
		}
		syncs[i] = time.Since(start)
	}
	sort.Slice(syncs, func(i, j int) bool { return syncs[i] < syncs[j] })
	report.SyncSamples = syncSamples
	report.SyncP50Ms = ms(percentile(syncs, 0.50))
	report.SyncP95Ms = ms(percentile(syncs, 0.95))
	return report, nil
}

func percentile(samples []time.Duration, p float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	index := int(float64(len(samples)-1) * p)
	return samples[index]
}

func us(d time.Duration) float64 {
	return float64(d.Microseconds())
}

func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}
