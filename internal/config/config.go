package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type File struct {
	Service            string `yaml:"service"`
	TenantID           string `yaml:"tenant_id"`
	EdgeID             string `yaml:"edge_id"`
	Location           string `yaml:"location"`
	GrantTTL           string `yaml:"grant_ttl"`
	LowRiskOfflineTTL  string `yaml:"low_risk_offline_ttl"`
	HighRiskOfflineTTL string `yaml:"high_risk_offline_ttl"`
	ChunkBytes         int    `yaml:"chunk_bytes"`
	MaxBundleBytes     int    `yaml:"max_bundle_bytes"`
	WorkerPool         int    `yaml:"worker_pool"`
	SimulatedEndpoints int    `yaml:"simulated_endpoints"`
}

type Limits struct {
	GrantTTL           time.Duration
	LowRiskOfflineTTL  time.Duration
	HighRiskOfflineTTL time.Duration
	ChunkBytes         int
	MaxBundleBytes     int
	WorkerPool         int
	SimulatedEndpoints int
}

func Load(path string) (File, Limits, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return File{}, Limits{}, err
	}
	var file File
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return File{}, Limits{}, err
	}
	limits, err := file.Limits()
	if err != nil {
		return File{}, Limits{}, err
	}
	return file, limits, nil
}

func (f File) Limits() (Limits, error) {
	grant, err := time.ParseDuration(f.GrantTTL)
	if err != nil {
		return Limits{}, err
	}
	low, err := time.ParseDuration(f.LowRiskOfflineTTL)
	if err != nil {
		return Limits{}, err
	}
	high, err := time.ParseDuration(f.HighRiskOfflineTTL)
	if err != nil {
		return Limits{}, err
	}
	chunk := f.ChunkBytes
	if chunk <= 0 {
		chunk = 128
	}
	maxBundle := f.MaxBundleBytes
	if maxBundle <= 0 {
		maxBundle = 1 << 20
	}
	pool := f.WorkerPool
	if pool <= 0 {
		pool = 4
	}
	endpoints := f.SimulatedEndpoints
	if endpoints <= 0 {
		endpoints = 300
	}
	return Limits{
		GrantTTL:           grant,
		LowRiskOfflineTTL:  low,
		HighRiskOfflineTTL: high,
		ChunkBytes:         chunk,
		MaxBundleBytes:     maxBundle,
		WorkerPool:         pool,
		SimulatedEndpoints: endpoints,
	}, nil
}
