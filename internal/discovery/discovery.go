// Package discovery reads a fixed simulator catalog.
// It does not open network connections and it does not scan arbitrary addresses.
package discovery

import (
	"context"
	"sync/atomic"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/model"
)

type Asset struct {
	ID     string
	Type   string
	Source string
}

func Scan(connector string) ([]Asset, error) {
	switch connector {
	case "sim-cmdb":
		return []Asset{
			{ID: "SYN-ASSET-DB-1", Type: "database", Source: "sim-cmdb"},
			{ID: "SYN-ASSET-APP-1", Type: "application", Source: "sim-cmdb"},
		}, nil
	case "sim-app":
		return []Asset{
			{ID: "SYN-ASSET-APP-2", Type: "application", Source: "sim-app"},
		}, nil
	default:
		return nil, apperr.New("unknown_connector", "connector is not in the simulator catalog", 422)
	}
}

type Pool struct {
	sem      chan struct{}
	inflight atomic.Int32
	maxSeen  atomic.Int32
}

func NewPool(size int) *Pool {
	if size < 1 {
		size = 1
	}
	return &Pool{sem: make(chan struct{}, size)}
}

func (p *Pool) MaxSeen() int32 {
	return p.maxSeen.Load()
}

// Submit runs fn when a slot is free. A full pool returns worker_pool_saturated
// instead of queueing without bound.
func (p *Pool) Submit(ctx context.Context, fn func()) error {
	select {
	case p.sem <- struct{}{}:
		current := p.inflight.Add(1)
		for {
			seen := p.maxSeen.Load()
			if current <= seen || p.maxSeen.CompareAndSwap(seen, current) {
				break
			}
		}
		go func() {
			defer func() {
				p.inflight.Add(-1)
				<-p.sem
			}()
			fn()
		}()
		return nil
	case <-ctx.Done():
		return apperr.New("worker_pool_saturated", "discovery worker pool is full", 503)
	}
}

func ToModel(tenant string, at int64, items []Asset) []model.Asset {
	out := make([]model.Asset, 0, len(items))
	for _, item := range items {
		out = append(out, model.Asset{
			ID:             item.ID,
			TenantID:       tenant,
			Source:         item.Source,
			Type:           item.Type,
			ObservedAtUnix: at,
		})
	}
	return out
}
