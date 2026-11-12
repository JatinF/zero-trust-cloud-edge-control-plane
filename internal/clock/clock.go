// Package clock is the lab clock for policy and grant expiry.
// Workload certificate lifetime uses the process wall clock instead.
package clock

import (
	"sync"
	"time"
)

type Clock struct {
	mu  sync.Mutex
	now time.Time
}

func New(now time.Time) *Clock {
	return &Clock{now: now.UTC()}
}

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *Clock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now.UTC()
	c.mu.Unlock()
}

func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}
