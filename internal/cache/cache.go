// Package cache is a non-authoritative metadata cache.
// Authorization must not read an allow or deny from this package.
package cache

import "sync"

type Cache struct {
	mu    sync.Mutex
	down  bool
	items map[string]string
}

func New() *Cache {
	return &Cache{items: map[string]string{}}
}

func (c *Cache) SetDown(down bool) {
	c.mu.Lock()
	c.down = down
	c.mu.Unlock()
}

func (c *Cache) Down() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.down
}

func (c *Cache) Set(key, value string) {
	c.mu.Lock()
	c.items[key] = value
	c.mu.Unlock()
}

// Get returns false when the cache is down. A miss is not an allow.
func (c *Cache) Get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down {
		return "", false
	}
	value, ok := c.items[key]
	return value, ok
}
