package cache

import (
	"sync"
	"time"
)

type entry[V any] struct {
	value     V
	expiresAt time.Time
}

type Cache[K comparable, V any] struct {
	ttl   time.Duration
	clone func(V) V
	mu    sync.RWMutex
	items map[K]entry[V]
}

func New[K comparable, V any](ttl time.Duration, clone func(V) V) *Cache[K, V] {
	if ttl <= 0 {
		return nil
	}

	return &Cache[K, V]{
		ttl:   ttl,
		clone: clone,
		items: make(map[K]entry[V]),
	}
}

// Sweep deletes all entries whose TTL has expired as of now.
// Call this periodically from an external scheduler.
func (c *Cache[K, V]) Sweep(now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	for k, e := range c.items {
		if now.After(e.expiresAt) {
			delete(c.items, k)
		}
	}
	c.mu.Unlock()
}

func (c *Cache[K, V]) Get(key K, now time.Time) (V, bool) {
	var zero V
	if c == nil {
		return zero, false
	}

	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()
	if !ok || now.After(e.expiresAt) {
		if ok {
			c.mu.Lock()
			if current, still := c.items[key]; still && now.After(current.expiresAt) {
				delete(c.items, key)
			}
			c.mu.Unlock()
		}
		return zero, false
	}

	return c.cloneValue(e.value), true
}

func (c *Cache[K, V]) Set(key K, value V, now time.Time) {
	if c == nil {
		return
	}

	c.mu.Lock()
	c.items[key] = entry[V]{
		value:     c.cloneValue(value),
		expiresAt: now.Add(c.ttl),
	}
	c.mu.Unlock()
}

func (c *Cache[K, V]) cloneValue(value V) V {
	if c.clone == nil {
		return value
	}
	return c.clone(value)
}
