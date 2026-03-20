package cache

import (
	"reflect"
	"testing"
	"time"
)

func TestNewReturnsNilWhenDisabled(t *testing.T) {
	if cache := New[int, string](0, nil); cache != nil {
		t.Fatal("New() returned non-nil cache for zero TTL")
	}
}

func TestCacheReturnsClonedValues(t *testing.T) {
	now := time.Now().UTC()
	cache := New[int](time.Minute, func(value []string) []string {
		return append([]string(nil), value...)
	})

	cache.Set(42, []string{"admin"}, now)

	roles, ok := cache.Get(42, now)
	if !ok {
		t.Fatal("Get() cache miss, want hit")
	}
	roles[0] = "viewer"

	again, ok := cache.Get(42, now)
	if !ok {
		t.Fatal("Get() cache miss after mutation, want hit")
	}
	if !reflect.DeepEqual(again, []string{"admin"}) {
		t.Fatalf("Get() = %v, want %v", again, []string{"admin"})
	}
}

func TestCacheExpiresEntries(t *testing.T) {
	now := time.Now().UTC()
	cache := New[string, int](10*time.Millisecond, nil)
	cache.Set("answer", 42, now)

	if value, ok := cache.Get("answer", now.Add(5*time.Millisecond)); !ok || value != 42 {
		t.Fatalf("Get() = (%d, %t), want (42, true)", value, ok)
	}
	if _, ok := cache.Get("answer", now.Add(25*time.Millisecond)); ok {
		t.Fatal("Get() cache hit after expiry, want miss")
	}
}

func TestCacheSweepEvictsExpiredEntries(t *testing.T) {
	now := time.Now().UTC()
	cache := New[string, int](10*time.Millisecond, nil)
	cache.Set("answer", 42, now)

	cache.Sweep(now.Add(25 * time.Millisecond))

	cache.mu.RLock()
	_, stillPresent := cache.items["answer"]
	cache.mu.RUnlock()
	if stillPresent {
		t.Fatal("Sweep() did not evict expired entry")
	}
}

func TestCacheGetDoesNotDeleteFreshEntryOnExpiredRead(t *testing.T) {
	cache := New[string, int](time.Minute, nil)

	past := time.Now().UTC().Add(-2 * time.Minute)
	future := time.Now().UTC().Add(time.Minute)

	// Store an entry using a past timestamp so the first read considers it expired.
	cache.mu.Lock()
	cache.items["key"] = entry[int]{value: 1, expiresAt: past.Add(cache.ttl)}
	cache.mu.Unlock()

	// Concurrently refresh the entry before Get acquires the write lock.
	cache.Set("key", 99, future)

	// Get with a "now" past the original expiry: should not delete the fresh entry.
	cache.Get("key", past.Add(2*time.Minute))

	if v, ok := cache.Get("key", time.Now().UTC()); !ok || v != 99 {
		t.Fatalf("Get() = (%d, %t), want (99, true); fresh entry was incorrectly deleted", v, ok)
	}
}
