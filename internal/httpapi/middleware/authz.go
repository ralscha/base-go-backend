package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/alexedwards/scs/v2"
)

type RoleResolver func(ctx context.Context, userID int64) ([]string, error)

type roleCacheEntry struct {
	roles     []string
	expiresAt time.Time
}

type roleCache struct {
	ttl   time.Duration
	mu    sync.RWMutex
	items map[int64]roleCacheEntry
}

func newRoleCache(ttl time.Duration) *roleCache {
	if ttl <= 0 {
		return nil
	}

	return &roleCache{
		ttl:   ttl,
		items: make(map[int64]roleCacheEntry),
	}
}

func (c *roleCache) get(userID int64, now time.Time) ([]string, bool) {
	if c == nil {
		return nil, false
	}

	c.mu.RLock()
	entry, ok := c.items[userID]
	c.mu.RUnlock()
	if !ok || now.After(entry.expiresAt) {
		if ok {
			c.mu.Lock()
			delete(c.items, userID)
			c.mu.Unlock()
		}
		return nil, false
	}

	return append([]string(nil), entry.roles...), true
}

func (c *roleCache) set(userID int64, roles []string, now time.Time) {
	if c == nil {
		return
	}

	c.mu.Lock()
	c.items[userID] = roleCacheEntry{
		roles:     append([]string(nil), roles...),
		expiresAt: now.Add(c.ttl),
	}
	c.mu.Unlock()
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func RequireAuthenticated(sessions *scs.SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if sessions.GetInt64(r.Context(), "user_id") == 0 {
				writeAuthzError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RequireRoles(sessions *scs.SessionManager, resolveRoles RoleResolver, cacheTTL time.Duration, required ...string) func(http.Handler) http.Handler {
	cache := newRoleCache(cacheTTL)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := sessions.GetInt64(r.Context(), "user_id")
			if userID == 0 {
				writeAuthzError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
				return
			}

			roles, err := resolveRoleNames(r.Context(), userID, resolveRoles, cache)
			if err != nil {
				writeAuthzError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
				return
			}
			if contains(roles, "admin") {
				next.ServeHTTP(w, r)
				return
			}

			for _, role := range required {
				if contains(roles, role) {
					next.ServeHTTP(w, r)
					return
				}
			}

			writeAuthzError(w, http.StatusForbidden, "forbidden", "missing role")
		})
	}
}

func resolveRoleNames(ctx context.Context, userID int64, resolveRoles RoleResolver, cache *roleCache) ([]string, error) {
	now := time.Now().UTC()
	if roles, ok := cache.get(userID, now); ok {
		return roles, nil
	}

	roles, err := resolveRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	cache.set(userID, roles, now)
	return append([]string(nil), roles...), nil
}

func contains(items []string, wanted string) bool {
	return slices.Contains(items, wanted)
}

func writeAuthzError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	var payload apiError
	payload.Error.Code = code
	payload.Error.Message = message
	_ = json.NewEncoder(w).Encode(payload)
}
