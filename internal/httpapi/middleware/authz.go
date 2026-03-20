package middleware

import (
	"context"
	"net/http"
	"slices"
	"time"

	internalcache "base/internal/cache"
	"base/internal/httpapi/jsonio"

	"github.com/alexedwards/scs/v2"
)

type RoleResolver func(ctx context.Context, userID int64) ([]string, error)

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

func RequireRoles(sessions *scs.SessionManager, resolveRoles RoleResolver, roleCache *internalcache.Cache[int64, []string], required ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := sessions.GetInt64(r.Context(), "user_id")
			if userID == 0 {
				writeAuthzError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
				return
			}

			roles, err := resolveRoleNames(r.Context(), userID, resolveRoles, roleCache)
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

func resolveRoleNames(ctx context.Context, userID int64, resolveRoles RoleResolver, roleCache *internalcache.Cache[int64, []string]) ([]string, error) {
	now := time.Now().UTC()
	if roles, ok := roleCache.Get(userID, now); ok {
		return roles, nil
	}

	roles, err := resolveRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	roleCache.Set(userID, roles, now)
	return append([]string(nil), roles...), nil
}

func contains(items []string, wanted string) bool {
	return slices.Contains(items, wanted)
}

func writeAuthzError(w http.ResponseWriter, status int, code, message string) {
	jsonio.WriteError(w, status, code, message)
}
