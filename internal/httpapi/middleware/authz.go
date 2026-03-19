package middleware

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/alexedwards/scs/v2"
)

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

func RequireRoles(sessions *scs.SessionManager, required ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			roles, _ := sessions.Get(r.Context(), "roles").([]string)
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
