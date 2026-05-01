package middleware

import (
	"net/http"
	"strings"
)

var defaultCORSHeaders = "Accept, Authorization, Content-Type"
var defaultCORSMethods = "GET, POST, PUT, PATCH, DELETE, OPTIONS"

func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	allowAny := false
	for _, origin := range allowedOrigins {
		trimmed := strings.TrimSpace(origin)
		if trimmed == "" {
			continue
		}
		if trimmed == "*" {
			allowAny = true
			continue
		}
		allowed[trimmed] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" || (!allowAny && !originAllowed(origin, allowed)) {
				next.ServeHTTP(w, r)
				return
			}

			headers := w.Header()
			headers.Add("Vary", "Origin")
			headers.Add("Vary", "Access-Control-Request-Method")
			headers.Add("Vary", "Access-Control-Request-Headers")
			headers.Set("Access-Control-Allow-Origin", origin)
			headers.Set("Access-Control-Allow-Credentials", "true")
			headers.Set("Access-Control-Allow-Methods", defaultCORSMethods)
			headers.Set("Access-Control-Max-Age", "300")

			requestHeaders := strings.TrimSpace(r.Header.Get("Access-Control-Request-Headers"))
			if requestHeaders == "" {
				requestHeaders = defaultCORSHeaders
			}
			headers.Set("Access-Control-Allow-Headers", requestHeaders)

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func originAllowed(origin string, allowed map[string]struct{}) bool {
	_, ok := allowed[origin]
	return ok
}
