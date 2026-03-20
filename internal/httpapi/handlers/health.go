package handlers

import (
	"database/sql"
	"net/http"
	"time"

	"base/internal/httpapi/jsonio"
)

type HealthHandler struct {
	DB *sql.DB
}

func (h HealthHandler) Live(w http.ResponseWriter, _ *http.Request) {
	jsonio.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC(),
	})
}

func (h HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	if err := h.DB.PingContext(r.Context()); err != nil {
		jsonio.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "degraded",
			"error":  "database unavailable",
		})
		return
	}

	jsonio.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "ready",
	})
}
