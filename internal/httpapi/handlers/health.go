package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

type HealthHandler struct {
	DB *sql.DB
}

func (h HealthHandler) Live(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC(),
	})
}

func (h HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	if err := h.DB.PingContext(r.Context()); err != nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "degraded",
			"error":  "database unavailable",
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"status": "ready",
	})
}

func respondJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
