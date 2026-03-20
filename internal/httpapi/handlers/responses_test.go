package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"base/internal/config"
	"base/internal/database"
	"base/internal/testutil"
)

func TestWriteJSON(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeJSON(recorder, http.StatusCreated, map[string]any{"id": 7, "name": "alice"})

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusCreated)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}

	var payload envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	data, ok := payload.Data.(map[string]any)
	if !ok {
		t.Fatalf("payload.Data type = %T, want object", payload.Data)
	}
	if data["name"] != "alice" {
		t.Fatalf("payload.Data[name] = %v, want alice", data["name"])
	}
	if got, ok := data["id"].(float64); !ok || got != 7 {
		t.Fatalf("payload.Data[id] = %v, want 7", data["id"])
	}
}

func TestWriteError(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeError(recorder, http.StatusBadRequest, "invalid_request", "missing email")

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}

	var payload envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Error == nil {
		t.Fatal("payload.Error = nil, want error object")
	}
	if payload.Error.Code != "invalid_request" || payload.Error.Message != "missing email" {
		t.Fatalf("payload.Error = %+v, want invalid_request/missing email", payload.Error)
	}
	if payload.Data != nil {
		t.Fatalf("payload.Data = %v, want nil", payload.Data)
	}
}

func TestHealthHandlerLive(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health", nil)

	HealthHandler{}.Live(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("status payload = %v, want ok", payload["status"])
	}
	if _, ok := payload["time"].(string); !ok {
		t.Fatalf("time payload type = %T, want string", payload["time"])
	}
}

func TestHealthHandlerReady(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		ctx := context.Background()
		databaseURL := testutil.FreshPostgresDatabaseURL(t, ctx)

		db, err := database.Open(ctx, config.DatabaseConfig{URL: databaseURL, MaxOpenConns: 5, MaxIdleConns: 2, ConnMaxLifetime: time.Minute, ConnMaxIdleTime: time.Minute})
		if err != nil {
			t.Fatalf("database.Open() error = %v", err)
		}
		defer func() { _ = db.Close() }()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/readiness", nil)
		HealthHandler{DB: db}.Ready(recorder, request)

		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
		}

		var payload map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}
		if payload["status"] != "ready" {
			t.Fatalf("payload = %+v, want ready status", payload)
		}
	})

	t.Run("degraded", func(t *testing.T) {
		db, err := sql.Open("pgx", "postgres://base_user:base_password@127.0.0.1:1/base?sslmode=disable&connect_timeout=1")
		if err != nil {
			t.Fatalf("sql.Open() error = %v", err)
		}
		defer func() { _ = db.Close() }()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/readiness", nil)
		HealthHandler{DB: db}.Ready(recorder, request)

		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
		}

		var payload map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}
		if payload["status"] != "degraded" || payload["error"] != "database unavailable" {
			t.Fatalf("payload = %+v, want degraded/database unavailable", payload)
		}
	})
}
