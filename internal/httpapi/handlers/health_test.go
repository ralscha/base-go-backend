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

type liveResponse struct {
	Data struct {
		Status string `json:"status"`
		Time   string `json:"time"`
	} `json:"data"`
}

type readyResponse struct {
	Data struct {
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	} `json:"data"`
}

func TestHealthHandlerLive(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health", nil)

	HealthHandler{}.Live(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var payload liveResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Data.Status != "ok" {
		t.Fatalf("status payload = %q, want ok", payload.Data.Status)
	}
	if payload.Data.Time == "" {
		t.Fatal("time payload = empty, want RFC3339 timestamp")
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

		var payload readyResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}
		if payload.Data.Status != "ready" {
			t.Fatalf("payload = %+v, want ready status", payload.Data)
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

		var payload readyResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}
		if payload.Data.Status != "degraded" || payload.Data.Error != "database unavailable" {
			t.Fatalf("payload = %+v, want degraded/database unavailable", payload.Data)
		}
	})
}
