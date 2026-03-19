package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexedwards/scs/v2"
)

func TestRequireAuthenticatedRejectsAnonymousRequests(t *testing.T) {
	sessions := scs.New()
	handler := sessions.LoadAndSave(RequireAuthenticated(sessions)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}

	var payload apiError
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Error.Code != "unauthorized" || payload.Error.Message != "authentication required" {
		t.Fatalf("payload = %+v, want unauthorized response", payload)
	}
}

func TestRequireAuthenticatedAllowsSignedInRequests(t *testing.T) {
	sessions := scs.New()
	nextCalled := false
	protected := RequireAuthenticated(sessions)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	handler := sessions.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions.Put(r.Context(), "user_id", int64(42))
		protected.ServeHTTP(w, r)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
}

func TestRequireRolesAllowsAdminOverride(t *testing.T) {
	sessions := scs.New()
	nextCalled := false
	protected := RequireRoles(sessions, "reports:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	handler := sessions.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions.Put(r.Context(), "roles", []string{"admin"})
		protected.ServeHTTP(w, r)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if !nextCalled {
		t.Fatal("expected admin role to bypass specific role checks")
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
}

func TestRequireRolesRejectsMissingRole(t *testing.T) {
	sessions := scs.New()
	protected := RequireRoles(sessions, "reports:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))
	handler := sessions.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions.Put(r.Context(), "roles", []string{"viewer"})
		protected.ServeHTTP(w, r)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}

	var payload apiError
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Error.Code != "forbidden" || payload.Error.Message != "missing role" {
		t.Fatalf("payload = %+v, want forbidden response", payload)
	}
}
