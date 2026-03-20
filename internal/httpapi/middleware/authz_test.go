package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	internalcache "base/internal/cache"

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
	resolverCalls := 0
	protected := RequireRoles(sessions, func(ctx context.Context, userID int64) ([]string, error) {
		resolverCalls++
		if userID != 42 {
			t.Fatalf("userID = %d, want 42", userID)
		}
		return []string{"admin"}, nil
	}, internalcache.New[int64, []string](time.Minute, nil), "reports:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		t.Fatal("expected admin role to bypass specific role checks")
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if resolverCalls != 1 {
		t.Fatalf("resolverCalls = %d, want 1", resolverCalls)
	}
}

func TestRequireRolesRejectsMissingRole(t *testing.T) {
	sessions := scs.New()
	protected := RequireRoles(sessions, func(ctx context.Context, userID int64) ([]string, error) {
		if userID != 42 {
			t.Fatalf("userID = %d, want 42", userID)
		}
		return []string{"viewer"}, nil
	}, internalcache.New[int64, []string](time.Minute, nil), "reports:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))
	handler := sessions.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions.Put(r.Context(), "user_id", int64(42))
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

func TestRequireRolesCachesResolverResults(t *testing.T) {
	sessions := scs.New()
	var mu sync.Mutex
	resolverCalls := 0
	protected := RequireRoles(sessions, func(ctx context.Context, userID int64) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		resolverCalls++
		return []string{"reports:read"}, nil
	}, internalcache.New[int64, []string](time.Minute, nil), "reports:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	handler := sessions.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions.Put(r.Context(), "user_id", int64(42))
		protected.ServeHTTP(w, r)
	}))

	for range 2 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if resolverCalls != 1 {
		t.Fatalf("resolverCalls = %d, want 1", resolverCalls)
	}
}

func TestRequireRolesRefreshesAfterCacheExpiry(t *testing.T) {
	sessions := scs.New()
	var mu sync.Mutex
	currentRoles := []string{"viewer"}
	resolverCalls := 0
	protected := RequireRoles(sessions, func(ctx context.Context, userID int64) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		resolverCalls++
		return append([]string(nil), currentRoles...), nil
	}, internalcache.New[int64, []string](10*time.Millisecond, nil), "reports:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	handler := sessions.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions.Put(r.Context(), "user_id", int64(42))
		protected.ServeHTTP(w, r)
	}))

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/", nil))
	if first.Code != http.StatusForbidden {
		t.Fatalf("first status = %d, want %d", first.Code, http.StatusForbidden)
	}

	mu.Lock()
	currentRoles = []string{"reports:read"}
	mu.Unlock()

	time.Sleep(25 * time.Millisecond)

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/", nil))
	if second.Code != http.StatusNoContent {
		t.Fatalf("second status = %d, want %d", second.Code, http.StatusNoContent)
	}

	mu.Lock()
	defer mu.Unlock()
	if resolverCalls != 2 {
		t.Fatalf("resolverCalls = %d, want 2", resolverCalls)
	}
}
