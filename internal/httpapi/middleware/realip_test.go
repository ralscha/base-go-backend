package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRealIPIgnoresForwardedHeadersFromUntrustedPeers(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "203.0.113.15:8080"
	request.Header.Set("X-Forwarded-For", "198.51.100.20")

	var gotRemoteAddr string
	handler := RealIP([]string{"127.0.0.1/32"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRemoteAddr = r.RemoteAddr
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), request)

	if gotRemoteAddr != "203.0.113.15:8080" {
		t.Fatalf("RemoteAddr = %q, want original untrusted peer", gotRemoteAddr)
	}
}

func TestRealIPUsesRightMostUntrustedForwardedAddress(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "127.0.0.1:8080"
	request.Header.Set("X-Forwarded-For", "198.51.100.20, 203.0.113.44")

	var gotRemoteAddr string
	handler := RealIP([]string{"127.0.0.1/32"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRemoteAddr = r.RemoteAddr
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), request)

	if gotRemoteAddr != "203.0.113.44" {
		t.Fatalf("RemoteAddr = %q, want first untrusted proxy hop", gotRemoteAddr)
	}
}

func TestRealIPFallsBackToXRealIPForTrustedProxy(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "127.0.0.1:8080"
	request.Header.Set("X-Real-IP", "198.51.100.20")

	var gotRemoteAddr string
	handler := RealIP([]string{"127.0.0.1/32"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRemoteAddr = r.RemoteAddr
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), request)

	if gotRemoteAddr != "198.51.100.20" {
		t.Fatalf("RemoteAddr = %q, want X-Real-IP value", gotRemoteAddr)
	}
}
