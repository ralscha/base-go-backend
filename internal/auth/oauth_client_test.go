package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"base/internal/config"
)

func TestConfiguredOAuthProviderExchangeCode(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", r.Method)
			}
			if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
				t.Fatalf("Content-Type = %q, want application/x-www-form-urlencoded", got)
			}

			body, err := ioReadAllAndClose(r)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			values, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatalf("ParseQuery() error = %v", err)
			}
			if values.Get("grant_type") != "authorization_code" || values.Get("code") != "code-123" || values.Get("client_id") != "client-id" || values.Get("client_secret") != "client-secret" || values.Get("redirect_uri") != "https://app.example.com/callback" || values.Get("code_verifier") != "verifier-123" {
				t.Fatalf("unexpected token request values: %v", values)
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":" access-token ","refresh_token":" refresh-token ","expires_in":60}`))
		}))
		defer server.Close()

		provider := configuredOAuthProvider{
			config: config.OAuthProviderConfig{
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "https://app.example.com/callback",
				TokenURL:     server.URL,
			},
			httpClient: server.Client(),
		}

		before := time.Now().UTC()
		tokens, err := provider.ExchangeCode(context.Background(), "code-123", "verifier-123")
		after := time.Now().UTC()
		if err != nil {
			t.Fatalf("ExchangeCode() error = %v", err)
		}
		if tokens.AccessToken != "access-token" || tokens.RefreshToken != "refresh-token" {
			t.Fatalf("tokens = %+v, want trimmed access/refresh tokens", tokens)
		}
		if tokens.Expiry.Before(before.Add(59*time.Second)) || tokens.Expiry.After(after.Add(61*time.Second)) {
			t.Fatalf("Expiry = %v, want about 60 seconds from now", tokens.Expiry)
		}
	})

	t.Run("http error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad token request", http.StatusBadRequest)
		}))
		defer server.Close()

		provider := configuredOAuthProvider{config: config.OAuthProviderConfig{TokenURL: server.URL}, httpClient: server.Client()}
		_, err := provider.ExchangeCode(context.Background(), "code", "verifier")
		if err == nil || !strings.Contains(err.Error(), "token endpoint returned 400") {
			t.Fatalf("ExchangeCode() error = %v, want token endpoint status error", err)
		}
	})

	t.Run("missing access token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"refresh_token":"only-refresh"}`))
		}))
		defer server.Close()

		provider := configuredOAuthProvider{config: config.OAuthProviderConfig{TokenURL: server.URL}, httpClient: server.Client()}
		_, err := provider.ExchangeCode(context.Background(), "code", "verifier")
		if !errors.Is(err, ErrRequestFailed) {
			t.Fatalf("ExchangeCode() error = %v, want %v", err, ErrRequestFailed)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"access_token":`))
		}))
		defer server.Close()

		provider := configuredOAuthProvider{config: config.OAuthProviderConfig{TokenURL: server.URL}, httpClient: server.Client()}
		_, err := provider.ExchangeCode(context.Background(), "code", "verifier")
		if err == nil {
			t.Fatal("ExchangeCode() error = nil, want decode error")
		}
	})
}

func TestConfiguredOAuthProviderFetchProfile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s, want GET", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
				t.Fatalf("Authorization = %q, want bearer token", got)
			}
			_, _ = w.Write([]byte(`{"sub":"user-1","email":" USER@example.com ","email_verified":"true","preferred_username":"alice","name":"Alice Doe"}`))
		}))
		defer server.Close()

		provider := configuredOAuthProvider{
			config: config.OAuthProviderConfig{
				UserInfoURL:        server.URL,
				SubjectField:       "sub",
				EmailField:         "email",
				EmailVerifiedField: "email_verified",
				UsernameField:      "preferred_username",
				NameField:          "name",
			},
			httpClient: server.Client(),
		}

		profile, err := provider.FetchProfile(context.Background(), "access-token")
		if err != nil {
			t.Fatalf("FetchProfile() error = %v", err)
		}
		if profile.Subject != "user-1" || profile.Email != "user@example.com" || !profile.EmailVerified || profile.Username != "alice" || profile.Name != "Alice Doe" {
			t.Fatalf("profile = %+v, want normalized profile fields", profile)
		}
	})

	t.Run("http error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("denied"))
		}))
		defer server.Close()

		provider := configuredOAuthProvider{config: config.OAuthProviderConfig{UserInfoURL: server.URL}, httpClient: server.Client()}
		_, err := provider.FetchProfile(context.Background(), "access-token")
		if err == nil || !strings.Contains(err.Error(), "userinfo endpoint returned 401") {
			t.Fatalf("FetchProfile() error = %v, want userinfo status error", err)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"sub":`))
		}))
		defer server.Close()

		provider := configuredOAuthProvider{config: config.OAuthProviderConfig{UserInfoURL: server.URL}, httpClient: server.Client()}
		_, err := provider.FetchProfile(context.Background(), "access-token")
		if err == nil {
			t.Fatal("FetchProfile() error = nil, want decode error")
		}
	})
}

func ioReadAllAndClose(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	return body, nil
}
