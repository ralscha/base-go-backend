package config

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var loadConfigMu sync.Mutex

func TestLoadAppliesDefaultsAndEnvironmentOverrides(t *testing.T) {
	loadConfigMu.Lock()
	defer loadConfigMu.Unlock()

	writeConfigFixture(t, `
app:
  name: ""
  env: test

http:
  address: ":8080"

security:
  encryption_key: 0123456789abcdef0123456789abcdef
`)
	t.Setenv("BASE_HTTP_ADDRESS", ":9999")
	t.Setenv("BASE_DATABASE_MAX_OPEN_CONNS", "11")
	t.Setenv("BASE_SECURITY_ALLOWED_ORIGINS", "https://app.example.com, https://admin.example.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.App.Name != "base" {
		t.Fatalf("App.Name = %q, want base", cfg.App.Name)
	}
	if cfg.HTTP.Address != ":9999" {
		t.Fatalf("HTTP.Address = %q, want :9999", cfg.HTTP.Address)
	}
	if cfg.Database.MaxOpenConns != 11 {
		t.Fatalf("Database.MaxOpenConns = %d, want 11", cfg.Database.MaxOpenConns)
	}
	if len(cfg.Security.AllowedOrigins) != 2 || cfg.Security.AllowedOrigins[0] != "https://app.example.com" || cfg.Security.AllowedOrigins[1] != "https://admin.example.com" {
		t.Fatalf("Security.AllowedOrigins = %#v, want parsed comma-separated origins", cfg.Security.AllowedOrigins)
	}
	if cfg.OAuth.StateTTL != 10*time.Minute {
		t.Fatalf("OAuth.StateTTL = %v, want 10m", cfg.OAuth.StateTTL)
	}
	if cfg.OAuth.StateBytes != 32 {
		t.Fatalf("OAuth.StateBytes = %d, want 32", cfg.OAuth.StateBytes)
	}
	if cfg.OAuth.PKCEVerifierBytes != 32 {
		t.Fatalf("OAuth.PKCEVerifierBytes = %d, want 32", cfg.OAuth.PKCEVerifierBytes)
	}
	if cfg.Security.AuthorizationCacheTTL != 5*time.Second {
		t.Fatalf("Security.AuthorizationCacheTTL = %v, want 5s", cfg.Security.AuthorizationCacheTTL)
	}
	if cfg.OAuth.Providers == nil {
		t.Fatal("OAuth.Providers = nil, want initialized map")
	}
}

func TestLoadAppliesNestedOAuthProviderEnvironmentOverrides(t *testing.T) {
	loadConfigMu.Lock()
	defer loadConfigMu.Unlock()

	writeConfigFixture(t, `
app:
  env: test

security:
  encryption_key: 0123456789abcdef0123456789abcdef

oauth:
  providers:
    google:
      enabled: false
      client_id: ""
      client_secret: ""
      auth_url: https://accounts.google.com/o/oauth2/v2/auth
      token_url: https://oauth2.googleapis.com/token
      user_info_url: https://openidconnect.googleapis.com/v1/userinfo
      redirect_url: http://localhost:8080/api/v1/auth/oauth/google/callback
`)
	t.Setenv("BASE_OAUTH_PROVIDERS_GOOGLE_CLIENT_ID", "google-client-id")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	provider, ok := cfg.OAuth.Providers["google"]
	if !ok {
		t.Fatal("OAuth.Providers[google] missing after env override")
	}
	if provider.ClientID != "google-client-id" {
		t.Fatalf("OAuth.Providers[google].ClientID = %q, want google-client-id", provider.ClientID)
	}
}

func TestLoadRejectsDefaultEncryptionKeyInProduction(t *testing.T) {
	loadConfigMu.Lock()
	defer loadConfigMu.Unlock()

	writeConfigFixture(t, `
app:
  env: production

security:
  encryption_key: 0123456789abcdef0123456789abcdef
`)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want production encryption key validation error")
	}
	if !strings.Contains(err.Error(), "security.encryption_key must be changed") {
		t.Fatalf("Load() error = %v, want encryption key validation error", err)
	}
}

func TestLoadRejectsEnabledOAuthProviderWithMissingFields(t *testing.T) {
	loadConfigMu.Lock()
	defer loadConfigMu.Unlock()

	writeConfigFixture(t, `
app:
  env: test

security:
  encryption_key: 0123456789abcdef0123456789abcdef

oauth:
  providers:
    github:
      enabled: true
      client_id: client-id
`)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want oauth provider validation error")
	}
	if !strings.Contains(err.Error(), "oauth.providers.github must set client_id") {
		t.Fatalf("Load() error = %v, want oauth provider validation error", err)
	}
}

func TestLoadRejectsInvalidRiverConfigWhenEnabled(t *testing.T) {
	loadConfigMu.Lock()
	defer loadConfigMu.Unlock()

	testCases := []struct {
		name      string
		configYML string
		want      string
	}{
		{
			name: "missing email outbox interval",
			configYML: `
app:
  env: test

security:
  encryption_key: 0123456789abcdef0123456789abcdef

river:
  enabled: true
  email_outbox_every: 0s
  email_outbox_retention: 720h
  cleanup_every: 1h
  inactivity_check_every: 24h
  max_workers: 10
`,
			want: "river.email_outbox_every must be greater than zero",
		},
		{
			name: "invalid worker count",
			configYML: `
app:
  env: test

security:
  encryption_key: 0123456789abcdef0123456789abcdef

river:
  enabled: true
  email_outbox_every: 1m
  email_outbox_retention: 720h
  cleanup_every: 1h
  inactivity_check_every: 24h
  max_workers: 0
`,
			want: "river.max_workers must be between 1 and 10000",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			writeConfigFixture(t, testCase.configYML)

			_, err := Load()
			if err == nil {
				t.Fatal("Load() error = nil, want river validation error")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("Load() error = %v, want %q", err, testCase.want)
			}
		})
	}
}

func writeConfigFixture(t *testing.T, contents string) {
	t.Helper()

	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(strings.TrimSpace(contents)), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWD)
	})
}
