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
	if cfg.OAuth.StateTTL != 10*time.Minute {
		t.Fatalf("OAuth.StateTTL = %v, want 10m", cfg.OAuth.StateTTL)
	}
	if cfg.OAuth.StateBytes != 32 {
		t.Fatalf("OAuth.StateBytes = %d, want 32", cfg.OAuth.StateBytes)
	}
	if cfg.OAuth.PKCEVerifierBytes != 32 {
		t.Fatalf("OAuth.PKCEVerifierBytes = %d, want 32", cfg.OAuth.PKCEVerifierBytes)
	}
	if cfg.OAuth.Providers == nil {
		t.Fatal("OAuth.Providers = nil, want initialized map")
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

func writeConfigFixture(t *testing.T, contents string) {
	t.Helper()

	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(strings.TrimSpace(contents)), 0o644); err != nil {
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
