package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type Config struct {
	App       AppConfig       `koanf:"app"`
	HTTP      HTTPConfig      `koanf:"http"`
	Database  DatabaseConfig  `koanf:"database"`
	Session   SessionConfig   `koanf:"session"`
	Security  SecurityConfig  `koanf:"security"`
	OAuth     OAuthConfig     `koanf:"oauth"`
	WebAuthn  WebAuthnConfig  `koanf:"webauthn"`
	Mailer    MailerConfig    `koanf:"mailer"`
	Scheduler SchedulerConfig `koanf:"scheduler"`
}

type AppConfig struct {
	Name     string `koanf:"name"`
	Env      string `koanf:"env"`
	LogLevel string `koanf:"log_level"`
}

type HTTPConfig struct {
	Address           string        `koanf:"address"`
	ReadTimeout       time.Duration `koanf:"read_timeout"`
	ReadHeaderTimeout time.Duration `koanf:"read_header_timeout"`
	WriteTimeout      time.Duration `koanf:"write_timeout"`
	IdleTimeout       time.Duration `koanf:"idle_timeout"`
	ShutdownTimeout   time.Duration `koanf:"shutdown_timeout"`
	TrustedProxies    []string      `koanf:"trusted_proxies"`
}

type DatabaseConfig struct {
	URL             string        `koanf:"url"`
	MaxOpenConns    int           `koanf:"max_open_conns"`
	MaxIdleConns    int           `koanf:"max_idle_conns"`
	ConnMaxLifetime time.Duration `koanf:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `koanf:"conn_max_idle_time"`
}

type SessionConfig struct {
	CookieName  string        `koanf:"cookie_name"`
	Lifetime    time.Duration `koanf:"lifetime"`
	IdleTimeout time.Duration `koanf:"idle_timeout"`
	SameSite    string        `koanf:"same_site"`
	Secure      bool          `koanf:"secure"`
	HTTPOnly    bool          `koanf:"http_only"`
	Persist     bool          `koanf:"persist"`
}

type SecurityConfig struct {
	AllowedOrigins         []string      `koanf:"allowed_origins"`
	CSRFSecure             bool          `koanf:"csrf_secure"`
	EncryptionKey          string        `koanf:"encryption_key"`
	AuthorizationCacheTTL  time.Duration `koanf:"authorization_cache_ttl"`
	PasswordResetTTL       time.Duration `koanf:"password_reset_ttl"`
	EmailVerificationTTL   time.Duration `koanf:"email_verification_ttl"`
	RecoveryTTL            time.Duration `koanf:"recovery_ttl"`
	FailedLoginThreshold   int           `koanf:"failed_login_threshold"`
	FailedLoginWindow      time.Duration `koanf:"failed_login_window"`
	InactivityDisableAfter time.Duration `koanf:"inactivity_disable_after"`
	TOTPIssuer             string        `koanf:"totp_issuer"`
}

type OAuthConfig struct {
	StateTTL          time.Duration                  `koanf:"state_ttl"`
	StateBytes        int                            `koanf:"state_bytes"`
	PKCEVerifierBytes int                            `koanf:"pkce_verifier_bytes"`
	Providers         map[string]OAuthProviderConfig `koanf:"providers"`
}

type OAuthProviderConfig struct {
	Enabled            bool     `koanf:"enabled"`
	ClientID           string   `koanf:"client_id"`
	ClientSecret       string   `koanf:"client_secret"`
	AuthURL            string   `koanf:"auth_url"`
	TokenURL           string   `koanf:"token_url"`
	UserInfoURL        string   `koanf:"user_info_url"`
	RedirectURL        string   `koanf:"redirect_url"`
	Scopes             []string `koanf:"scopes"`
	SubjectField       string   `koanf:"subject_field"`
	EmailField         string   `koanf:"email_field"`
	EmailVerifiedField string   `koanf:"email_verified_field"`
	UsernameField      string   `koanf:"username_field"`
	NameField          string   `koanf:"name_field"`
}

type WebAuthnConfig struct {
	RPID          string   `koanf:"rp_id"`
	RPDisplayName string   `koanf:"rp_display_name"`
	RPOrigins     []string `koanf:"rp_origins"`
}

type MailerConfig struct {
	Enabled    bool   `koanf:"enabled"`
	From       string `koanf:"from"`
	Host       string `koanf:"host"`
	Port       int    `koanf:"port"`
	Username   string `koanf:"username"`
	Password   string `koanf:"password"`
	RequireTLS bool   `koanf:"require_tls"`
}

type SchedulerConfig struct {
	Enabled              bool          `koanf:"enabled"`
	EmailOutboxEvery     time.Duration `koanf:"email_outbox_every"`
	CleanupEvery         time.Duration `koanf:"cleanup_every"`
	InactivityCheckEvery time.Duration `koanf:"inactivity_check_every"`
}

func Load() (Config, error) {
	k := koanf.New(".")
	if err := k.Load(file.Provider("config/config.yaml"), yaml.Parser()); err != nil {
		return Config{}, fmt.Errorf("load config file: %w", err)
	}

	if err := k.Load(env.Provider("BASE_", ".", func(raw string) string {
		trimmed := strings.TrimPrefix(raw, "BASE_")
		return strings.ToLower(strings.ReplaceAll(trimmed, "_", "."))
	}), nil); err != nil {
		return Config{}, fmt.Errorf("load environment: %w", err)
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshal config: %w", err)
	}

	if cfg.App.Name == "" {
		cfg.App.Name = "base"
	}
	if cfg.OAuth.StateTTL <= 0 {
		cfg.OAuth.StateTTL = 10 * time.Minute
	}
	if cfg.OAuth.StateBytes <= 0 {
		cfg.OAuth.StateBytes = 32
	}
	if cfg.OAuth.PKCEVerifierBytes <= 0 {
		cfg.OAuth.PKCEVerifierBytes = 32
	}
	if cfg.OAuth.Providers == nil {
		cfg.OAuth.Providers = map[string]OAuthProviderConfig{}
	}
	if cfg.Security.AuthorizationCacheTTL <= 0 {
		cfg.Security.AuthorizationCacheTTL = 5 * time.Second
	}
	for name, provider := range cfg.OAuth.Providers {
		if !provider.Enabled {
			continue
		}
		if provider.ClientID == "" || provider.ClientSecret == "" || provider.AuthURL == "" || provider.TokenURL == "" || provider.UserInfoURL == "" || provider.RedirectURL == "" {
			return Config{}, fmt.Errorf("oauth.providers.%s must set client_id, client_secret, auth_url, token_url, user_info_url, and redirect_url when enabled", name)
		}
	}

	const defaultEncryptionKey = "0123456789abcdef0123456789abcdef"
	appEnv := strings.ToLower(cfg.App.Env)
	if cfg.Security.EncryptionKey == defaultEncryptionKey && appEnv != "development" && appEnv != "test" {
		return Config{}, fmt.Errorf("security.encryption_key must be changed from the default value in non-development environments")
	}

	return cfg, nil
}
