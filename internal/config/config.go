package config

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type Config struct {
	App      AppConfig      `koanf:"app"`
	HTTP     HTTPConfig     `koanf:"http"`
	Database DatabaseConfig `koanf:"database"`
	Session  SessionConfig  `koanf:"session"`
	Security SecurityConfig `koanf:"security"`
	OAuth    OAuthConfig    `koanf:"oauth"`
	WebAuthn WebAuthnConfig `koanf:"webauthn"`
	Mailer   MailerConfig   `koanf:"mailer"`
	River    RiverConfig    `koanf:"river"`
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

type RiverConfig struct {
	Enabled              bool          `koanf:"enabled"`
	EmailOutboxEvery     time.Duration `koanf:"email_outbox_every"`
	EmailOutboxRetention time.Duration `koanf:"email_outbox_retention"`
	CleanupEvery         time.Duration `koanf:"cleanup_every"`
	InactivityCheckEvery time.Duration `koanf:"inactivity_check_every"`
	MaxWorkers           int           `koanf:"max_workers"`
}

const riverQueueMaxWorkers = 10000

func Load() (Config, error) {
	k := koanf.New(".")
	if err := k.Load(file.Provider("config/config.yaml"), yaml.Parser()); err != nil {
		return Config{}, fmt.Errorf("load config file: %w", err)
	}

	if err := k.Load(env.ProviderWithValue("BASE_", ".", func(raw, value string) (string, any) {
		key, fieldType, ok := envVarToConfigKey(raw)
		if !ok {
			return "", nil
		}
		return key, parseEnvValue(fieldType, value)
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
	if cfg.River.EmailOutboxRetention <= 0 {
		cfg.River.EmailOutboxRetention = 30 * 24 * time.Hour
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
	if cfg.River.Enabled {
		if cfg.River.EmailOutboxEvery <= 0 {
			return Config{}, fmt.Errorf("river.email_outbox_every must be greater than zero when river.enabled=true")
		}
		if cfg.River.CleanupEvery <= 0 {
			return Config{}, fmt.Errorf("river.cleanup_every must be greater than zero when river.enabled=true")
		}
		if cfg.River.InactivityCheckEvery <= 0 {
			return Config{}, fmt.Errorf("river.inactivity_check_every must be greater than zero when river.enabled=true")
		}
		if cfg.River.MaxWorkers < 1 || cfg.River.MaxWorkers > riverQueueMaxWorkers {
			return Config{}, fmt.Errorf("river.max_workers must be between 1 and %d when river.enabled=true", riverQueueMaxWorkers)
		}
	}

	return cfg, nil
}

var configType = reflect.TypeFor[Config]()

func envVarToConfigKey(raw string) (string, reflect.Type, bool) {
	trimmed := strings.TrimPrefix(raw, "BASE_")
	if trimmed == "" {
		return "", nil, false
	}

	path, fieldType, ok := matchEnvTokens(configType, strings.Split(strings.ToLower(trimmed), "_"), nil)
	if !ok {
		return "", nil, false
	}

	return strings.Join(path, "."), fieldType, true
}

func matchEnvTokens(t reflect.Type, tokens, path []string) ([]string, reflect.Type, bool) {
	t = indirectType(t)

	if t.Kind() == reflect.Struct {
		for field := range t.Fields() {
			tag := field.Tag.Get("koanf")
			if tag == "" || tag == "-" {
				continue
			}

			tagTokens := strings.Split(tag, "_")
			if !hasTokenPrefix(tokens, tagTokens) {
				continue
			}

			nextPath := appendPath(path, tag)
			fieldType := indirectType(field.Type)
			remaining := tokens[len(tagTokens):]
			if len(remaining) == 0 {
				return nextPath, fieldType, true
			}

			if fieldType.Kind() == reflect.Struct || fieldType.Kind() == reflect.Map {
				if matchedPath, leafType, ok := matchEnvTokens(fieldType, remaining, nextPath); ok {
					return matchedPath, leafType, true
				}
			}
		}
	}
	if t.Kind() == reflect.Map {
		elemType := indirectType(t.Elem())
		for keyLen := 1; keyLen <= len(tokens); keyLen++ {
			mapKey := strings.Join(tokens[:keyLen], "_")
			nextPath := appendPath(path, mapKey)
			remaining := tokens[keyLen:]
			if len(remaining) == 0 {
				return nextPath, elemType, true
			}

			if elemType.Kind() == reflect.Struct || elemType.Kind() == reflect.Map {
				if matchedPath, leafType, ok := matchEnvTokens(elemType, remaining, nextPath); ok {
					return matchedPath, leafType, true
				}
			}
		}
	}

	return nil, nil, false
}

func parseEnvValue(fieldType reflect.Type, value string) any {
	fieldType = indirectType(fieldType)

	if fieldType == reflect.TypeFor[time.Duration]() {
		parsed, err := time.ParseDuration(value)
		if err == nil {
			return parsed
		}
		return value
	}

	if fieldType.Kind() == reflect.Bool {
		parsed, err := strconv.ParseBool(value)
		if err == nil {
			return parsed
		}
	}
	if isSignedIntKind(fieldType.Kind()) {
		parsed, err := strconv.ParseInt(value, 10, fieldType.Bits())
		if err == nil {
			return reflect.ValueOf(parsed).Convert(fieldType).Interface()
		}
	}
	if fieldType.Kind() == reflect.Slice {
		elemType := indirectType(fieldType.Elem())
		if elemType.Kind() == reflect.String {
			if strings.TrimSpace(value) == "" {
				return []string{}
			}
			parts := strings.Split(value, ",")
			values := make([]string, 0, len(parts))
			for _, part := range parts {
				values = append(values, strings.TrimSpace(part))
			}
			return values
		}
	}

	return value
}

func isSignedIntKind(kind reflect.Kind) bool {
	return kind == reflect.Int ||
		kind == reflect.Int8 ||
		kind == reflect.Int16 ||
		kind == reflect.Int32 ||
		kind == reflect.Int64
}

func appendPath(path []string, part string) []string {
	next := make([]string, len(path), len(path)+1)
	copy(next, path)
	return append(next, part)
}

func hasTokenPrefix(tokens, prefix []string) bool {
	if len(tokens) < len(prefix) {
		return false
	}
	for i := range prefix {
		if tokens[i] != prefix[i] {
			return false
		}
	}
	return true
}

func indirectType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}
