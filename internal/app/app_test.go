package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"base/internal/config"
	"base/internal/testutil"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLoggerReturnsStoredLogger(t *testing.T) {
	logger := slog.Default()
	application := &App{logger: logger}

	if got := application.Logger(); got != logger {
		t.Fatalf("Logger() = %p, want %p", got, logger)
	}
}

func TestNewLoggerLevels(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name         string
		level        string
		enabledDebug bool
		enabledInfo  bool
		enabledWarn  bool
		enabledError bool
	}{
		{name: "debug", level: "debug", enabledDebug: true, enabledInfo: true, enabledWarn: true, enabledError: true},
		{name: "warn", level: "warn", enabledDebug: false, enabledInfo: false, enabledWarn: true, enabledError: true},
		{name: "error", level: "error", enabledDebug: false, enabledInfo: false, enabledWarn: false, enabledError: true},
		{name: "default info", level: "unknown", enabledDebug: false, enabledInfo: true, enabledWarn: true, enabledError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			logger := newLogger(testCase.level)
			if logger.Enabled(ctx, slog.LevelDebug) != testCase.enabledDebug {
				t.Fatalf("debug enabled = %v, want %v", logger.Enabled(ctx, slog.LevelDebug), testCase.enabledDebug)
			}
			if logger.Enabled(ctx, slog.LevelInfo) != testCase.enabledInfo {
				t.Fatalf("info enabled = %v, want %v", logger.Enabled(ctx, slog.LevelInfo), testCase.enabledInfo)
			}
			if logger.Enabled(ctx, slog.LevelWarn) != testCase.enabledWarn {
				t.Fatalf("warn enabled = %v, want %v", logger.Enabled(ctx, slog.LevelWarn), testCase.enabledWarn)
			}
			if logger.Enabled(ctx, slog.LevelError) != testCase.enabledError {
				t.Fatalf("error enabled = %v, want %v", logger.Enabled(ctx, slog.LevelError), testCase.enabledError)
			}
		})
	}
}

func TestNewSessionManagerConfiguresCookieAndSameSite(t *testing.T) {
	testCases := []struct {
		name             string
		sameSite         string
		wantSameSiteMode http.SameSite
	}{
		{name: "strict", sameSite: "strict", wantSameSiteMode: http.SameSiteStrictMode},
		{name: "none", sameSite: "none", wantSameSiteMode: http.SameSiteNoneMode},
		{name: "default lax", sameSite: "lax", wantSameSiteMode: http.SameSiteLaxMode},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			manager, store := newSessionManager((*pgxpool.Pool)(nil), config.Config{
				Session: config.SessionConfig{
					CookieName:  "base_session",
					HTTPOnly:    true,
					Persist:     true,
					Secure:      true,
					Lifetime:    24 * time.Hour,
					IdleTimeout: 12 * time.Hour,
					SameSite:    testCase.sameSite,
				},
			})

			if manager.Cookie.Name != "base_session" || !manager.Cookie.HttpOnly || !manager.Cookie.Persist || !manager.Cookie.Secure {
				t.Fatalf("manager cookie = %+v, want configured cookie", manager.Cookie)
			}
			if manager.Cookie.SameSite != testCase.wantSameSiteMode {
				t.Fatalf("SameSite = %v, want %v", manager.Cookie.SameSite, testCase.wantSameSiteMode)
			}
			if manager.Lifetime != 24*time.Hour || manager.IdleTimeout != 12*time.Hour {
				t.Fatalf("manager lifetime settings = %v/%v, want 24h/12h", manager.Lifetime, manager.IdleTimeout)
			}
			if manager.Store != store {
				t.Fatal("manager.Store was not set to returned store")
			}
			if store == nil {
				t.Fatal("store = nil, want store instance")
			}
		})
	}
}

func TestNewAndRunStartsAndStopsApp(t *testing.T) {
	ctx := context.Background()
	databaseURL := testutil.FreshPostgresDatabaseURL(t, ctx)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close() error = %v", err)
	}

	application, err := New(ctx, config.Config{
		App: config.AppConfig{Env: "test", LogLevel: "debug"},
		HTTP: config.HTTPConfig{
			Address:           address,
			ReadTimeout:       5 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       5 * time.Second,
			ShutdownTimeout:   5 * time.Second,
		},
		Database: config.DatabaseConfig{
			URL:             databaseURL,
			MaxOpenConns:    5,
			MaxIdleConns:    2,
			ConnMaxLifetime: time.Minute,
			ConnMaxIdleTime: time.Minute,
		},
		Session: config.SessionConfig{
			CookieName:  "base_session",
			Lifetime:    24 * time.Hour,
			IdleTimeout: 12 * time.Hour,
			SameSite:    "lax",
			HTTPOnly:    true,
			Persist:     true,
		},
		Security: config.SecurityConfig{
			EncryptionKey:        "0123456789abcdef0123456789abcdef",
			PasswordResetTTL:     time.Hour,
			EmailVerificationTTL: 24 * time.Hour,
			RecoveryTTL:          30 * time.Minute,
			FailedLoginThreshold: 5,
			FailedLoginWindow:    15 * time.Minute,
			TOTPIssuer:           "base-test",
		},
		OAuth:    config.OAuthConfig{StateTTL: 10 * time.Minute, StateBytes: 32, PKCEVerifierBytes: 32, Providers: map[string]config.OAuthProviderConfig{}},
		WebAuthn: config.WebAuthnConfig{RPID: "localhost", RPDisplayName: "Base Test", RPOrigins: []string{"http://localhost"}},
		Mailer:   config.MailerConfig{Enabled: false},
		River:    config.RiverConfig{Enabled: false},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- application.Run(runCtx)
	}()

	client := &http.Client{Timeout: time.Second}
	healthURL := fmt.Sprintf("http://%s/health", address)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("timed out waiting for app health endpoint")
		}
		resp, err := client.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("Run() returned before health check: %v", err)
			}
			t.Fatal("Run() returned before health check without error")
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}
