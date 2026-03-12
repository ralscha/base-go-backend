package httpapi_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"base/internal/auth"
	"base/internal/config"
	"base/internal/database"
	"base/internal/httpapi"
	"base/internal/store/sqlc"

	"github.com/alexedwards/scs/pgxstore"
	"github.com/alexedwards/scs/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	ratelimit "github.com/ralscha/ratelimiter-pg"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestAccountRecoveryFlowReactivatesUserAndClearsTOTP(t *testing.T) {
	ctx := context.Background()
	env := newIntegrationEnv(t, ctx)
	user, err := env.queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "recovery-user", Email: "recover@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	passwordBefore, err := auth.HashPassword("ValidPassword123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if _, err := env.queries.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: user.ID, PasswordHash: passwordBefore}); err != nil {
		t.Fatalf("UpsertPasswordCredential() error = %v", err)
	}

	setup, err := env.authService.BeginTOTPSetup(ctx, user.ID)
	if err != nil {
		t.Fatalf("BeginTOTPSetup() error = %v", err)
	}
	code, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode() error = %v", err)
	}
	if _, err := env.authService.ConfirmTOTPSetup(ctx, user.ID, code); err != nil {
		t.Fatalf("ConfirmTOTPSetup() error = %v", err)
	}

	if _, err := env.db.ExecContext(ctx, `
		UPDATE users
		SET is_active = FALSE,
		    locked_until = NOW() + INTERVAL '1 hour',
		    failed_login_count = 3,
		    disabled_reason = 'inactivity',
		    disabled_at = NOW()
		WHERE id = $1
	`, user.ID); err != nil {
		t.Fatalf("disable user for setup: %v", err)
	}

	requestRecoveryPayload := map[string]string{"email": user.Email}
	requestRecoveryResp := postJSON(t, env.server.URL+"/api/v1/auth/account-recovery/request", requestRecoveryPayload)
	defer func() { _ = requestRecoveryResp.Body.Close() }()
	if requestRecoveryResp.StatusCode != http.StatusAccepted {
		t.Fatalf("account recovery request status = %d, want %d", requestRecoveryResp.StatusCode, http.StatusAccepted)
	}

	emails, err := env.queries.ListPendingEmails(ctx, 10)
	if err != nil {
		t.Fatalf("ListPendingEmails() error = %v", err)
	}
	if len(emails) != 1 {
		t.Fatalf("pending email count = %d, want 1", len(emails))
	}
	if emails[0].Template != "account-recovery" {
		t.Fatalf("email template = %q, want %q", emails[0].Template, "account-recovery")
	}

	var emailPayload struct {
		Token string `json:"token"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(emails[0].Payload, &emailPayload); err != nil {
		t.Fatalf("json.Unmarshal(email payload) error = %v", err)
	}
	if emailPayload.Token == "" {
		t.Fatal("expected recovery token in email payload")
	}

	confirmPayload := map[string]string{
		"token":    emailPayload.Token,
		"password": "RecoveredPassword123",
	}
	confirmResp := postJSON(t, env.server.URL+"/api/v1/auth/account-recovery/confirm", confirmPayload)
	defer func() { _ = confirmResp.Body.Close() }()
	if confirmResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(confirmResp.Body)
		t.Fatalf("account recovery confirm status = %d, want %d, body = %s", confirmResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	updatedUser, err := env.queries.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if !updatedUser.IsActive {
		t.Fatal("expected recovered user to be active")
	}
	if updatedUser.LockedUntil.Valid {
		t.Fatal("expected recovered user lock to be cleared")
	}
	if updatedUser.DisabledReason.Valid {
		t.Fatalf("expected disabled reason cleared, got %q", updatedUser.DisabledReason.String)
	}
	if updatedUser.DisabledAt.Valid {
		t.Fatal("expected disabled_at cleared")
	}
	if !updatedUser.EmailVerifiedAt.Valid {
		t.Fatal("expected email to be verified after recovery")
	}

	passwordCredential, err := env.queries.GetPasswordCredentialByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetPasswordCredentialByUserID() error = %v", err)
	}
	match, err := auth.ComparePassword("RecoveredPassword123", passwordCredential.PasswordHash)
	if err != nil {
		t.Fatalf("ComparePassword() error = %v", err)
	}
	if !match {
		t.Fatal("expected recovered password to be stored")
	}

	if _, err := env.queries.GetTotpConfigurationByUserID(ctx, user.ID); err == nil {
		t.Fatal("expected TOTP configuration to be removed during recovery")
	} else if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetTotpConfigurationByUserID() error = %v, want sql.ErrNoRows", err)
	}

	recoveryToken, err := env.queries.GetUserToken(ctx, sqlc.GetUserTokenParams{
		TokenHash: auth.HashToken(emailPayload.Token),
		Kind:      sqlc.TokenKindAccountRecovery,
	})
	if err == nil {
		t.Fatalf("expected used recovery token to be unavailable, got %+v", recoveryToken)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetRecoveryToken() error = %v, want sql.ErrNoRows", err)
	}
}

func TestAccountRecoveryTokenCannotBeReused(t *testing.T) {
	ctx := context.Background()
	env := newIntegrationEnv(t, ctx)
	user, err := env.queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "recovery-reuse", Email: "reuse@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	passwordBefore, err := auth.HashPassword("InitialPassword123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if _, err := env.queries.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: user.ID, PasswordHash: passwordBefore}); err != nil {
		t.Fatalf("UpsertPasswordCredential() error = %v", err)
	}

	requestRecoveryResp := postJSON(t, env.server.URL+"/api/v1/auth/account-recovery/request", map[string]string{"email": user.Email})
	defer func() { _ = requestRecoveryResp.Body.Close() }()
	if requestRecoveryResp.StatusCode != http.StatusAccepted {
		t.Fatalf("account recovery request status = %d, want %d", requestRecoveryResp.StatusCode, http.StatusAccepted)
	}

	emails, err := env.queries.ListPendingEmails(ctx, 10)
	if err != nil {
		t.Fatalf("ListPendingEmails() error = %v", err)
	}
	if len(emails) != 1 {
		t.Fatalf("pending email count = %d, want 1", len(emails))
	}

	var emailPayload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(emails[0].Payload, &emailPayload); err != nil {
		t.Fatalf("json.Unmarshal(email payload) error = %v", err)
	}

	firstResp := postJSON(t, env.server.URL+"/api/v1/auth/account-recovery/confirm", map[string]string{
		"token":    emailPayload.Token,
		"password": "RecoveredPassword123",
	})
	defer func() { _ = firstResp.Body.Close() }()
	if firstResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(firstResp.Body)
		t.Fatalf("first recovery confirm status = %d, want %d, body = %s", firstResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	secondResp := postJSON(t, env.server.URL+"/api/v1/auth/account-recovery/confirm", map[string]string{
		"token":    emailPayload.Token,
		"password": "AnotherPassword123",
	})
	defer func() { _ = secondResp.Body.Close() }()
	if secondResp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(secondResp.Body)
		t.Fatalf("second recovery confirm status = %d, want %d, body = %s", secondResp.StatusCode, http.StatusBadRequest, strings.TrimSpace(string(body)))
	}

	var errorBody struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(secondResp.Body).Decode(&errorBody); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errorBody.Error.Code != "request_failed" {
		t.Fatalf("error code = %q, want %q", errorBody.Error.Code, "request_failed")
	}

	passwordCredential, err := env.queries.GetPasswordCredentialByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetPasswordCredentialByUserID() error = %v", err)
	}
	match, err := auth.ComparePassword("RecoveredPassword123", passwordCredential.PasswordHash)
	if err != nil {
		t.Fatalf("ComparePassword() error = %v", err)
	}
	if !match {
		t.Fatal("expected password from first recovery to remain unchanged after token reuse")
	}
}

func TestExpiredAccountRecoveryTokenIsRejected(t *testing.T) {
	ctx := context.Background()
	env := newIntegrationEnv(t, ctx)
	user, err := env.queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "recovery-expired", Email: "expired@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	passwordBefore, err := auth.HashPassword("InitialPassword123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if _, err := env.queries.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: user.ID, PasswordHash: passwordBefore}); err != nil {
		t.Fatalf("UpsertPasswordCredential() error = %v", err)
	}

	requestRecoveryResp := postJSON(t, env.server.URL+"/api/v1/auth/account-recovery/request", map[string]string{"email": user.Email})
	defer func() { _ = requestRecoveryResp.Body.Close() }()
	if requestRecoveryResp.StatusCode != http.StatusAccepted {
		t.Fatalf("account recovery request status = %d, want %d", requestRecoveryResp.StatusCode, http.StatusAccepted)
	}

	emails, err := env.queries.ListPendingEmails(ctx, 10)
	if err != nil {
		t.Fatalf("ListPendingEmails() error = %v", err)
	}
	if len(emails) != 1 {
		t.Fatalf("pending email count = %d, want 1", len(emails))
	}

	var emailPayload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(emails[0].Payload, &emailPayload); err != nil {
		t.Fatalf("json.Unmarshal(email payload) error = %v", err)
	}

	if _, err := env.db.ExecContext(ctx, `
		UPDATE user_tokens
		SET expires_at = NOW() - INTERVAL '1 minute'
		WHERE token_hash = $1
	`, auth.HashToken(emailPayload.Token)); err != nil {
		t.Fatalf("expire recovery token for setup: %v", err)
	}

	confirmResp := postJSON(t, env.server.URL+"/api/v1/auth/account-recovery/confirm", map[string]string{
		"token":    emailPayload.Token,
		"password": "RecoveredPassword123",
	})
	defer func() { _ = confirmResp.Body.Close() }()
	if confirmResp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(confirmResp.Body)
		t.Fatalf("expired recovery confirm status = %d, want %d, body = %s", confirmResp.StatusCode, http.StatusBadRequest, strings.TrimSpace(string(body)))
	}

	var errorBody struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(confirmResp.Body).Decode(&errorBody); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errorBody.Error.Code != "request_failed" {
		t.Fatalf("error code = %q, want %q", errorBody.Error.Code, "request_failed")
	}

	passwordCredential, err := env.queries.GetPasswordCredentialByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetPasswordCredentialByUserID() error = %v", err)
	}
	match, err := auth.ComparePassword("InitialPassword123", passwordCredential.PasswordHash)
	if err != nil {
		t.Fatalf("ComparePassword() error = %v", err)
	}
	if !match {
		t.Fatal("expected expired recovery token to leave original password unchanged")
	}
}

func postJSON(t *testing.T, endpoint string, payload any) *http.Response {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(body)) //nolint:gosec // test helper with controlled endpoint
	if err != nil {
		t.Fatalf("http.Post() error = %v", err)
	}

	return resp
}

type integrationEnv struct {
	db          *sql.DB
	pool        *pgxpool.Pool
	server      *httptest.Server
	queries     *sqlc.Queries
	authService *auth.Service
}

func newIntegrationEnv(t *testing.T, ctx context.Context) *integrationEnv {
	t.Helper()

	container, err := tcpostgres.Run(
		ctx,
		"postgres:18-alpine",
		tcpostgres.BasicWaitStrategies(),
		tcpostgres.WithDatabase("base"),
		tcpostgres.WithUsername("base_user"),
		tcpostgres.WithPassword("base_password"),
	)
	if err != nil {
		t.Fatalf("postgres.Run() error = %v", err)
	}
	t.Cleanup(func() {
		terminateCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = container.Terminate(terminateCtx)
	})

	databaseURL, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("ConnectionString() error = %v", err)
	}

	dbCfg := config.DatabaseConfig{
		URL:             databaseURL,
		MaxOpenConns:    10,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
		ConnMaxIdleTime: time.Minute,
	}

	db, err := database.Open(ctx, dbCfg)
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := database.RunMigrations(ctx, db); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	t.Cleanup(pool.Close)

	appCfg := config.Config{
		Database: dbCfg,
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
		WebAuthn: config.WebAuthnConfig{
			RPID:          "localhost",
			RPDisplayName: "Base Test",
			RPOrigins:     []string{"http://localhost:3000", "http://localhost:8080"},
		},
	}

	authService, err := auth.NewService(ctx, db, pool, appCfg)
	if err != nil {
		t.Fatalf("auth.NewService() error = %v", err)
	}

	sessions := scs.New()
	sessions.Store = pgxstore.NewWithCleanupInterval(pool, 0)
	sessions.Cookie.Name = appCfg.Session.CookieName
	sessions.Cookie.HttpOnly = true
	sessions.Lifetime = appCfg.Session.Lifetime
	sessions.IdleTimeout = appCfg.Session.IdleTimeout

	loginLimiter := ratelimit.New(pool, "public", ratelimit.BucketConfig{
		Capacity:        5,
		RefillPerSecond: 1.0 / 60.0,
		CostPerRequest:  1,
		DenyRetryFloor:  time.Second,
	})
	if err := loginLimiter.Init(ctx); err != nil {
		t.Fatalf("loginLimiter.Init() error = %v", err)
	}

	handler := httpapi.NewRouter(db, sessions, authService, loginLimiter, appCfg)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return &integrationEnv{
		db:          db,
		pool:        pool,
		server:      server,
		queries:     sqlc.New(db),
		authService: authService,
	}
}
