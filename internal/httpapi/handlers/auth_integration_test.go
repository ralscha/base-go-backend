package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"base/internal/auth"
	"base/internal/config"
	"base/internal/database"
	"base/internal/store/sqlc"
	"base/internal/testutil"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
)

func TestLogoutDestroysSession(t *testing.T) {
	sessions := scs.New()
	handler := AuthHandler{Sessions: sessions}
	mux := http.NewServeMux()
	mux.HandleFunc("/seed", func(w http.ResponseWriter, r *http.Request) {
		sessions.Put(r.Context(), "user_id", int64(42))
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"user_id": sessions.GetInt64(r.Context(), "user_id")})
	})
	mux.HandleFunc("/logout", handler.Logout)
	server := httptest.NewServer(sessions.LoadAndSave(mux))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{Jar: jar}

	seedResp, err := client.Get(server.URL + "/seed")
	if err != nil {
		t.Fatalf("GET /seed error = %v", err)
	}
	_ = seedResp.Body.Close()

	checkUserID := func() float64 {
		t.Helper()
		resp, err := client.Get(server.URL + "/check")
		if err != nil {
			t.Fatalf("GET /check error = %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		var payload envelope
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			t.Fatalf("Decode(/check) error = %v", err)
		}
		data := payload.Data.(map[string]any)
		return data["user_id"].(float64)
	}

	if got := checkUserID(); got != 42 {
		t.Fatalf("seeded user_id = %v, want 42", got)
	}

	logoutResp, err := client.Get(server.URL + "/logout")
	if err != nil {
		t.Fatalf("GET /logout error = %v", err)
	}
	defer func() { _ = logoutResp.Body.Close() }()
	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d, want %d", logoutResp.StatusCode, http.StatusOK)
	}

	var logoutPayload envelope
	if err := json.NewDecoder(logoutResp.Body).Decode(&logoutPayload); err != nil {
		t.Fatalf("Decode(/logout) error = %v", err)
	}
	if logoutPayload.Data.(map[string]any)["logged_out"] != true {
		t.Fatalf("logout payload = %+v, want logged_out=true", logoutPayload)
	}

	if got := checkUserID(); got != 0 {
		t.Fatalf("user_id after logout = %v, want 0", got)
	}
}

func TestMeUnauthorizedWithoutSession(t *testing.T) {
	sessions := scs.New()
	handler := AuthHandler{Service: nil, Sessions: sessions}
	server := httptest.NewServer(sessions.LoadAndSave(http.HandlerFunc(handler.Me)))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("GET /me error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestMeReturnsCurrentUser(t *testing.T) {
	ctx := context.Background()
	_, queries, service := newHandlerAuthTestEnv(t, ctx)

	user, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "me-user", Email: "me@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	role, err := queries.GetRoleByName(ctx, "user")
	if err != nil {
		t.Fatalf("GetRoleByName() error = %v", err)
	}
	if err := queries.AddUserRole(ctx, sqlc.AddUserRoleParams{UserID: user.ID, RoleID: role.ID}); err != nil {
		t.Fatalf("AddUserRole() error = %v", err)
	}
	if _, err := queries.UpsertTotpConfiguration(ctx, sqlc.UpsertTotpConfigurationParams{
		UserID:           user.ID,
		SecretCiphertext: []byte("ciphertext"),
		SecretNonce:      []byte("nonce"),
		EnabledAt:        sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}); err != nil {
		t.Fatalf("UpsertTotpConfiguration() error = %v", err)
	}

	sessions := scs.New()
	handler := AuthHandler{Service: service, Sessions: sessions}
	server := httptest.NewServer(sessions.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions.Put(r.Context(), "user_id", user.ID)
		handler.Me(w, r)
	})))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("GET /me error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var payload envelope
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("Decode(/me) error = %v", err)
	}
	userPayload := payload.Data.(map[string]any)["user"].(map[string]any)
	if userPayload["username"] != "me-user" || userPayload["email"] != "me@example.com" {
		t.Fatalf("user payload = %+v, want current user identity", userPayload)
	}
	if userPayload["totp_enabled"] != true {
		t.Fatalf("user payload = %+v, want totp_enabled=true", userPayload)
	}
	roles := userPayload["roles"].([]any)
	if len(roles) != 1 || roles[0] != "user" {
		t.Fatalf("roles = %v, want [user]", roles)
	}
}

func TestVerifyEmailSuccess(t *testing.T) {
	ctx := context.Background()
	_, queries, service := newHandlerAuthTestEnv(t, ctx)

	user, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "verify-handler", Email: "verify-handler@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	plainToken, tokenHash, err := auth.NewToken()
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
	if _, err := queries.CreateUserToken(ctx, sqlc.CreateUserTokenParams{UserID: user.ID, Kind: sqlc.TokenKindEmailVerification, TokenHash: tokenHash, ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatalf("CreateUserToken() error = %v", err)
	}

	handler := AuthHandler{Service: service}
	req := httptest.NewRequest(http.MethodGet, "/verify-email?token="+plainToken, nil)
	recorder := httptest.NewRecorder()
	handler.VerifyEmail(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var payload envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Data.(map[string]any)["verified"] != true {
		t.Fatalf("payload = %+v, want verified=true", payload)
	}
}

func TestRequestPasswordResetAcceptedAndEnqueuesEmail(t *testing.T) {
	ctx := context.Background()
	_, queries, service := newHandlerAuthTestEnv(t, ctx)

	user, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "reset-handler", Email: "reset-handler@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	handler := AuthHandler{Service: service}
	req := httptest.NewRequest(http.MethodPost, "/password-reset/request", strings.NewReader(`{"email":"`+user.Email+`"}`))
	recorder := httptest.NewRecorder()
	handler.RequestPasswordReset(recorder, req)

	if recorder.Code != http.StatusAccepted {
		body, _ := io.ReadAll(recorder.Body)
		t.Fatalf("status = %d, want %d, body=%s", recorder.Code, http.StatusAccepted, string(body))
	}
	var payload envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Data.(map[string]any)["requested"] != true {
		t.Fatalf("payload = %+v, want requested=true", payload)
	}

	emails, err := queries.ListPendingEmails(ctx, 10)
	if err != nil {
		t.Fatalf("ListPendingEmails() error = %v", err)
	}
	if len(emails) != 1 || emails[0].Template != "password-reset" || emails[0].Recipient != user.Email {
		t.Fatalf("emails = %+v, want one password-reset email", emails)
	}
}

func TestRequestPasswordResetAcceptedForUnknownEmail(t *testing.T) {
	ctx := context.Background()
	_, queries, service := newHandlerAuthTestEnv(t, ctx)

	handler := AuthHandler{Service: service}
	req := httptest.NewRequest(http.MethodPost, "/password-reset/request", strings.NewReader(`{"email":"missing@example.com"}`))
	recorder := httptest.NewRecorder()
	handler.RequestPasswordReset(recorder, req)

	if recorder.Code != http.StatusAccepted {
		body, _ := io.ReadAll(recorder.Body)
		t.Fatalf("status = %d, want %d, body=%s", recorder.Code, http.StatusAccepted, string(body))
	}
	var payload envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Data.(map[string]any)["requested"] != true {
		t.Fatalf("payload = %+v, want requested=true", payload)
	}

	emails, err := queries.ListPendingEmails(ctx, 10)
	if err != nil {
		t.Fatalf("ListPendingEmails() error = %v", err)
	}
	if len(emails) != 0 {
		t.Fatalf("emails = %+v, want no queued emails", emails)
	}
}

func TestRegisterAndLoginFlow(t *testing.T) {
	ctx := context.Background()
	_, queries, service := newHandlerAuthTestEnv(t, ctx)

	sessions := scs.New()
	handler := AuthHandler{Service: service, Sessions: sessions, LoginRateLimiter: service.RateLimiter()}
	mux := http.NewServeMux()
	mux.HandleFunc("/register", handler.Register)
	mux.HandleFunc("/login", handler.Login)
	mux.HandleFunc("/me", handler.Me)
	server := httptest.NewServer(sessions.LoadAndSave(mux))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{Jar: jar}

	registerResp, err := client.Post(server.URL+"/register", "application/json", strings.NewReader(`{"username":"handler-user","email":"handler-user@example.com","password":"ValidPassword123"}`))
	if err != nil {
		t.Fatalf("POST /register error = %v", err)
	}
	defer func() { _ = registerResp.Body.Close() }()
	if registerResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(registerResp.Body)
		t.Fatalf("register status = %d, want %d, body=%s", registerResp.StatusCode, http.StatusCreated, string(body))
	}

	var registerPayload envelope
	if err := json.NewDecoder(registerResp.Body).Decode(&registerPayload); err != nil {
		t.Fatalf("Decode(/register) error = %v", err)
	}
	userPayload := registerPayload.Data.(map[string]any)["user"].(map[string]any)
	if userPayload["username"] != "handler-user" || userPayload["email"] != "handler-user@example.com" {
		t.Fatalf("register payload = %+v, want normalized user identity", registerPayload)
	}

	user, err := queries.GetUserByEmail(ctx, "handler-user@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail() error = %v", err)
	}
	if err := queries.MarkUserEmailVerified(ctx, user.ID); err != nil {
		t.Fatalf("MarkUserEmailVerified() error = %v", err)
	}
	emails, err := queries.ListPendingEmails(ctx, 10)
	if err != nil {
		t.Fatalf("ListPendingEmails() error = %v", err)
	}
	if len(emails) != 1 || emails[0].Template != "verify-email" {
		t.Fatalf("emails = %+v, want one verify-email message", emails)
	}

	loginResp, err := client.Post(server.URL+"/login", "application/json", strings.NewReader(`{"email":"handler-user@example.com","password":"ValidPassword123"}`))
	if err != nil {
		t.Fatalf("POST /login error = %v", err)
	}
	defer func() { _ = loginResp.Body.Close() }()
	if loginResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("login status = %d, want %d, body=%s", loginResp.StatusCode, http.StatusOK, string(body))
	}

	var loginPayload envelope
	if err := json.NewDecoder(loginResp.Body).Decode(&loginPayload); err != nil {
		t.Fatalf("Decode(/login) error = %v", err)
	}
	loginUser := loginPayload.Data.(map[string]any)["user"].(map[string]any)
	if loginUser["user_id"].(float64) != float64(user.ID) {
		t.Fatalf("login payload = %+v, want logged in user id", loginPayload)
	}

	meResp, err := client.Get(server.URL + "/me")
	if err != nil {
		t.Fatalf("GET /me error = %v", err)
	}
	defer func() { _ = meResp.Body.Close() }()
	if meResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(meResp.Body)
		t.Fatalf("me status = %d, want %d, body=%s", meResp.StatusCode, http.StatusOK, string(body))
	}

	var mePayload envelope
	if err := json.NewDecoder(meResp.Body).Decode(&mePayload); err != nil {
		t.Fatalf("Decode(/me) error = %v", err)
	}
	meUser := mePayload.Data.(map[string]any)["user"].(map[string]any)
	if meUser["email"] != "handler-user@example.com" {
		t.Fatalf("me payload = %+v, want current session user", mePayload)
	}

}

func TestLoginReturnsTOTPRequired(t *testing.T) {
	ctx := context.Background()
	_, queries, service := newHandlerAuthTestEnv(t, ctx)

	user, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "login-totp", Email: "login-totp@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	role, err := queries.GetRoleByName(ctx, "user")
	if err != nil {
		t.Fatalf("GetRoleByName() error = %v", err)
	}
	if err := queries.AddUserRole(ctx, sqlc.AddUserRoleParams{UserID: user.ID, RoleID: role.ID}); err != nil {
		t.Fatalf("AddUserRole() error = %v", err)
	}
	hash, err := auth.HashPassword("ValidPassword123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if _, err := queries.SetUserPasswordHash(ctx, sqlc.SetUserPasswordHashParams{ID: user.ID, PasswordHash: sql.NullString{String: hash, Valid: true}}); err != nil {
		t.Fatalf("SetUserPasswordHash() error = %v", err)
	}
	if err := queries.MarkUserEmailVerified(ctx, user.ID); err != nil {
		t.Fatalf("MarkUserEmailVerified() error = %v", err)
	}
	setup, err := service.BeginTOTPSetup(ctx, user.ID)
	if err != nil {
		t.Fatalf("BeginTOTPSetup() error = %v", err)
	}
	code, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode() error = %v", err)
	}
	if err := service.ConfirmTOTPSetup(ctx, user.ID, code); err != nil {
		t.Fatalf("ConfirmTOTPSetup() error = %v", err)
	}

	sessions := scs.New()
	handler := AuthHandler{Service: service, Sessions: sessions, LoginRateLimiter: service.RateLimiter()}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"email":"login-totp@example.com","password":"ValidPassword123"}`))
	handler.Login(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		body, _ := io.ReadAll(recorder.Body)
		t.Fatalf("status = %d, want %d, body=%s", recorder.Code, http.StatusUnauthorized, string(body))
	}
	var payload envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	errorPayload := payload.Error
	if errorPayload == nil || errorPayload.Code != "totp_required" {
		t.Fatalf("payload = %+v, want totp_required error", payload)
	}
}

func TestLoginMasksCredentialAndAccountStateFailures(t *testing.T) {
	testCases := []struct {
		name  string
		setup func(t *testing.T, ctx context.Context, db *sql.DB, queries *sqlc.Queries) (string, string)
	}{
		{
			name: "unknown account",
			setup: func(t *testing.T, ctx context.Context, db *sql.DB, queries *sqlc.Queries) (string, string) {
				t.Helper()
				return "missing@example.com", "WrongPassword123"
			},
		},
		{
			name: "wrong password",
			setup: func(t *testing.T, ctx context.Context, db *sql.DB, queries *sqlc.Queries) (string, string) {
				t.Helper()
				user := createHandlerPasswordUser(t, ctx, queries, "wrong-pass-handler", "wrong-pass-handler@example.com", "ValidPassword123", true)
				return user.Email, "WrongPassword123"
			},
		},
		{
			name: "disabled account",
			setup: func(t *testing.T, ctx context.Context, db *sql.DB, queries *sqlc.Queries) (string, string) {
				t.Helper()
				user := createHandlerPasswordUser(t, ctx, queries, "disabled-handler", "disabled-handler@example.com", "ValidPassword123", true)
				if _, err := db.ExecContext(ctx, `UPDATE users SET is_active = FALSE WHERE id = $1`, user.ID); err != nil {
					t.Fatalf("disable user error = %v", err)
				}
				return user.Email, "ValidPassword123"
			},
		},
		{
			name: "locked account",
			setup: func(t *testing.T, ctx context.Context, db *sql.DB, queries *sqlc.Queries) (string, string) {
				t.Helper()
				user := createHandlerPasswordUser(t, ctx, queries, "locked-handler", "locked-handler@example.com", "ValidPassword123", true)
				if _, err := db.ExecContext(ctx, `UPDATE users SET locked_until = NOW() + INTERVAL '1 hour' WHERE id = $1`, user.ID); err != nil {
					t.Fatalf("lock user error = %v", err)
				}
				return user.Email, "ValidPassword123"
			},
		},
		{
			name: "unverified account",
			setup: func(t *testing.T, ctx context.Context, db *sql.DB, queries *sqlc.Queries) (string, string) {
				t.Helper()
				user := createHandlerPasswordUser(t, ctx, queries, "unverified-handler", "unverified-handler@example.com", "ValidPassword123", false)
				return user.Email, "ValidPassword123"
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			db, queries, service := newHandlerAuthTestEnv(t, ctx)
			email, password := testCase.setup(t, ctx, db, queries)

			sessions := scs.New()
			handler := AuthHandler{Service: service, Sessions: sessions, LoginRateLimiter: service.RateLimiter()}
			server := httptest.NewServer(sessions.LoadAndSave(http.HandlerFunc(handler.Login)))
			defer server.Close()

			resp, err := http.Post(server.URL, "application/json", strings.NewReader(`{"email":"`+email+`","password":"`+password+`"}`))
			if err != nil {
				t.Fatalf("POST /login error = %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusUnauthorized {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusUnauthorized, string(body))
			}

			var payload envelope
			if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
				t.Fatalf("Decode(/login) error = %v", err)
			}
			if payload.Error == nil {
				t.Fatal("payload.Error = nil, want error payload")
			}
			if payload.Error.Code != "invalid_credentials" || payload.Error.Message != standardLoginFailureMessage {
				t.Fatalf("payload.Error = %+v, want code=%q message=%q", payload.Error, "invalid_credentials", standardLoginFailureMessage)
			}
		})
	}
}

func TestStartOAuthInvalidProvider(t *testing.T) {
	ctx := context.Background()
	_, _, service := newHandlerAuthTestEnv(t, ctx)

	sessions := scs.New()
	handler := AuthHandler{Service: service, Sessions: sessions}
	server := httptest.NewServer(sessions.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.StartOAuth(w, withChiURLParam(r, "provider", "missing"))
	})))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("GET /oauth/start error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(resp.Body) error = %v", err)
	}
	assertErrorCode(t, body, "oauth_provider_invalid")
}

func TestCompleteOAuthRequiresValidSessionState(t *testing.T) {
	ctx := context.Background()
	_, _, service := newHandlerAuthTestEnv(t, ctx)

	sessions := scs.New()
	handler := AuthHandler{Service: service, Sessions: sessions}
	server := httptest.NewServer(sessions.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.CompleteOAuth(w, withChiURLParam(r, "provider", "missing"))
	})))
	defer server.Close()

	resp, err := http.Get(server.URL + "?state=abc&code=def")
	if err != nil {
		t.Fatalf("GET /oauth/callback error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(resp.Body) error = %v", err)
	}
	assertErrorCode(t, body, "oauth_state_invalid")
}

func TestBeginPasskeyRegistrationStoresSession(t *testing.T) {
	ctx := context.Background()
	_, queries, service := newHandlerAuthTestEnv(t, ctx)

	user, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "passkey-register", Email: "passkey-register@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	sessions := scs.New()
	handler := AuthHandler{Service: service, Sessions: sessions}
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		sessions.Put(r.Context(), "user_id", user.ID)
		handler.BeginPasskeyRegistration(w, r)
	})
	mux.HandleFunc("/peek", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"session": sessions.GetString(r.Context(), passkeyRegistrationSessionKey)})
	})
	server := httptest.NewServer(sessions.LoadAndSave(mux))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{Jar: jar}

	startResp, err := client.Post(server.URL+"/start", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /start error = %v", err)
	}
	defer func() { _ = startResp.Body.Close() }()
	if startResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(startResp.Body)
		t.Fatalf("start status = %d, want %d, body=%s", startResp.StatusCode, http.StatusOK, string(body))
	}
	var startPayload envelope
	if err := json.NewDecoder(startResp.Body).Decode(&startPayload); err != nil {
		t.Fatalf("Decode(/start) error = %v", err)
	}
	if startPayload.Data.(map[string]any)["options"] == nil {
		t.Fatalf("payload = %+v, want options", startPayload)
	}

	peekResp, err := client.Get(server.URL + "/peek")
	if err != nil {
		t.Fatalf("GET /peek error = %v", err)
	}
	defer func() { _ = peekResp.Body.Close() }()
	var peekPayload envelope
	if err := json.NewDecoder(peekResp.Body).Decode(&peekPayload); err != nil {
		t.Fatalf("Decode(/peek) error = %v", err)
	}
	if strings.TrimSpace(peekPayload.Data.(map[string]any)["session"].(string)) == "" {
		t.Fatalf("peek payload = %+v, want stored registration session", peekPayload)
	}
}

func TestFinishPasskeyRegistrationRequiresSession(t *testing.T) {
	ctx := context.Background()
	_, queries, service := newHandlerAuthTestEnv(t, ctx)

	user, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "passkey-finish", Email: "passkey-finish@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	sessions := scs.New()
	handler := AuthHandler{Service: service, Sessions: sessions}
	server := httptest.NewServer(sessions.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions.Put(r.Context(), "user_id", user.ID)
		handler.FinishPasskeyRegistration(w, r)
	})))
	defer server.Close()

	resp, err := http.Post(server.URL, "application/json", strings.NewReader(`{"credential":{},"name":"Laptop key"}`))
	if err != nil {
		t.Fatalf("POST /finish passkey registration error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(resp.Body) error = %v", err)
	}
	assertErrorCode(t, body, "passkey_ceremony_missing")
}

func TestBeginPasskeyLoginStoresSessionAndFinishRequiresSession(t *testing.T) {
	ctx := context.Background()
	_, _, service := newHandlerAuthTestEnv(t, ctx)

	sessions := scs.New()
	handler := AuthHandler{Service: service, Sessions: sessions}
	mux := http.NewServeMux()
	mux.HandleFunc("/start", handler.BeginPasskeyLogin)
	mux.HandleFunc("/peek", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"session": sessions.GetString(r.Context(), passkeyLoginSessionKey)})
	})
	mux.HandleFunc("/finish", handler.FinishPasskeyLogin)
	server := httptest.NewServer(sessions.LoadAndSave(mux))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{Jar: jar}

	startResp, err := client.Post(server.URL+"/start", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /start error = %v", err)
	}
	defer func() { _ = startResp.Body.Close() }()
	if startResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(startResp.Body)
		t.Fatalf("start status = %d, want %d, body=%s", startResp.StatusCode, http.StatusOK, string(body))
	}
	var startPayload envelope
	if err := json.NewDecoder(startResp.Body).Decode(&startPayload); err != nil {
		t.Fatalf("Decode(/start) error = %v", err)
	}
	if startPayload.Data.(map[string]any)["options"] == nil {
		t.Fatalf("payload = %+v, want options", startPayload)
	}

	peekResp, err := client.Get(server.URL + "/peek")
	if err != nil {
		t.Fatalf("GET /peek error = %v", err)
	}
	defer func() { _ = peekResp.Body.Close() }()
	var peekPayload envelope
	if err := json.NewDecoder(peekResp.Body).Decode(&peekPayload); err != nil {
		t.Fatalf("Decode(/peek) error = %v", err)
	}
	if strings.TrimSpace(peekPayload.Data.(map[string]any)["session"].(string)) == "" {
		t.Fatalf("peek payload = %+v, want stored login session", peekPayload)
	}

	clearReq, err := http.NewRequest(http.MethodGet, server.URL+"/peek", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	_ = clearReq

	blankJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New(blank) error = %v", err)
	}
	blankClient := &http.Client{Jar: blankJar}
	finishResp, err := blankClient.Post(server.URL+"/finish", "application/json", strings.NewReader(`{"credential":{}}`))
	if err != nil {
		t.Fatalf("POST /finish error = %v", err)
	}
	defer func() { _ = finishResp.Body.Close() }()
	if finishResp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(finishResp.Body)
		t.Fatalf("finish status = %d, want %d, body=%s", finishResp.StatusCode, http.StatusBadRequest, string(body))
	}
	body, err := io.ReadAll(finishResp.Body)
	if err != nil {
		t.Fatalf("ReadAll(finishResp.Body) error = %v", err)
	}
	assertErrorCode(t, body, "passkey_ceremony_missing")
}

func TestResetPasswordSuccess(t *testing.T) {
	ctx := context.Background()
	_, queries, service := newHandlerAuthTestEnv(t, ctx)

	user, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "reset-handler-success", Email: "reset-success@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	passwordHash, err := auth.HashPassword("InitialPassword123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if _, err := queries.SetUserPasswordHash(ctx, sqlc.SetUserPasswordHashParams{ID: user.ID, PasswordHash: sql.NullString{String: passwordHash, Valid: true}}); err != nil {
		t.Fatalf("SetUserPasswordHash() error = %v", err)
	}
	plainToken, tokenHash, err := auth.NewToken()
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
	if _, err := queries.CreateUserToken(ctx, sqlc.CreateUserTokenParams{UserID: user.ID, Kind: sqlc.TokenKindPasswordReset, TokenHash: tokenHash, ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatalf("CreateUserToken() error = %v", err)
	}
	handler := AuthHandler{Service: service}
	req := httptest.NewRequest(http.MethodPost, "/password-reset/confirm", strings.NewReader(`{"token":"`+plainToken+`","password":"UpdatedPassword123"}`))
	recorder := httptest.NewRecorder()
	handler.ResetPassword(recorder, req)

	if recorder.Code != http.StatusOK {
		body, _ := io.ReadAll(recorder.Body)
		t.Fatalf("status = %d, want %d, body=%s", recorder.Code, http.StatusOK, string(body))
	}
	var payload envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Data.(map[string]any)["password_reset"] != true {
		t.Fatalf("payload = %+v, want password_reset=true", payload)
	}

	credential, err := queries.GetUserWithPasswordByEmail(ctx, user.Email)
	if err != nil {
		t.Fatalf("GetUserWithPasswordByEmail() error = %v", err)
	}
	match, err := auth.ComparePassword("UpdatedPassword123", credential.PasswordHash.String)
	if err != nil {
		t.Fatalf("ComparePassword() error = %v", err)
	}
	if !match {
		t.Fatal("expected updated password to be stored")
	}
}

func TestTOTPHandlerFlow(t *testing.T) {
	ctx := context.Background()
	_, queries, service := newHandlerAuthTestEnv(t, ctx)

	user, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "totp-handler", Email: "totp-handler@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	sessions := scs.New()
	handler := AuthHandler{Service: service, Sessions: sessions}
	mux := http.NewServeMux()
	mux.HandleFunc("/setup", func(w http.ResponseWriter, r *http.Request) {
		sessions.Put(r.Context(), "user_id", user.ID)
		handler.SetupTOTP(w, r)
	})
	mux.HandleFunc("/enable", func(w http.ResponseWriter, r *http.Request) {
		sessions.Put(r.Context(), "user_id", user.ID)
		handler.EnableTOTP(w, r)
	})
	mux.HandleFunc("/disable", func(w http.ResponseWriter, r *http.Request) {
		sessions.Put(r.Context(), "user_id", user.ID)
		handler.DisableTOTP(w, r)
	})
	server := httptest.NewServer(sessions.LoadAndSave(mux))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{Jar: jar}

	setupResp, err := client.Get(server.URL + "/setup")
	if err != nil {
		t.Fatalf("GET /setup error = %v", err)
	}
	defer func() { _ = setupResp.Body.Close() }()
	if setupResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(setupResp.Body)
		t.Fatalf("setup status = %d, want %d, body=%s", setupResp.StatusCode, http.StatusOK, string(body))
	}
	var setupPayload envelope
	if err := json.NewDecoder(setupResp.Body).Decode(&setupPayload); err != nil {
		t.Fatalf("Decode(/setup) error = %v", err)
	}
	totpPayload := setupPayload.Data.(map[string]any)["totp"].(map[string]any)
	secret := totpPayload["secret"].(string)
	if secret == "" || totpPayload["issuer"] != "base-test" || totpPayload["account"] != user.Email {
		t.Fatalf("setup payload = %+v, want secret/issuer/account", totpPayload)
	}

	code, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode() error = %v", err)
	}
	enableResp, err := client.Post(server.URL+"/enable", "application/json", strings.NewReader(`{"code":"`+code+`"}`))
	if err != nil {
		t.Fatalf("POST /enable error = %v", err)
	}
	defer func() { _ = enableResp.Body.Close() }()
	if enableResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(enableResp.Body)
		t.Fatalf("enable status = %d, want %d, body=%s", enableResp.StatusCode, http.StatusOK, string(body))
	}
	var enablePayload envelope
	if err := json.NewDecoder(enableResp.Body).Decode(&enablePayload); err != nil {
		t.Fatalf("Decode(/enable) error = %v", err)
	}
	if enablePayload.Data.(map[string]any)["totp_enabled"] != true {
		t.Fatalf("enable payload = %+v, want totp_enabled=true", enablePayload)
	}

	configRow, err := queries.GetTotpConfigurationByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetTotpConfigurationByUserID() error = %v", err)
	}
	if !configRow.EnabledAt.Valid {
		t.Fatal("expected TOTP configuration to be enabled")
	}

	disableReq, err := http.NewRequest(http.MethodPost, server.URL+"/disable", nil)
	if err != nil {
		t.Fatalf("NewRequest(/disable) error = %v", err)
	}
	disableResp, err := client.Do(disableReq)
	if err != nil {
		t.Fatalf("POST /disable error = %v", err)
	}
	defer func() { _ = disableResp.Body.Close() }()
	if disableResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(disableResp.Body)
		t.Fatalf("disable status = %d, want %d, body=%s", disableResp.StatusCode, http.StatusOK, string(body))
	}
	var disablePayload envelope
	if err := json.NewDecoder(disableResp.Body).Decode(&disablePayload); err != nil {
		t.Fatalf("Decode(/disable) error = %v", err)
	}
	if disablePayload.Data.(map[string]any)["totp_disabled"] != true {
		t.Fatalf("disable payload = %+v, want totp_disabled=true", disablePayload)
	}
	if _, err := queries.GetTotpConfigurationByUserID(ctx, user.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetTotpConfigurationByUserID() after disable error = %v, want sql.ErrNoRows", err)
	}
}

func TestRequestAccountRecoveryAcceptedAndRecoverAccountSuccess(t *testing.T) {
	ctx := context.Background()
	_, queries, service := newHandlerAuthTestEnv(t, ctx)

	user, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "recover-handler", Email: "recover-handler@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	hash, err := auth.HashPassword("InitialPassword123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if _, err := queries.SetUserPasswordHash(ctx, sqlc.SetUserPasswordHashParams{ID: user.ID, PasswordHash: sql.NullString{String: hash, Valid: true}}); err != nil {
		t.Fatalf("SetUserPasswordHash() error = %v", err)
	}
	if _, err := queries.UpsertTotpConfiguration(ctx, sqlc.UpsertTotpConfigurationParams{UserID: user.ID, SecretCiphertext: []byte("cipher"), SecretNonce: []byte("nonce"), EnabledAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}}); err != nil {
		t.Fatalf("UpsertTotpConfiguration() error = %v", err)
	}

	handler := AuthHandler{Service: service}
	requestResp := httptest.NewRecorder()
	requestReq := httptest.NewRequest(http.MethodPost, "/account-recovery/request", strings.NewReader(`{"email":"`+user.Email+`"}`))
	handler.RequestAccountRecovery(requestResp, requestReq)
	if requestResp.Code != http.StatusAccepted {
		body, _ := io.ReadAll(requestResp.Body)
		t.Fatalf("request status = %d, want %d, body=%s", requestResp.Code, http.StatusAccepted, string(body))
	}

	emails, err := queries.ListPendingEmails(ctx, 10)
	if err != nil {
		t.Fatalf("ListPendingEmails() error = %v", err)
	}
	if len(emails) != 1 || emails[0].Template != "account-recovery" {
		t.Fatalf("emails = %+v, want one account-recovery email", emails)
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(emails[0].Payload), &payload); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	recoverResp := httptest.NewRecorder()
	recoverReq := httptest.NewRequest(http.MethodPost, "/account-recovery/confirm", strings.NewReader(`{"token":"`+payload.Token+`","password":"RecoveredPassword123"}`))
	handler.RecoverAccount(recoverResp, recoverReq)
	if recoverResp.Code != http.StatusOK {
		body, _ := io.ReadAll(recoverResp.Body)
		t.Fatalf("recover status = %d, want %d, body=%s", recoverResp.Code, http.StatusOK, string(body))
	}

	var recoverPayload envelope
	if err := json.Unmarshal(recoverResp.Body.Bytes(), &recoverPayload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	data := recoverPayload.Data.(map[string]any)
	if data["recovered"] != true {
		t.Fatalf("recover payload = %+v, want recovered=true", recoverPayload)
	}
	if _, err := queries.GetTotpConfigurationByUserID(ctx, user.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetTotpConfigurationByUserID() after recover error = %v, want sql.ErrNoRows", err)
	}
	credential, err := queries.GetUserWithPasswordByEmail(ctx, user.Email)
	if err != nil {
		t.Fatalf("GetUserWithPasswordByEmail() error = %v", err)
	}
	match, err := auth.ComparePassword("RecoveredPassword123", credential.PasswordHash.String)
	if err != nil {
		t.Fatalf("ComparePassword() error = %v", err)
	}
	if !match {
		t.Fatal("expected recovered password to be stored")
	}
}

func TestRequestAccountRecoveryAcceptedForUnknownEmail(t *testing.T) {
	ctx := context.Background()
	_, queries, service := newHandlerAuthTestEnv(t, ctx)

	handler := AuthHandler{Service: service}
	requestResp := httptest.NewRecorder()
	requestReq := httptest.NewRequest(http.MethodPost, "/account-recovery/request", strings.NewReader(`{"email":"missing@example.com"}`))
	handler.RequestAccountRecovery(requestResp, requestReq)

	if requestResp.Code != http.StatusAccepted {
		body, _ := io.ReadAll(requestResp.Body)
		t.Fatalf("request status = %d, want %d, body=%s", requestResp.Code, http.StatusAccepted, string(body))
	}
	var payload envelope
	if err := json.Unmarshal(requestResp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Data.(map[string]any)["requested"] != true {
		t.Fatalf("payload = %+v, want requested=true", payload)
	}

	emails, err := queries.ListPendingEmails(ctx, 10)
	if err != nil {
		t.Fatalf("ListPendingEmails() error = %v", err)
	}
	if len(emails) != 0 {
		t.Fatalf("emails = %+v, want no queued emails", emails)
	}
}

func newHandlerAuthTestEnv(t *testing.T, ctx context.Context) (*sql.DB, *sqlc.Queries, *auth.Service) {
	t.Helper()

	databaseURL := testutil.FreshPostgresDatabaseURL(t, ctx)

	dbCfg := config.DatabaseConfig{URL: databaseURL, MaxOpenConns: 5, MaxIdleConns: 2, ConnMaxLifetime: time.Minute, ConnMaxIdleTime: time.Minute}
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

	service, err := auth.NewService(ctx, db, pool, config.Config{
		Database: dbCfg,
		Security: config.SecurityConfig{FailedLoginThreshold: 5, FailedLoginWindow: 15 * time.Minute, EncryptionKey: "0123456789abcdef0123456789abcdef", TOTPIssuer: "base-test", EmailVerificationTTL: time.Hour, PasswordResetTTL: time.Hour, RecoveryTTL: 30 * time.Minute},
		WebAuthn: config.WebAuthnConfig{RPID: "localhost", RPDisplayName: "Base Test", RPOrigins: []string{"http://localhost"}},
		OAuth:    config.OAuthConfig{StateTTL: 10 * time.Minute, StateBytes: 32, PKCEVerifierBytes: 32, Providers: map[string]config.OAuthProviderConfig{}},
	})
	if err != nil {
		t.Fatalf("auth.NewService() error = %v", err)
	}

	return db, sqlc.New(db), service
}

func createHandlerPasswordUser(t *testing.T, ctx context.Context, queries *sqlc.Queries, username, email, password string, verified bool) sqlc.User {
	t.Helper()

	user, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: username, Email: email})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if _, err := queries.SetUserPasswordHash(ctx, sqlc.SetUserPasswordHashParams{ID: user.ID, PasswordHash: sql.NullString{String: hash, Valid: true}}); err != nil {
		t.Fatalf("SetUserPasswordHash() error = %v", err)
	}
	if verified {
		if err := queries.MarkUserEmailVerified(ctx, user.ID); err != nil {
			t.Fatalf("MarkUserEmailVerified() error = %v", err)
		}
	}

	return user
}

func assertHandlerQueryCount(t *testing.T, ctx context.Context, db *sql.DB, query string, want int, args ...any) {
	t.Helper()

	var got int
	if err := db.QueryRowContext(ctx, query, args...).Scan(&got); err != nil {
		t.Fatalf("count query %q error = %v", query, err)
	}
	if got != want {
		t.Fatalf("count query %q = %d, want %d", query, got, want)
	}
}

func assertErrorCode(t *testing.T, body []byte, wantCode string) {
	t.Helper()

	var payload envelope
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Error == nil || payload.Error.Code != wantCode {
		t.Fatalf("payload = %+v, want error code %q", payload, wantCode)
	}
}

func responseHasCookie(resp *http.Response, name string) bool {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return true
		}
	}

	return false
}

func withChiURLParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
