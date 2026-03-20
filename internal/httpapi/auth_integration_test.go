package httpapi_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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
	if err := json.Unmarshal([]byte(emails[0].Payload), &emailPayload); err != nil {
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
	if err := json.Unmarshal([]byte(emails[0].Payload), &emailPayload); err != nil {
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
	if err := json.Unmarshal([]byte(emails[0].Payload), &emailPayload); err != nil {
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

func TestFailedPasswordLoginsUseUserCounterForLockout(t *testing.T) {
	ctx := context.Background()
	env := newIntegrationEnv(t, ctx)

	user, err := env.queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "lockout-user", Email: "lockout@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	passwordHash, err := auth.HashPassword("CorrectPassword123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if _, err := env.queries.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: user.ID, PasswordHash: passwordHash}); err != nil {
		t.Fatalf("UpsertPasswordCredential() error = %v", err)
	}

	if _, err := env.db.ExecContext(ctx, `
		UPDATE users
		SET email_verified_at = NOW()
		WHERE id = $1
	`, user.ID); err != nil {
		t.Fatalf("verify user for setup: %v", err)
	}

	for attempt := 1; attempt <= 5; attempt++ {
		_, err := env.authService.LoginWithPassword(ctx, auth.LoginInput{
			Identifier: user.Email,
			Password:   "WrongPassword123",
			IPAddress:  "203.0.113.10",
			UserAgent:  "integration-test",
		})
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("attempt %d LoginWithPassword() error = %v, want %v", attempt, err, auth.ErrInvalidCredentials)
		}
	}

	updatedUser, err := env.queries.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if updatedUser.FailedLoginCount != 5 {
		t.Fatalf("failed_login_count = %d, want 5", updatedUser.FailedLoginCount)
	}
	if !updatedUser.LockedUntil.Valid {
		t.Fatal("expected user to be locked after reaching failed login threshold")
	}
	if !updatedUser.DisabledReason.Valid || updatedUser.DisabledReason.String != "failed_login_attempts" {
		t.Fatalf("disabled_reason = %q, want %q", updatedUser.DisabledReason.String, "failed_login_attempts")
	}
}

func TestPasswordLoginPersistsSessionForAuthenticatedRoutes(t *testing.T) {
	ctx := context.Background()
	env := newIntegrationEnv(t, ctx)

	user, err := env.queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "session-user", Email: "session@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	passwordHash, err := auth.HashPassword("CorrectPassword123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if _, err := env.queries.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: user.ID, PasswordHash: passwordHash}); err != nil {
		t.Fatalf("UpsertPasswordCredential() error = %v", err)
	}

	if _, err := env.db.ExecContext(ctx, `
		UPDATE users
		SET email_verified_at = NOW()
		WHERE id = $1
	`, user.ID); err != nil {
		t.Fatalf("verify user for setup: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{Jar: jar}

	loginBody, err := json.Marshal(map[string]string{
		"identifier": user.Email,
		"password":   "CorrectPassword123",
	})
	if err != nil {
		t.Fatalf("json.Marshal(login payload) error = %v", err)
	}

	loginReq, err := http.NewRequestWithContext(ctx, http.MethodPost, env.server.URL+"/api/v1/auth/login", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("http.NewRequestWithContext(login) error = %v", err)
	}
	loginReq.Header.Set("Content-Type", "application/json")

	loginResp, err := client.Do(loginReq)
	if err != nil {
		t.Fatalf("client.Do(login) error = %v", err)
	}
	defer func() { _ = loginResp.Body.Close() }()
	if loginResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("login status = %d, want %d, body = %s", loginResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	meReq, err := http.NewRequestWithContext(ctx, http.MethodGet, env.server.URL+"/api/v1/auth/me", nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext(me) error = %v", err)
	}

	meResp, err := client.Do(meReq)
	if err != nil {
		t.Fatalf("client.Do(me) error = %v", err)
	}
	defer func() { _ = meResp.Body.Close() }()
	if meResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(meResp.Body)
		t.Fatalf("me status = %d, want %d, body = %s", meResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	var body struct {
		Data struct {
			User struct {
				UserID   int64  `json:"user_id"`
				Username string `json:"username"`
				Email    string `json:"email"`
			} `json:"user"`
		} `json:"data"`
	}
	if err := json.NewDecoder(meResp.Body).Decode(&body); err != nil {
		t.Fatalf("json.NewDecoder(me body).Decode() error = %v", err)
	}
	if body.Data.User.UserID != user.ID {
		t.Fatalf("me user_id = %d, want %d", body.Data.User.UserID, user.ID)
	}
	if body.Data.User.Email != user.Email {
		t.Fatalf("me email = %q, want %q", body.Data.User.Email, user.Email)
	}
	if body.Data.User.Username != user.Username {
		t.Fatalf("me username = %q, want %q", body.Data.User.Username, user.Username)
	}
}

func TestOAuthSignupCreatesUserAndPersistsSession(t *testing.T) {
	ctx := context.Background()
	env := newIntegrationEnv(t, ctx)
	client := newCookieClient(t)

	startResp := mustDoRequest(t, client, newRequest(t, ctx, http.MethodGet, env.server.URL+"/api/v1/auth/oauth/test/start", nil))
	defer func() { _ = startResp.Body.Close() }()
	if startResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(startResp.Body)
		t.Fatalf("oauth start status = %d, want %d, body = %s", startResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	var startBody struct {
		Data struct {
			AuthorizationURL string `json:"authorization_url"`
			Mode             string `json:"mode"`
		} `json:"data"`
	}
	if err := json.NewDecoder(startResp.Body).Decode(&startBody); err != nil {
		t.Fatalf("decode oauth start response: %v", err)
	}
	if startBody.Data.Mode != "login" {
		t.Fatalf("oauth start mode = %q, want %q", startBody.Data.Mode, "login")
	}

	authorizationURL, err := url.Parse(startBody.Data.AuthorizationURL)
	if err != nil {
		t.Fatalf("url.Parse(authorization_url) error = %v", err)
	}
	state := authorizationURL.Query().Get("state")
	if state == "" {
		t.Fatal("expected oauth state in authorization URL")
	}
	if authorizationURL.Query().Get("code_challenge") == "" {
		t.Fatal("expected pkce code challenge in authorization URL")
	}

	code := env.oauthProvider.issueCode(oauthProviderProfile{
		Subject:       "oauth-signup-user",
		Email:         "oauth-signup@example.com",
		EmailVerified: true,
		Username:      "oauthsignup",
		Name:          "OAuth Signup",
	})

	callbackURL := env.server.URL + "/api/v1/auth/oauth/test/callback?state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(code)
	callbackResp := mustDoRequest(t, client, newRequest(t, ctx, http.MethodGet, callbackURL, nil))
	defer func() { _ = callbackResp.Body.Close() }()
	if callbackResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(callbackResp.Body)
		t.Fatalf("oauth callback status = %d, want %d, body = %s", callbackResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	var callbackBody struct {
		Data struct {
			User struct {
				UserID   int64  `json:"user_id"`
				Email    string `json:"email"`
				Username string `json:"username"`
			} `json:"user"`
			Provider string `json:"provider"`
			Mode     string `json:"mode"`
			Created  bool   `json:"created"`
			Linked   bool   `json:"linked"`
		} `json:"data"`
	}
	if err := json.NewDecoder(callbackResp.Body).Decode(&callbackBody); err != nil {
		t.Fatalf("decode oauth callback response: %v", err)
	}
	if !callbackBody.Data.Created {
		t.Fatal("expected oauth signup to create a user")
	}
	if callbackBody.Data.Linked {
		t.Fatal("expected oauth signup response to report linked=false")
	}
	if callbackBody.Data.Provider != "test" {
		t.Fatalf("oauth provider = %q, want %q", callbackBody.Data.Provider, "test")
	}
	if callbackBody.Data.User.Email != "oauth-signup@example.com" {
		t.Fatalf("oauth callback email = %q, want %q", callbackBody.Data.User.Email, "oauth-signup@example.com")
	}

	meResp := mustDoRequest(t, client, newRequest(t, ctx, http.MethodGet, env.server.URL+"/api/v1/auth/me", nil))
	defer func() { _ = meResp.Body.Close() }()
	if meResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(meResp.Body)
		t.Fatalf("oauth me status = %d, want %d, body = %s", meResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	createdUser, err := env.queries.GetUserByEmail(ctx, "oauth-signup@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail() error = %v", err)
	}
	if !createdUser.EmailVerifiedAt.Valid {
		t.Fatal("expected oauth signup to verify the user email")
	}

	account, err := env.queries.GetOAuthAccountByProviderIdentity(ctx, sqlc.GetOAuthAccountByProviderIdentityParams{Provider: "test", ProviderUserID: "oauth-signup-user"})
	if err != nil {
		t.Fatalf("GetOAuthAccountByProviderIdentity() error = %v", err)
	}
	if account.UserID != createdUser.ID {
		t.Fatalf("oauth account user_id = %d, want %d", account.UserID, createdUser.ID)
	}
	if len(account.AccessTokenCiphertext) == 0 {
		t.Fatal("expected encrypted oauth access token to be stored")
	}
	if len(account.RefreshTokenCiphertext) == 0 {
		t.Fatal("expected encrypted oauth refresh token to be stored")
	}
}

func TestOAuthLoginUsesExistingLinkedAccount(t *testing.T) {
	ctx := context.Background()
	env := newIntegrationEnv(t, ctx)

	firstClient := newCookieClient(t)
	firstUserID := completeOAuthFlowForTest(t, ctx, env, firstClient, oauthProviderProfile{
		Subject:       "oauth-existing-user",
		Email:         "oauth-existing@example.com",
		EmailVerified: true,
		Username:      "oauthexisting",
		Name:          "OAuth Existing",
	})

	secondClient := newCookieClient(t)
	secondUserID := completeOAuthFlowForTest(t, ctx, env, secondClient, oauthProviderProfile{
		Subject:       "oauth-existing-user",
		Email:         "oauth-existing@example.com",
		EmailVerified: true,
		Username:      "oauthexisting",
		Name:          "OAuth Existing",
	})

	if secondUserID != firstUserID {
		t.Fatalf("oauth login user_id = %d, want %d", secondUserID, firstUserID)
	}

	meResp := mustDoRequest(t, secondClient, newRequest(t, ctx, http.MethodGet, env.server.URL+"/api/v1/auth/me", nil))
	defer func() { _ = meResp.Body.Close() }()
	if meResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(meResp.Body)
		t.Fatalf("oauth me status = %d, want %d, body = %s", meResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}
}

func TestOAuthLinkAddsProviderToCurrentUser(t *testing.T) {
	ctx := context.Background()
	env := newIntegrationEnv(t, ctx)

	user, err := env.queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "oauth-link-user", Email: "oauth-link@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	passwordHash, err := auth.HashPassword("LinkedPassword123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if _, err := env.queries.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: user.ID, PasswordHash: passwordHash}); err != nil {
		t.Fatalf("UpsertPasswordCredential() error = %v", err)
	}
	if err := env.queries.MarkUserEmailVerified(ctx, user.ID); err != nil {
		t.Fatalf("MarkUserEmailVerified() error = %v", err)
	}
	role, err := env.queries.GetRoleByName(ctx, "user")
	if err != nil {
		t.Fatalf("GetRoleByName() error = %v", err)
	}
	if err := env.queries.AddUserRole(ctx, sqlc.AddUserRoleParams{UserID: user.ID, RoleID: role.ID}); err != nil {
		t.Fatalf("AddUserRole() error = %v", err)
	}

	client := newCookieClient(t)
	loginBody, err := json.Marshal(map[string]string{
		"identifier": user.Email,
		"password":   "LinkedPassword123",
	})
	if err != nil {
		t.Fatalf("json.Marshal(login payload) error = %v", err)
	}
	loginResp := mustDoRequest(t, client, newRequest(t, ctx, http.MethodPost, env.server.URL+"/api/v1/auth/login", bytes.NewReader(loginBody), withJSONContentType()))
	defer func() { _ = loginResp.Body.Close() }()
	if loginResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("password login status = %d, want %d, body = %s", loginResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	startResp := mustDoRequest(t, client, newRequest(t, ctx, http.MethodGet, env.server.URL+"/api/v1/auth/oauth/test/start", nil))
	defer func() { _ = startResp.Body.Close() }()
	if startResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(startResp.Body)
		t.Fatalf("oauth start status = %d, want %d, body = %s", startResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	var startBody struct {
		Data struct {
			AuthorizationURL string `json:"authorization_url"`
			Mode             string `json:"mode"`
		} `json:"data"`
	}
	if err := json.NewDecoder(startResp.Body).Decode(&startBody); err != nil {
		t.Fatalf("decode oauth start response: %v", err)
	}
	if startBody.Data.Mode != testOAuthModeLink {
		t.Fatalf("oauth start mode = %q, want %q", startBody.Data.Mode, testOAuthModeLink)
	}
	authorizationURL, err := url.Parse(startBody.Data.AuthorizationURL)
	if err != nil {
		t.Fatalf("url.Parse(authorization_url) error = %v", err)
	}

	code := env.oauthProvider.issueCode(oauthProviderProfile{
		Subject:       "oauth-linked-provider-user",
		Email:         "provider-only@example.com",
		EmailVerified: true,
		Username:      "providerlink",
		Name:          "Provider Link",
	})
	callbackURL := env.server.URL + "/api/v1/auth/oauth/test/callback?state=" + url.QueryEscape(authorizationURL.Query().Get("state")) + "&code=" + url.QueryEscape(code)
	callbackResp := mustDoRequest(t, client, newRequest(t, ctx, http.MethodGet, callbackURL, nil))
	defer func() { _ = callbackResp.Body.Close() }()
	if callbackResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(callbackResp.Body)
		t.Fatalf("oauth link callback status = %d, want %d, body = %s", callbackResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	var callbackBody struct {
		Data struct {
			User struct {
				UserID int64 `json:"user_id"`
			} `json:"user"`
			Mode   string `json:"mode"`
			Linked bool   `json:"linked"`
		} `json:"data"`
	}
	if err := json.NewDecoder(callbackResp.Body).Decode(&callbackBody); err != nil {
		t.Fatalf("decode oauth link callback response: %v", err)
	}
	if callbackBody.Data.Mode != testOAuthModeLink {
		t.Fatalf("oauth callback mode = %q, want %q", callbackBody.Data.Mode, testOAuthModeLink)
	}
	if !callbackBody.Data.Linked {
		t.Fatal("expected oauth link response to report linked=true")
	}
	if callbackBody.Data.User.UserID != user.ID {
		t.Fatalf("oauth link user_id = %d, want %d", callbackBody.Data.User.UserID, user.ID)
	}

	account, err := env.queries.GetOAuthAccountByProviderIdentity(ctx, sqlc.GetOAuthAccountByProviderIdentityParams{Provider: "test", ProviderUserID: "oauth-linked-provider-user"})
	if err != nil {
		t.Fatalf("GetOAuthAccountByProviderIdentity() error = %v", err)
	}
	if account.UserID != user.ID {
		t.Fatalf("oauth account user_id = %d, want %d", account.UserID, user.ID)
	}
}

func TestOAuthLinkConflictWhenIdentityBelongsToAnotherUser(t *testing.T) {
	ctx := context.Background()
	env := newIntegrationEnv(t, ctx)

	ownerClient := newCookieClient(t)
	ownerUserID := completeOAuthFlowForTest(t, ctx, env, ownerClient, oauthProviderProfile{
		Subject:       "oauth-conflict-user",
		Email:         "oauth-conflict-owner@example.com",
		EmailVerified: true,
		Username:      "oauthowner",
		Name:          "OAuth Owner",
	})

	user, err := env.queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "oauth-conflict-linker", Email: "oauth-conflict-linker@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	passwordHash, err := auth.HashPassword("LinkedPassword123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if _, err := env.queries.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: user.ID, PasswordHash: passwordHash}); err != nil {
		t.Fatalf("UpsertPasswordCredential() error = %v", err)
	}
	if err := env.queries.MarkUserEmailVerified(ctx, user.ID); err != nil {
		t.Fatalf("MarkUserEmailVerified() error = %v", err)
	}
	role, err := env.queries.GetRoleByName(ctx, "user")
	if err != nil {
		t.Fatalf("GetRoleByName() error = %v", err)
	}
	if err := env.queries.AddUserRole(ctx, sqlc.AddUserRoleParams{UserID: user.ID, RoleID: role.ID}); err != nil {
		t.Fatalf("AddUserRole() error = %v", err)
	}

	client := newCookieClient(t)
	loginBody, err := json.Marshal(map[string]string{
		"identifier": user.Email,
		"password":   "LinkedPassword123",
	})
	if err != nil {
		t.Fatalf("json.Marshal(login payload) error = %v", err)
	}
	loginResp := mustDoRequest(t, client, newRequest(t, ctx, http.MethodPost, env.server.URL+"/api/v1/auth/login", bytes.NewReader(loginBody), withJSONContentType()))
	defer func() { _ = loginResp.Body.Close() }()
	if loginResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("password login status = %d, want %d, body = %s", loginResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	startResp := mustDoRequest(t, client, newRequest(t, ctx, http.MethodGet, env.server.URL+"/api/v1/auth/oauth/test/start", nil))
	defer func() { _ = startResp.Body.Close() }()
	if startResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(startResp.Body)
		t.Fatalf("oauth start status = %d, want %d, body = %s", startResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	var startBody struct {
		Data struct {
			AuthorizationURL string `json:"authorization_url"`
			Mode             string `json:"mode"`
		} `json:"data"`
	}
	if err := json.NewDecoder(startResp.Body).Decode(&startBody); err != nil {
		t.Fatalf("decode oauth start response: %v", err)
	}
	if startBody.Data.Mode != testOAuthModeLink {
		t.Fatalf("oauth start mode = %q, want %q", startBody.Data.Mode, testOAuthModeLink)
	}

	authorizationURL, err := url.Parse(startBody.Data.AuthorizationURL)
	if err != nil {
		t.Fatalf("url.Parse(authorization_url) error = %v", err)
	}

	code := env.oauthProvider.issueCode(oauthProviderProfile{
		Subject:       "oauth-conflict-user",
		Email:         "oauth-conflict-owner@example.com",
		EmailVerified: true,
		Username:      "oauthowner",
		Name:          "OAuth Owner",
	})
	callbackURL := env.server.URL + "/api/v1/auth/oauth/test/callback?state=" + url.QueryEscape(authorizationURL.Query().Get("state")) + "&code=" + url.QueryEscape(code)
	callbackResp := mustDoRequest(t, client, newRequest(t, ctx, http.MethodGet, callbackURL, nil))
	defer func() { _ = callbackResp.Body.Close() }()
	if callbackResp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(callbackResp.Body)
		t.Fatalf("oauth link conflict status = %d, want %d, body = %s", callbackResp.StatusCode, http.StatusConflict, strings.TrimSpace(string(body)))
	}

	var errorBody struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(callbackResp.Body).Decode(&errorBody); err != nil {
		t.Fatalf("decode oauth conflict response: %v", err)
	}
	if errorBody.Error.Code != "oauth_conflict" {
		t.Fatalf("oauth conflict error code = %q, want %q", errorBody.Error.Code, "oauth_conflict")
	}

	account, err := env.queries.GetOAuthAccountByProviderIdentity(ctx, sqlc.GetOAuthAccountByProviderIdentityParams{Provider: "test", ProviderUserID: "oauth-conflict-user"})
	if err != nil {
		t.Fatalf("GetOAuthAccountByProviderIdentity() error = %v", err)
	}
	if account.UserID != ownerUserID {
		t.Fatalf("oauth account user_id = %d, want %d", account.UserID, ownerUserID)
	}
	if account.UserID == user.ID {
		t.Fatal("expected oauth account to remain linked to the original user")
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
	db            *sql.DB
	pool          *pgxpool.Pool
	server        *httptest.Server
	queries       *sqlc.Queries
	authService   *auth.Service
	oauthProvider *oauthTestProvider
}

func newIntegrationEnv(t *testing.T, ctx context.Context) *integrationEnv {
	t.Helper()

	oauthProvider := newOAuthTestProvider(t)

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
		OAuth: config.OAuthConfig{
			StateTTL:          10 * time.Minute,
			StateBytes:        32,
			PKCEVerifierBytes: 32,
			Providers: map[string]config.OAuthProviderConfig{
				"test": {
					Enabled:      true,
					ClientID:     "client-id",
					ClientSecret: "client-secret",
					AuthURL:      oauthProvider.server.URL + "/oauth/authorize",
					TokenURL:     oauthProvider.server.URL + "/oauth/token",
					UserInfoURL:  oauthProvider.server.URL + "/userinfo",
					RedirectURL:  "http://app.local/api/v1/auth/oauth/test/callback",
					Scopes:       []string{"openid", "email", "profile"},
				},
			},
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
		db:            db,
		pool:          pool,
		server:        server,
		queries:       sqlc.New(db),
		authService:   authService,
		oauthProvider: oauthProvider,
	}
}

type oauthProviderProfile struct {
	Subject       string
	Email         string
	EmailVerified bool
	Username      string
	Name          string
}

const testOAuthModeLink = "link"

type oauthTestProvider struct {
	server       *httptest.Server
	mu           sync.Mutex
	authorizeMap map[string]oauthProviderProfile
	tokenMap     map[string]oauthProviderProfile
}

func newOAuthTestProvider(t *testing.T) *oauthTestProvider {
	t.Helper()

	provider := &oauthTestProvider{
		authorizeMap: map[string]oauthProviderProfile{},
		tokenMap:     map[string]oauthProviderProfile{},
	}
	provider.server = httptest.NewServer(http.HandlerFunc(provider.serveHTTP))
	t.Cleanup(provider.server.Close)
	return provider
}

func (provider *oauthTestProvider) issueCode(profile oauthProviderProfile) string {
	provider.mu.Lock()
	defer provider.mu.Unlock()

	plain, _, err := auth.NewToken()
	if err != nil {
		panic(err)
	}
	provider.authorizeMap[plain] = profile
	return plain
}

func (provider *oauthTestProvider) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/oauth/authorize":
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		code := provider.issueCode(oauthProviderProfile{
			Subject:       "authorize-flow-user",
			Email:         "authorize-flow@example.com",
			EmailVerified: true,
			Username:      "authorizeflow",
			Name:          "Authorize Flow",
		})
		redirectTo := redirectURI + "?state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(code)
		http.Redirect(w, r, redirectTo, http.StatusFound)
	case "/oauth/token":
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			writeOAuthProviderError(w, http.StatusBadRequest, "invalid form")
			return
		}
		code := strings.TrimSpace(r.Form.Get("code"))
		if code == "" || strings.TrimSpace(r.Form.Get("code_verifier")) == "" {
			writeOAuthProviderError(w, http.StatusBadRequest, "missing code or verifier")
			return
		}

		provider.mu.Lock()
		profile, ok := provider.authorizeMap[code]
		if ok {
			delete(provider.authorizeMap, code)
		}
		provider.mu.Unlock()
		if !ok {
			writeOAuthProviderError(w, http.StatusBadRequest, "unknown code")
			return
		}

		accessToken := "access-" + code
		provider.mu.Lock()
		provider.tokenMap[accessToken] = profile
		provider.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  accessToken,
			"refresh_token": "refresh-" + code,
			"expires_in":    3600,
			"token_type":    "Bearer",
		})
	case "/userinfo":
		token := strings.TrimPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ")
		provider.mu.Lock()
		profile, ok := provider.tokenMap[token]
		provider.mu.Unlock()
		if !ok {
			writeOAuthProviderError(w, http.StatusUnauthorized, "unknown token")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":                profile.Subject,
			"email":              profile.Email,
			"email_verified":     profile.EmailVerified,
			"preferred_username": profile.Username,
			"name":               profile.Name,
		})
	default:
		http.NotFound(w, r)
	}
}

func writeOAuthProviderError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func completeOAuthFlowForTest(t *testing.T, ctx context.Context, env *integrationEnv, client *http.Client, profile oauthProviderProfile) int64 {
	t.Helper()

	startResp := mustDoRequest(t, client, newRequest(t, ctx, http.MethodGet, env.server.URL+"/api/v1/auth/oauth/test/start", nil))
	defer func() { _ = startResp.Body.Close() }()
	if startResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(startResp.Body)
		t.Fatalf("oauth start status = %d, want %d, body = %s", startResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	var startBody struct {
		Data struct {
			AuthorizationURL string `json:"authorization_url"`
		} `json:"data"`
	}
	if err := json.NewDecoder(startResp.Body).Decode(&startBody); err != nil {
		t.Fatalf("decode oauth start response: %v", err)
	}
	authorizationURL, err := url.Parse(startBody.Data.AuthorizationURL)
	if err != nil {
		t.Fatalf("url.Parse(authorization_url) error = %v", err)
	}

	code := env.oauthProvider.issueCode(profile)
	callbackURL := env.server.URL + "/api/v1/auth/oauth/test/callback?state=" + url.QueryEscape(authorizationURL.Query().Get("state")) + "&code=" + url.QueryEscape(code)
	callbackResp := mustDoRequest(t, client, newRequest(t, ctx, http.MethodGet, callbackURL, nil))
	defer func() { _ = callbackResp.Body.Close() }()
	if callbackResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(callbackResp.Body)
		t.Fatalf("oauth callback status = %d, want %d, body = %s", callbackResp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	var callbackBody struct {
		Data struct {
			User struct {
				UserID int64 `json:"user_id"`
			} `json:"user"`
		} `json:"data"`
	}
	if err := json.NewDecoder(callbackResp.Body).Decode(&callbackBody); err != nil {
		t.Fatalf("decode oauth callback response: %v", err)
	}
	return callbackBody.Data.User.UserID
}

func newCookieClient(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	return &http.Client{Jar: jar}
}

type requestOption func(*http.Request)

func withJSONContentType() requestOption {
	return func(req *http.Request) {
		req.Header.Set("Content-Type", "application/json")
	}
}

func newRequest(t *testing.T, ctx context.Context, method string, endpoint string, body io.Reader, options ...requestOption) *http.Request {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v", err)
	}
	for _, option := range options {
		option(req)
	}
	return req
}

func mustDoRequest(t *testing.T, client *http.Client, req *http.Request) *http.Response {
	t.Helper()

	//nolint:gosec // Test helper only issues requests to in-process httptest servers and controlled local providers.
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	return resp
}
