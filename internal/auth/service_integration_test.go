package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"base/internal/config"
	"base/internal/database"
	"base/internal/store/sqlc"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestCurrentUserRequiresAuthentication(t *testing.T) {
	service := &Service{}
	_, err := service.CurrentUser(context.Background(), 0)
	if err != ErrUnauthorized {
		t.Fatalf("CurrentUser() error = %v, want %v", err, ErrUnauthorized)
	}
}

func TestRegisterCreatesUserRoleVerificationTokenAndEmail(t *testing.T) {
	ctx := context.Background()
	db, queries := newAuthTestDB(t, ctx)
	service := newAuthTestService(db, queries)

	principal, err := service.Register(ctx, RegisterInput{
		Username: "  NewUser ",
		Email:    " NewUser@Example.com ",
		Password: "ValidPassword123",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if principal.Username != "newuser" || principal.Email != "newuser@example.com" {
		t.Fatalf("principal = %+v, want normalized username/email", principal)
	}
	if principal.Verified {
		t.Fatal("expected new registration to be unverified")
	}

	user, err := queries.GetUserByEmail(ctx, "newuser@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail() error = %v", err)
	}
	roles, err := queries.ListUserRoleNames(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListUserRoleNames() error = %v", err)
	}
	if len(roles) != 1 || roles[0] != "user" {
		t.Fatalf("roles = %v, want [user]", roles)
	}

	if _, err := queries.GetPasswordCredentialByUserID(ctx, user.ID); err != nil {
		t.Fatalf("GetPasswordCredentialByUserID() error = %v", err)
	}

	emails, err := queries.ListPendingEmails(ctx, 10)
	if err != nil {
		t.Fatalf("ListPendingEmails() error = %v", err)
	}
	if len(emails) != 1 {
		t.Fatalf("pending emails = %d, want 1", len(emails))
	}
	if emails[0].Template != "verify-email" || emails[0].Recipient != "newuser@example.com" {
		t.Fatalf("email = %+v, want verify-email to normalized address", emails[0])
	}

	var payload struct {
		Token string `json:"token"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal([]byte(emails[0].Payload), &payload); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}
	if payload.Token == "" || payload.Email != "newuser@example.com" {
		t.Fatalf("payload = %+v, want token and normalized email", payload)
	}

	storedToken, err := queries.GetUserToken(ctx, sqlc.GetUserTokenParams{TokenHash: HashToken(payload.Token), Kind: sqlc.TokenKindEmailVerification})
	if err != nil {
		t.Fatalf("GetUserToken() error = %v", err)
	}
	if storedToken.UserID != user.ID {
		t.Fatalf("stored token user_id = %d, want %d", storedToken.UserID, user.ID)
	}
}

func TestVerifyEmailMarksUserVerifiedAndConsumesToken(t *testing.T) {
	ctx := context.Background()
	db, queries := newAuthTestDB(t, ctx)
	service := newAuthTestService(db, queries)

	user := createAuthTestUser(t, ctx, queries, "verify-user", "verify@example.com")
	plainToken, tokenHash, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
	createdToken, err := queries.CreateUserToken(ctx, sqlc.CreateUserTokenParams{
		UserID:    user.ID,
		Kind:      sqlc.TokenKindEmailVerification,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateUserToken() error = %v", err)
	}

	if err := service.VerifyEmail(ctx, plainToken); err != nil {
		t.Fatalf("VerifyEmail() error = %v", err)
	}

	updatedUser, err := queries.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if !updatedUser.EmailVerifiedAt.Valid {
		t.Fatal("expected EmailVerifiedAt to be set")
	}

	if _, err := queries.GetUserToken(ctx, sqlc.GetUserTokenParams{TokenHash: tokenHash, Kind: sqlc.TokenKindEmailVerification}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetUserToken(used) error = %v, want sql.ErrNoRows", err)
	}

	var usedAt sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT used_at FROM user_tokens WHERE id = $1`, createdToken.ID).Scan(&usedAt); err != nil {
		t.Fatalf("query used_at error = %v", err)
	}
	if !usedAt.Valid {
		t.Fatal("expected used_at to be populated")
	}
}

func TestRequestPasswordResetAndResetPassword(t *testing.T) {
	ctx := context.Background()
	db, queries := newAuthTestDB(t, ctx)
	service := newAuthTestService(db, queries)

	user := createAuthTestUser(t, ctx, queries, "reset-user", "reset@example.com")
	if _, err := queries.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: user.ID, PasswordHash: "$argon2id$initial"}); err != nil {
		t.Fatalf("UpsertPasswordCredential() error = %v", err)
	}
	if err := queries.CreateUserSessionRecord(ctx, sqlc.CreateUserSessionRecordParams{Token: "token-1", UserID: user.ID, DeviceID: "device-1", Expiry: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatalf("CreateUserSessionRecord() error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO sessions (token, data, expiry) VALUES ($1, $2, $3)`, "token-1", []byte("session"), time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("insert sessions row error = %v", err)
	}

	if err := service.RequestPasswordReset(ctx, user.Email); err != nil {
		t.Fatalf("RequestPasswordReset() error = %v", err)
	}

	emails, err := queries.ListPendingEmails(ctx, 10)
	if err != nil {
		t.Fatalf("ListPendingEmails() error = %v", err)
	}
	if len(emails) != 1 || emails[0].Template != "password-reset" {
		t.Fatalf("emails = %+v, want one password-reset email", emails)
	}

	var payload struct {
		Token string `json:"token"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal([]byte(emails[0].Payload), &payload); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}
	if payload.Token == "" || payload.Email != user.Email {
		t.Fatalf("payload = %+v, want token and email", payload)
	}

	if err := service.ResetPassword(ctx, payload.Token, "UpdatedPassword123"); err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}

	credential, err := queries.GetPasswordCredentialByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetPasswordCredentialByUserID() error = %v", err)
	}
	match, err := ComparePassword("UpdatedPassword123", credential.PasswordHash)
	if err != nil {
		t.Fatalf("ComparePassword() error = %v", err)
	}
	if !match {
		t.Fatal("expected updated password hash to match")
	}

	if _, err := queries.GetUserToken(ctx, sqlc.GetUserTokenParams{TokenHash: HashToken(payload.Token), Kind: sqlc.TokenKindPasswordReset}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetUserToken(used reset token) error = %v, want sql.ErrNoRows", err)
	}
	assertQueryCount(t, ctx, db, `SELECT COUNT(*) FROM sessions WHERE token = 'token-1'`, 0)
	assertQueryCount(t, ctx, db, `SELECT COUNT(*) FROM user_sessions WHERE token = 'token-1' AND revoked_at IS NOT NULL`, 1)
}

func TestTOTPFlowAndLoginWithRecoveryCode(t *testing.T) {
	ctx := context.Background()
	db, queries, service := newAuthRuntimeTestEnv(t, ctx)

	passwordHash, err := HashPassword("ValidPassword123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	user := createAuthTestUser(t, ctx, queries, "totp-user", "totp@example.com")
	addRoleToUser(t, ctx, queries, user.ID, "user")
	if _, err := queries.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: user.ID, PasswordHash: passwordHash}); err != nil {
		t.Fatalf("UpsertPasswordCredential() error = %v", err)
	}
	if err := queries.MarkUserEmailVerified(ctx, user.ID); err != nil {
		t.Fatalf("MarkUserEmailVerified() error = %v", err)
	}

	setup, err := service.BeginTOTPSetup(ctx, user.ID)
	if err != nil {
		t.Fatalf("BeginTOTPSetup() error = %v", err)
	}
	if setup.Secret == "" || setup.Issuer != "base-test" || setup.Account != user.Email || setup.OTPAuthURL == "" {
		t.Fatalf("setup = %+v, want populated TOTP setup", setup)
	}

	configRow, err := queries.GetTotpConfigurationByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetTotpConfigurationByUserID() error = %v", err)
	}
	if configRow.EnabledAt.Valid {
		t.Fatal("expected TOTP config to be disabled before confirmation")
	}

	code, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode() error = %v", err)
	}
	recoveryCodes, err := service.ConfirmTOTPSetup(ctx, user.ID, code)
	if err != nil {
		t.Fatalf("ConfirmTOTPSetup() error = %v", err)
	}
	if len(recoveryCodes) != 10 {
		t.Fatalf("len(recoveryCodes) = %d, want 10", len(recoveryCodes))
	}

	configRow, err = queries.GetTotpConfigurationByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetTotpConfigurationByUserID() after confirm error = %v", err)
	}
	if !configRow.EnabledAt.Valid {
		t.Fatal("expected TOTP config to be enabled after confirmation")
	}
	assertQueryCount(t, ctx, db, `SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, 10, user.ID)

	_, err = service.LoginWithPassword(ctx, LoginInput{Identifier: user.Email, Password: "ValidPassword123", IPAddress: "127.0.0.1"})
	if !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("LoginWithPassword() error = %v, want %v", err, ErrTOTPRequired)
	}

	principal, err := service.LoginWithPassword(ctx, LoginInput{Identifier: user.Email, Password: "ValidPassword123", RecoveryCode: recoveryCodes[0], IPAddress: "127.0.0.1"})
	if err != nil {
		t.Fatalf("LoginWithPassword(recovery code) error = %v", err)
	}
	if principal.UserID != user.ID || !principal.TOTPEnabled {
		t.Fatalf("principal = %+v, want authenticated principal with TOTP enabled", principal)
	}

	assertQueryCount(t, ctx, db, `SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = $1 AND used_at IS NOT NULL`, 1, user.ID)
	updatedUser, err := queries.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if !updatedUser.LastLoginAt.Valid || updatedUser.FailedLoginCount != 0 {
		t.Fatalf("updated user = %+v, want last_login_at set and failed_login_count reset", updatedUser)
	}

	if err := service.DisableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("DisableTOTP() error = %v", err)
	}
	if _, err := queries.GetTotpConfigurationByUserID(ctx, user.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetTotpConfigurationByUserID() after disable error = %v, want sql.ErrNoRows", err)
	}
	assertQueryCount(t, ctx, db, `SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = $1`, 0, user.ID)
}

func TestLoginWithPasswordEdgeCases(t *testing.T) {
	ctx := context.Background()
	db, queries, service := newAuthRuntimeTestEnv(t, ctx)

	createVerifiedUser := func(username, email, password string) sqlc.User {
		t.Helper()
		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword() error = %v", err)
		}
		user := createAuthTestUser(t, ctx, queries, username, email)
		addRoleToUser(t, ctx, queries, user.ID, "user")
		if _, err := queries.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: user.ID, PasswordHash: hash}); err != nil {
			t.Fatalf("UpsertPasswordCredential() error = %v", err)
		}
		if err := queries.MarkUserEmailVerified(ctx, user.ID); err != nil {
			t.Fatalf("MarkUserEmailVerified() error = %v", err)
		}
		return user
	}

	t.Run("disabled account", func(t *testing.T) {
		user := createVerifiedUser("disabled-user", "disabled@example.com", "ValidPassword123")
		if _, err := db.ExecContext(ctx, `UPDATE users SET is_active = FALSE WHERE id = $1`, user.ID); err != nil {
			t.Fatalf("disable user error = %v", err)
		}

		_, err := service.LoginWithPassword(ctx, LoginInput{Identifier: user.Email, Password: "ValidPassword123", IPAddress: "127.0.0.1"})
		if !errors.Is(err, ErrAccountDisabled) {
			t.Fatalf("LoginWithPassword() error = %v, want %v", err, ErrAccountDisabled)
		}
	})

	t.Run("locked account", func(t *testing.T) {
		user := createVerifiedUser("locked-user", "locked@example.com", "ValidPassword123")
		if _, err := db.ExecContext(ctx, `UPDATE users SET locked_until = NOW() + INTERVAL '1 hour' WHERE id = $1`, user.ID); err != nil {
			t.Fatalf("lock user error = %v", err)
		}

		_, err := service.LoginWithPassword(ctx, LoginInput{Identifier: user.Email, Password: "ValidPassword123", IPAddress: "127.0.0.1"})
		if !errors.Is(err, ErrAccountLocked) {
			t.Fatalf("LoginWithPassword() error = %v, want %v", err, ErrAccountLocked)
		}
	})

	t.Run("unverified account", func(t *testing.T) {
		hash, err := HashPassword("ValidPassword123")
		if err != nil {
			t.Fatalf("HashPassword() error = %v", err)
		}
		user := createAuthTestUser(t, ctx, queries, "unverified-user", "unverified@example.com")
		if _, err := queries.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: user.ID, PasswordHash: hash}); err != nil {
			t.Fatalf("UpsertPasswordCredential() error = %v", err)
		}

		_, err = service.LoginWithPassword(ctx, LoginInput{Identifier: user.Email, Password: "ValidPassword123", IPAddress: "127.0.0.1"})
		if !errors.Is(err, ErrEmailUnverified) {
			t.Fatalf("LoginWithPassword() error = %v, want %v", err, ErrEmailUnverified)
		}
	})

	t.Run("invalid password increments failures", func(t *testing.T) {
		user := createVerifiedUser("wrong-pass-user", "wrongpass@example.com", "ValidPassword123")

		_, err := service.LoginWithPassword(ctx, LoginInput{Identifier: user.Email, Password: "WrongPassword123", IPAddress: "127.0.0.1"})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("LoginWithPassword() error = %v, want %v", err, ErrInvalidCredentials)
		}
		updatedUser, err := queries.GetUserByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("GetUserByID() error = %v", err)
		}
		if updatedUser.FailedLoginCount != 1 {
			t.Fatalf("FailedLoginCount = %d, want 1", updatedUser.FailedLoginCount)
		}
	})

	t.Run("username login succeeds and resets counters", func(t *testing.T) {
		user := createVerifiedUser("username-login", "username-login@example.com", "ValidPassword123")
		if _, err := db.ExecContext(ctx, `UPDATE users SET failed_login_count = 3 WHERE id = $1`, user.ID); err != nil {
			t.Fatalf("seed failed_login_count error = %v", err)
		}

		principal, err := service.LoginWithPassword(ctx, LoginInput{Identifier: user.Username, Password: "ValidPassword123", IPAddress: "127.0.0.1"})
		if err != nil {
			t.Fatalf("LoginWithPassword() error = %v", err)
		}
		if principal.UserID != user.ID || principal.Username != user.Username {
			t.Fatalf("principal = %+v, want authenticated user", principal)
		}
		updatedUser, err := queries.GetUserByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("GetUserByID() error = %v", err)
		}
		if !updatedUser.LastLoginAt.Valid || updatedUser.FailedLoginCount != 0 {
			t.Fatalf("updated user = %+v, want last_login_at set and failures reset", updatedUser)
		}
	})
}

func TestRequestAccountRecoveryAndRecoverAccount(t *testing.T) {
	ctx := context.Background()
	db, queries := newAuthTestDB(t, ctx)
	service := newAuthTestService(db, queries)

	passwordHash, err := HashPassword("InitialPassword123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	user := createAuthTestUser(t, ctx, queries, "recover-user", "recover@example.com")
	if _, err := queries.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: user.ID, PasswordHash: passwordHash}); err != nil {
		t.Fatalf("UpsertPasswordCredential() error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE users SET is_active = FALSE, locked_until = NOW() + INTERVAL '1 hour', failed_login_count = 2, disabled_reason = 'inactivity', disabled_at = NOW() WHERE id = $1`, user.ID); err != nil {
		t.Fatalf("disable user error = %v", err)
	}
	if _, err := queries.UpsertTotpConfiguration(ctx, sqlc.UpsertTotpConfigurationParams{UserID: user.ID, SecretCiphertext: []byte("cipher"), SecretNonce: []byte("nonce"), EnabledAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}}); err != nil {
		t.Fatalf("UpsertTotpConfiguration() error = %v", err)
	}
	if _, err := queries.CreateTotpRecoveryCode(ctx, sqlc.CreateTotpRecoveryCodeParams{UserID: user.ID, CodeHash: HashToken("RECOVERYCODE")}); err != nil {
		t.Fatalf("CreateTotpRecoveryCode() error = %v", err)
	}

	if err := service.RequestAccountRecovery(ctx, user.Email); err != nil {
		t.Fatalf("RequestAccountRecovery() error = %v", err)
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
		Email string `json:"email"`
	}
	if err := json.Unmarshal([]byte(emails[0].Payload), &payload); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}
	if payload.Token == "" || payload.Email != user.Email {
		t.Fatalf("payload = %+v, want token and email", payload)
	}

	if err := service.RecoverAccount(ctx, payload.Token, "RecoveredPassword123"); err != nil {
		t.Fatalf("RecoverAccount() error = %v", err)
	}

	credential, err := queries.GetPasswordCredentialByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetPasswordCredentialByUserID() error = %v", err)
	}
	match, err := ComparePassword("RecoveredPassword123", credential.PasswordHash)
	if err != nil {
		t.Fatalf("ComparePassword() error = %v", err)
	}
	if !match {
		t.Fatal("expected recovered password to be stored")
	}
	restoredUser, err := queries.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if !restoredUser.IsActive || restoredUser.LockedUntil.Valid || restoredUser.DisabledReason.Valid || restoredUser.DisabledAt.Valid || restoredUser.FailedLoginCount != 0 {
		t.Fatalf("restored user = %+v, want active and unlocked account", restoredUser)
	}
	if _, err := queries.GetTotpConfigurationByUserID(ctx, user.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetTotpConfigurationByUserID() error = %v, want sql.ErrNoRows", err)
	}
	assertQueryCount(t, ctx, db, `SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = $1`, 0, user.ID)
	if _, err := queries.GetUserToken(ctx, sqlc.GetUserTokenParams{TokenHash: HashToken(payload.Token), Kind: sqlc.TokenKindAccountRecovery}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetUserToken(used recovery token) error = %v, want sql.ErrNoRows", err)
	}
}

func TestCurrentUserReturnsRolesAndTOTPFlag(t *testing.T) {
	ctx := context.Background()
	_, queries := newAuthTestDB(t, ctx)
	service := &Service{queries: queries}

	user := createAuthTestUser(t, ctx, queries, "current-user", "current@example.com")
	addRoleToUser(t, ctx, queries, user.ID, "user")
	if _, err := queries.UpsertTotpConfiguration(ctx, sqlc.UpsertTotpConfigurationParams{
		UserID:           user.ID,
		SecretCiphertext: []byte("ciphertext"),
		SecretNonce:      []byte("nonce"),
		EnabledAt:        sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}); err != nil {
		t.Fatalf("UpsertTotpConfiguration() error = %v", err)
	}

	principal, err := service.CurrentUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("CurrentUser() error = %v", err)
	}
	if principal.UserID != user.ID || principal.Username != user.Username || principal.Email != user.Email {
		t.Fatalf("principal = %+v, want user identity fields", principal)
	}
	if len(principal.Roles) != 1 || principal.Roles[0] != "user" {
		t.Fatalf("Roles = %v, want [user]", principal.Roles)
	}
	if !principal.TOTPEnabled {
		t.Fatal("expected TOTPEnabled to be true")
	}
}

func TestRecordUserSessionReplacesExistingDeviceSession(t *testing.T) {
	ctx := context.Background()
	db, queries := newAuthTestDB(t, ctx)
	service := &Service{queries: queries}

	user := createAuthTestUser(t, ctx, queries, "session-user", "session@example.com")
	if err := queries.CreateUserSessionRecord(ctx, sqlc.CreateUserSessionRecordParams{
		Token:    "old-device-token",
		UserID:   user.ID,
		DeviceID: "device-1",
		Expiry:   time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateUserSessionRecord(old same device) error = %v", err)
	}
	if err := queries.CreateUserSessionRecord(ctx, sqlc.CreateUserSessionRecordParams{
		Token:    "other-device-token",
		UserID:   user.ID,
		DeviceID: "device-2",
		Expiry:   time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateUserSessionRecord(other device) error = %v", err)
	}

	if err := service.RecordUserSession(ctx, user.ID, "device-1", "new-device-token", time.Now().UTC().Add(2*time.Hour)); err != nil {
		t.Fatalf("RecordUserSession() error = %v", err)
	}

	assertQueryCount(t, ctx, db, `SELECT COUNT(*) FROM user_sessions WHERE token = 'new-device-token' AND revoked_at IS NULL`, 1)
	assertQueryCount(t, ctx, db, `SELECT COUNT(*) FROM user_sessions WHERE token = 'old-device-token' AND revoked_at IS NOT NULL`, 1)
	assertQueryCount(t, ctx, db, `SELECT COUNT(*) FROM user_sessions WHERE token = 'other-device-token' AND revoked_at IS NULL`, 1)
	assertQueryCount(t, ctx, db, `SELECT COUNT(*) FROM user_sessions WHERE user_id = $1`, 3, user.ID)

	if err := service.RecordUserSession(ctx, 0, "", "", time.Now().UTC()); err != nil {
		t.Fatalf("RecordUserSession() for blank input error = %v, want nil", err)
	}
}

func TestCompleteUserAuthenticationUpdatesLastLogin(t *testing.T) {
	ctx := context.Background()
	_, queries := newAuthTestDB(t, ctx)
	service := &Service{queries: queries}

	user := createAuthTestUser(t, ctx, queries, "complete-auth", "complete@example.com")
	addRoleToUser(t, ctx, queries, user.ID, "user")

	principal, err := service.completeUserAuthentication(ctx, queries, user.ID, true)
	if err != nil {
		t.Fatalf("completeUserAuthentication() error = %v", err)
	}
	if principal.UserID != user.ID || len(principal.Roles) != 1 || principal.Roles[0] != "user" {
		t.Fatalf("principal = %+v, want user principal with role", principal)
	}

	updatedUser, err := queries.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if !updatedUser.LastLoginAt.Valid {
		t.Fatal("expected LastLoginAt to be updated")
	}
}

func TestPasskeyBeginFlowsGenerateSessions(t *testing.T) {
	ctx := context.Background()
	_, queries, service := newAuthRuntimeTestEnv(t, ctx)

	user := createAuthTestUser(t, ctx, queries, "passkey-user", "passkey@example.com")

	registrationOptions, registrationSessionJSON, err := service.BeginPasskeyRegistration(ctx, user.ID)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration() error = %v", err)
	}
	if registrationOptions == nil || len(registrationSessionJSON) == 0 {
		t.Fatalf("registration result = %+v/%q, want options and session", registrationOptions, string(registrationSessionJSON))
	}
	registrationSession, err := decodePasskeySession(registrationSessionJSON)
	if err != nil {
		t.Fatalf("decodePasskeySession(registration) error = %v", err)
	}
	if registrationSession.Challenge == "" || len(registrationSession.UserID) == 0 {
		t.Fatalf("registration session = %+v, want challenge and user handle", registrationSession)
	}

	loginOptions, loginSessionJSON, err := service.BeginPasskeyLogin()
	if err != nil {
		t.Fatalf("BeginPasskeyLogin() error = %v", err)
	}
	if loginOptions == nil || len(loginSessionJSON) == 0 {
		t.Fatalf("login result = %+v/%q, want options and session", loginOptions, string(loginSessionJSON))
	}
	loginSession, err := decodePasskeySession(loginSessionJSON)
	if err != nil {
		t.Fatalf("decodePasskeySession(login) error = %v", err)
	}
	if loginSession.Challenge == "" {
		t.Fatalf("login session = %+v, want challenge", loginSession)
	}

	if err := service.FinishPasskeyRegistration(ctx, user.ID, nil, []byte(`{}`), "Laptop key"); !errors.Is(err, ErrPasskeyCeremony) {
		t.Fatalf("FinishPasskeyRegistration() error = %v, want %v", err, ErrPasskeyCeremony)
	}
	if _, err := service.FinishPasskeyLogin(ctx, nil, []byte(`{}`), "", "", "agent", "127.0.0.1"); !errors.Is(err, ErrPasskeyCeremony) {
		t.Fatalf("FinishPasskeyLogin() error = %v, want %v", err, ErrPasskeyCeremony)
	}
}

func TestPasskeyCredentialPersistenceAndLookup(t *testing.T) {
	ctx := context.Background()
	_, queries := newAuthTestDB(t, ctx)
	service := &Service{queries: queries}

	user := createAuthTestUser(t, ctx, queries, "passkey-store", "passkey-store@example.com")
	aaguid := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	credential := &wa.Credential{
		ID:              []byte("credential-1"),
		PublicKey:       []byte("public-key-1"),
		AttestationType: "none",
		Transport:       []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC},
		Authenticator: wa.Authenticator{
			AAGUID:       aaguid[:],
			SignCount:    7,
			CloneWarning: true,
		},
	}

	if err := service.persistPasskeyCredential(ctx, user.ID, credential, ""); err != nil {
		t.Fatalf("persistPasskeyCredential() error = %v", err)
	}

	rows, err := queries.ListPasskeyCredentialsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListPasskeyCredentialsByUserID() error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if !rows[0].Name.Valid || rows[0].Name.String != "Passkey" {
		t.Fatalf("row name = %+v, want default Passkey", rows[0].Name)
	}
	if !bytes.Equal(rows[0].CredentialID, credential.ID) || !bytes.Equal(rows[0].CredentialPublicKey, credential.PublicKey) {
		t.Fatalf("row = %+v, want stored credential id/public key", rows[0])
	}
	if rows[0].AttestationType != "none" || rows[0].SignCount != 7 || !rows[0].CloneWarning {
		t.Fatalf("row = %+v, want stored attestation and authenticator fields", rows[0])
	}
	if !rows[0].Aaguid.Valid || rows[0].Aaguid.UUID != aaguid {
		t.Fatalf("row AAGUID = %+v, want %v", rows[0].Aaguid, aaguid)
	}

	loadedUser, err := service.loadPasskeyUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("loadPasskeyUser() error = %v", err)
	}
	if loadedUser.user.ID != user.ID || len(loadedUser.credentials) != 1 {
		t.Fatalf("loaded user = %+v, want user with one credential", loadedUser)
	}
	if !bytes.Equal(loadedUser.credentials[0].ID, credential.ID) {
		t.Fatalf("loaded credential ID = %q, want %q", loadedUser.credentials[0].ID, credential.ID)
	}

	byHandle, err := service.loadPasskeyUserByHandle(ctx, credential.ID, loadedUser.WebAuthnID())
	if err != nil {
		t.Fatalf("loadPasskeyUserByHandle() error = %v", err)
	}
	if byHandle.user.ID != user.ID {
		t.Fatalf("handle lookup user ID = %d, want %d", byHandle.user.ID, user.ID)
	}

	if _, err := service.loadPasskeyUserByHandle(ctx, credential.ID, []byte("short")); err == nil {
		t.Fatal("loadPasskeyUserByHandle(short handle) error = nil, want error")
	}
	if _, err := service.loadPasskeyUserByHandle(ctx, []byte("missing"), loadedUser.WebAuthnID()); err == nil {
		t.Fatal("loadPasskeyUserByHandle(missing credential) error = nil, want error")
	}

	updated := &wa.Credential{
		ID:              credential.ID,
		PublicKey:       []byte("public-key-2"),
		AttestationType: "basic",
		Transport:       []protocol.AuthenticatorTransport{protocol.Internal},
		Authenticator: wa.Authenticator{
			AAGUID:       aaguid[:],
			SignCount:    11,
			CloneWarning: false,
		},
	}
	if err := service.updatePasskeyCredential(ctx, updated); err != nil {
		t.Fatalf("updatePasskeyCredential() error = %v", err)
	}

	rows, err = queries.ListPasskeyCredentialsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListPasskeyCredentialsByUserID() after update error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) after update = %d, want 1", len(rows))
	}
	if !bytes.Equal(rows[0].CredentialPublicKey, updated.PublicKey) || rows[0].AttestationType != "basic" || rows[0].SignCount != 11 || rows[0].CloneWarning {
		t.Fatalf("updated row = %+v, want updated passkey fields", rows[0])
	}
}

func TestOAuthAuthorizationURLBuildsSessionAndMode(t *testing.T) {
	ctx := context.Background()
	db, queries := newAuthTestDB(t, ctx)
	client := &fakeOAuthClient{authorizationURL: "https://provider.example/authorize"}
	service := newAuthTestService(db, queries)
	service.cfg.OAuth = config.OAuthConfig{StateTTL: 10 * time.Minute, StateBytes: 12, PKCEVerifierBytes: 18}
	service.oauth = map[string]OAuthProviderClient{"test": client}

	authorizationURL, sessionJSON, mode, err := service.OAuthAuthorizationURL(ctx, " TEST ", 42)
	if err != nil {
		t.Fatalf("OAuthAuthorizationURL() error = %v", err)
	}
	if authorizationURL != "https://provider.example/authorize" {
		t.Fatalf("authorization URL = %q, want fake provider URL", authorizationURL)
	}
	if mode != "link" {
		t.Fatalf("mode = %q, want link", mode)
	}

	flowState, err := decodeOAuthFlow(sessionJSON)
	if err != nil {
		t.Fatalf("decodeOAuthFlow() error = %v", err)
	}
	if flowState.Provider != "test" || flowState.LinkUserID != 42 || flowState.State == "" || flowState.CodeVerifier == "" {
		t.Fatalf("flowState = %+v, want normalized provider and generated state", flowState)
	}
	if client.lastAuthorizationState != flowState.State {
		t.Fatalf("authorization state = %q, want %q", client.lastAuthorizationState, flowState.State)
	}
	if client.lastAuthorizationChallenge != pkceCodeChallenge(flowState.CodeVerifier) {
		t.Fatalf("authorization challenge = %q, want PKCE challenge derived from verifier", client.lastAuthorizationChallenge)
	}
	if time.Since(flowState.StartedAt) > time.Minute {
		t.Fatalf("StartedAt = %v, want recent timestamp", flowState.StartedAt)
	}
	_ = db
}

func TestCompleteOAuthAuthenticationCreatesUserAndStoresAccount(t *testing.T) {
	ctx := context.Background()
	db, queries := newAuthTestDB(t, ctx)
	client := &fakeOAuthClient{
		tokens:  OAuthTokens{AccessToken: "access-token", RefreshToken: "refresh-token", Expiry: time.Now().UTC().Add(time.Hour)},
		profile: OAuthProfile{Subject: "provider-user-1", Email: "oauth-create@example.com", EmailVerified: true, Username: "oauthcreate"},
	}
	service := newAuthTestService(db, queries)
	service.cfg.OAuth = config.OAuthConfig{StateTTL: 10 * time.Minute}
	service.oauth = map[string]OAuthProviderClient{"test": client}

	sessionJSON, err := encodeOAuthFlow(oauthFlowState{Provider: "test", State: "oauth-state", CodeVerifier: "oauth-verifier", StartedAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("encodeOAuthFlow() error = %v", err)
	}

	result, err := service.CompleteOAuthAuthentication(ctx, "test", sessionJSON, "oauth-state", "oauth-code", 0)
	if err != nil {
		t.Fatalf("CompleteOAuthAuthentication() error = %v", err)
	}
	if result.Provider != "test" || result.Mode != "login" || !result.Created || result.Linked {
		t.Fatalf("result = %+v, want created login result", result)
	}
	if result.Principal.Email != "oauth-create@example.com" || !result.Principal.Verified {
		t.Fatalf("principal = %+v, want verified oauth user", result.Principal)
	}
	if client.lastExchangeCode != "oauth-code" || client.lastExchangeVerifier != "oauth-verifier" || client.lastAccessToken != "access-token" {
		t.Fatalf("client = %+v, want exchange and profile fetch inputs recorded", client)
	}

	createdUser, err := queries.GetUserByEmail(ctx, "oauth-create@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail() error = %v", err)
	}
	if !createdUser.EmailVerifiedAt.Valid || !createdUser.LastLoginAt.Valid {
		t.Fatalf("created user = %+v, want verified with last login set", createdUser)
	}
	roles, err := queries.ListUserRoleNames(ctx, createdUser.ID)
	if err != nil {
		t.Fatalf("ListUserRoleNames() error = %v", err)
	}
	if len(roles) != 1 || roles[0] != "user" {
		t.Fatalf("roles = %v, want [user]", roles)
	}
	account, err := queries.GetOAuthAccountByProviderIdentity(ctx, sqlc.GetOAuthAccountByProviderIdentityParams{Provider: "test", ProviderUserID: "provider-user-1"})
	if err != nil {
		t.Fatalf("GetOAuthAccountByProviderIdentity() error = %v", err)
	}
	if account.UserID != createdUser.ID || len(account.AccessTokenCiphertext) == 0 || len(account.RefreshTokenCiphertext) == 0 || !account.TokenExpiresAt.Valid {
		t.Fatalf("oauth account = %+v, want stored tokens for created user", account)
	}
	assertQueryCount(t, ctx, db, `SELECT COUNT(*) FROM users WHERE email = 'oauth-create@example.com'`, 1)
}

func TestCompleteOAuthAuthenticationLinksExistingUserByEmail(t *testing.T) {
	ctx := context.Background()
	db, queries := newAuthTestDB(t, ctx)
	client := &fakeOAuthClient{
		tokens:  OAuthTokens{AccessToken: "access-token", Expiry: time.Now().UTC().Add(time.Hour)},
		profile: OAuthProfile{Subject: "provider-user-2", Email: "oauth-link@example.com", EmailVerified: true},
	}
	service := newAuthTestService(db, queries)
	service.cfg.OAuth = config.OAuthConfig{StateTTL: 10 * time.Minute}
	service.oauth = map[string]OAuthProviderClient{"test": client}

	user := createAuthTestUser(t, ctx, queries, "oauth-link", "oauth-link@example.com")
	addRoleToUser(t, ctx, queries, user.ID, "user")
	if err := queries.MarkUserEmailVerified(ctx, user.ID); err != nil {
		t.Fatalf("MarkUserEmailVerified() error = %v", err)
	}

	sessionJSON, err := encodeOAuthFlow(oauthFlowState{Provider: "test", State: "oauth-state", CodeVerifier: "oauth-verifier", StartedAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("encodeOAuthFlow() error = %v", err)
	}

	result, err := service.CompleteOAuthAuthentication(ctx, "test", sessionJSON, "oauth-state", "oauth-code", 0)
	if err != nil {
		t.Fatalf("CompleteOAuthAuthentication() error = %v", err)
	}
	if result.Created || !result.Linked || result.Principal.UserID != user.ID {
		t.Fatalf("result = %+v, want linked existing user", result)
	}

	account, err := queries.GetOAuthAccountByProviderIdentity(ctx, sqlc.GetOAuthAccountByProviderIdentityParams{Provider: "test", ProviderUserID: "provider-user-2"})
	if err != nil {
		t.Fatalf("GetOAuthAccountByProviderIdentity() error = %v", err)
	}
	if account.UserID != user.ID {
		t.Fatalf("oauth account user_id = %d, want %d", account.UserID, user.ID)
	}
}

func TestCompleteOAuthAuthenticationRejectsLinkedConflict(t *testing.T) {
	ctx := context.Background()
	db, queries := newAuthTestDB(t, ctx)
	client := &fakeOAuthClient{
		tokens:  OAuthTokens{AccessToken: "access-token", Expiry: time.Now().UTC().Add(time.Hour)},
		profile: OAuthProfile{Subject: "provider-conflict", Email: "conflict@example.com", EmailVerified: true},
	}
	service := newAuthTestService(db, queries)
	service.cfg.OAuth = config.OAuthConfig{StateTTL: 10 * time.Minute}
	service.oauth = map[string]OAuthProviderClient{"test": client}

	linkedUser := createAuthTestUser(t, ctx, queries, "linked-user", "linked@example.com")
	addRoleToUser(t, ctx, queries, linkedUser.ID, "user")
	otherUser := createAuthTestUser(t, ctx, queries, "other-user", "other@example.com")
	addRoleToUser(t, ctx, queries, otherUser.ID, "user")

	accessToken, err := sealStoredSecret("existing-access-token", service.cfg.Security.EncryptionKey)
	if err != nil {
		t.Fatalf("sealStoredSecret(access) error = %v", err)
	}
	refreshToken, err := sealStoredSecret("existing-refresh-token", service.cfg.Security.EncryptionKey)
	if err != nil {
		t.Fatalf("sealStoredSecret(refresh) error = %v", err)
	}
	if _, err := queries.UpsertOAuthAccount(ctx, sqlc.UpsertOAuthAccountParams{
		UserID:                 otherUser.ID,
		Provider:               "test",
		ProviderUserID:         "provider-conflict",
		AccessTokenCiphertext:  accessToken,
		RefreshTokenCiphertext: refreshToken,
		TokenExpiresAt:         sql.NullTime{Time: time.Now().UTC().Add(time.Hour), Valid: true},
	}); err != nil {
		t.Fatalf("UpsertOAuthAccount() error = %v", err)
	}

	sessionJSON, err := encodeOAuthFlow(oauthFlowState{Provider: "test", State: "oauth-state", CodeVerifier: "oauth-verifier", StartedAt: time.Now().UTC(), LinkUserID: linkedUser.ID})
	if err != nil {
		t.Fatalf("encodeOAuthFlow() error = %v", err)
	}

	_, err = service.CompleteOAuthAuthentication(ctx, "test", sessionJSON, "oauth-state", "oauth-code", linkedUser.ID)
	if !errors.Is(err, ErrOAuthConflict) {
		t.Fatalf("CompleteOAuthAuthentication() error = %v, want %v", err, ErrOAuthConflict)
	}
	assertQueryCount(t, ctx, db, `SELECT COUNT(*) FROM oauth_accounts WHERE provider = 'test'`, 1)
}

func newAuthTestDB(t *testing.T, ctx context.Context) (*sql.DB, *sqlc.Queries) {
	db, queries, _ := newAuthTestDBWithURL(t, ctx)
	return db, queries
}

func newAuthTestDBWithURL(t *testing.T, ctx context.Context) (*sql.DB, *sqlc.Queries, string) {
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

	db, err := database.Open(ctx, config.DatabaseConfig{
		URL:             databaseURL,
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
		ConnMaxIdleTime: time.Minute,
	})
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := database.RunMigrations(ctx, db); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}

	return db, sqlc.New(db), databaseURL
}

func newAuthTestService(db *sql.DB, queries *sqlc.Queries) *Service {
	return &Service{
		db:      db,
		queries: queries,
		cfg: config.Config{
			Security: config.SecurityConfig{
				EmailVerificationTTL: time.Hour,
				PasswordResetTTL:     time.Hour,
				RecoveryTTL:          30 * time.Minute,
				EncryptionKey:        "0123456789abcdef0123456789abcdef",
				TOTPIssuer:           "base-test",
			},
		},
	}
}

type fakeOAuthClient struct {
	authorizationURL           string
	tokens                     OAuthTokens
	profile                    OAuthProfile
	exchangeErr                error
	fetchErr                   error
	lastAuthorizationState     string
	lastAuthorizationChallenge string
	lastExchangeCode           string
	lastExchangeVerifier       string
	lastAccessToken            string
}

func (client *fakeOAuthClient) AuthorizationURL(state string, codeChallenge string) string {
	client.lastAuthorizationState = state
	client.lastAuthorizationChallenge = codeChallenge
	return client.authorizationURL
}

func (client *fakeOAuthClient) ExchangeCode(_ context.Context, code string, codeVerifier string) (OAuthTokens, error) {
	client.lastExchangeCode = code
	client.lastExchangeVerifier = codeVerifier
	if client.exchangeErr != nil {
		return OAuthTokens{}, client.exchangeErr
	}
	return client.tokens, nil
}

func (client *fakeOAuthClient) FetchProfile(_ context.Context, accessToken string) (OAuthProfile, error) {
	client.lastAccessToken = accessToken
	if client.fetchErr != nil {
		return OAuthProfile{}, client.fetchErr
	}
	return client.profile, nil
}

func newAuthRuntimeTestEnv(t *testing.T, ctx context.Context) (*sql.DB, *sqlc.Queries, *Service) {
	t.Helper()

	db, queries, databaseURL := newAuthTestDBWithURL(t, ctx)
	pgx, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	t.Cleanup(pgx.Close)

	service, err := NewService(ctx, db, pgx, config.Config{
		Security: config.SecurityConfig{
			FailedLoginThreshold: 5,
			FailedLoginWindow:    15 * time.Minute,
			EncryptionKey:        "0123456789abcdef0123456789abcdef",
			TOTPIssuer:           "base-test",
		},
		WebAuthn: config.WebAuthnConfig{RPID: "localhost", RPDisplayName: "Base Test", RPOrigins: []string{"http://localhost"}},
		OAuth:    config.OAuthConfig{StateTTL: 10 * time.Minute, StateBytes: 32, PKCEVerifierBytes: 32, Providers: map[string]config.OAuthProviderConfig{}},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	return db, queries, service
}

func createAuthTestUser(t *testing.T, ctx context.Context, queries *sqlc.Queries, username, email string) sqlc.User {
	t.Helper()

	user, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: username, Email: email})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	return user
}

func addRoleToUser(t *testing.T, ctx context.Context, queries *sqlc.Queries, userID int64, roleName string) {
	t.Helper()

	role, err := queries.GetRoleByName(ctx, roleName)
	if err != nil {
		t.Fatalf("GetRoleByName(%q) error = %v", roleName, err)
	}
	if err := queries.AddUserRole(ctx, sqlc.AddUserRoleParams{UserID: userID, RoleID: role.ID}); err != nil {
		t.Fatalf("AddUserRole() error = %v", err)
	}
}

func assertQueryCount(t *testing.T, ctx context.Context, db *sql.DB, query string, want int, args ...any) {
	t.Helper()

	var got int
	if err := db.QueryRowContext(ctx, query, args...).Scan(&got); err != nil {
		t.Fatalf("count query %q error = %v", query, err)
	}
	if got != want {
		t.Fatalf("count query %q = %d, want %d", query, got, want)
	}
}
