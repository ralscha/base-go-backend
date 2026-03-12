package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"base/internal/config"
	"base/internal/store/sqlc"

	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	ratelimit "github.com/ralscha/ratelimiter-pg"
	"github.com/sqlc-dev/pqtype"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account is locked")
	ErrAccountDisabled    = errors.New("account is disabled")
	ErrEmailUnverified    = errors.New("email verification required")
	ErrTOTPRequired       = errors.New("two-factor authentication required")
	ErrInvalidTOTP        = errors.New("invalid two-factor code")
	ErrPasskeyCeremony    = errors.New("passkey ceremony not initialized")
	ErrUnauthorized       = errors.New("authentication required")
)

type Service struct {
	db       *sql.DB
	queries  *sqlc.Queries
	limiter  *ratelimit.RateLimiter
	webAuthn *wa.WebAuthn
	cfg      config.Config
}

type SessionPrincipal struct {
	UserID      int64    `json:"user_id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	TOTPEnabled bool     `json:"totp_enabled"`
	Verified    bool     `json:"verified"`
}

type TOTPSetup struct {
	Secret     string `json:"secret"`
	Issuer     string `json:"issuer"`
	Account    string `json:"account"`
	OTPAuthURL string `json:"otpauth_url"`
}

type RegisterInput struct {
	Username string
	Email    string
	Password string
}

type LoginInput struct {
	Identifier   string
	Password     string
	TOTPCode     string
	RecoveryCode string
	IPAddress    string
	UserAgent    string
}

func NewService(ctx context.Context, db *sql.DB, pgxPool *pgxpool.Pool, cfg config.Config) (*Service, error) {
	limitCfg := ratelimit.BucketConfig{
		Capacity:        float64(cfg.Security.FailedLoginThreshold),
		RefillPerSecond: float64(cfg.Security.FailedLoginThreshold) / cfg.Security.FailedLoginWindow.Seconds(),
		CostPerRequest:  1,
		DenyRetryFloor:  time.Second,
	}

	limiter := ratelimit.New(pgxPool, "public", limitCfg)
	if err := limiter.Init(ctx); err != nil {
		return nil, fmt.Errorf("init rate limiter: %w", err)
	}

	webAuthn, err := wa.New(&wa.Config{
		RPID:          cfg.WebAuthn.RPID,
		RPDisplayName: cfg.WebAuthn.RPDisplayName,
		RPOrigins:     cfg.WebAuthn.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("init webauthn: %w", err)
	}

	return &Service{
		db:       db,
		queries:  sqlc.New(db),
		limiter:  limiter,
		webAuthn: webAuthn,
		cfg:      cfg,
	}, nil
}

func (s *Service) RateLimiter() *ratelimit.RateLimiter {
	return s.limiter
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (SessionPrincipal, error) {
	username := strings.ToLower(strings.TrimSpace(input.Username))
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if username == "" || email == "" {
		return SessionPrincipal{}, errors.New("username and email are required")
	}

	passwordHash, err := HashPassword(input.Password)
	if err != nil {
		return SessionPrincipal{}, err
	}

	plainToken, tokenHash, err := NewToken()
	if err != nil {
		return SessionPrincipal{}, fmt.Errorf("create verification token: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SessionPrincipal{}, err
	}
	defer func() { _ = tx.Rollback() }()

	q := s.queries.WithTx(tx)
	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Username: username, Email: email})
	if err != nil {
		return SessionPrincipal{}, err
	}

	if _, err := q.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: user.ID, PasswordHash: passwordHash}); err != nil {
		return SessionPrincipal{}, err
	}

	role, err := q.GetRoleByName(ctx, "user")
	if err != nil {
		return SessionPrincipal{}, err
	}
	if err := q.AddUserRole(ctx, sqlc.AddUserRoleParams{UserID: user.ID, RoleID: role.ID}); err != nil {
		return SessionPrincipal{}, err
	}

	if _, err := q.CreateUserToken(ctx, sqlc.CreateUserTokenParams{
		UserID:    user.ID,
		Kind:      sqlc.TokenKindEmailVerification,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().UTC().Add(s.cfg.Security.EmailVerificationTTL),
	}); err != nil {
		return SessionPrincipal{}, err
	}

	payload, err := json.Marshal(map[string]any{
		"token": plainToken,
		"email": user.Email,
	})
	if err != nil {
		return SessionPrincipal{}, err
	}

	if _, err := q.EnqueueEmail(ctx, sqlc.EnqueueEmailParams{
		Template:    "verify-email",
		Recipient:   user.Email,
		Subject:     "Verify your account",
		Payload:     payload,
		AvailableAt: time.Now().UTC(),
	}); err != nil {
		return SessionPrincipal{}, err
	}

	roles, err := q.ListUserRoleNames(ctx, user.ID)
	if err != nil {
		return SessionPrincipal{}, err
	}
	if err := tx.Commit(); err != nil {
		return SessionPrincipal{}, err
	}

	return principalFromUser(user, roles), nil
}

func (s *Service) LoginWithPassword(ctx context.Context, input LoginInput) (SessionPrincipal, error) {
	identifier := strings.ToLower(strings.TrimSpace(input.Identifier))
	if identifier == "" || input.Password == "" {
		return SessionPrincipal{}, ErrInvalidCredentials
	}

	if err := s.enforceRateLimit(ctx, identifier, input.IPAddress); err != nil {
		return SessionPrincipal{}, err
	}

	user, err := s.lookupUser(ctx, identifier)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			_ = s.recordLoginAttempt(ctx, 0, identifier, false, input.IPAddress, input.UserAgent)
			return SessionPrincipal{}, ErrInvalidCredentials
		}
		return SessionPrincipal{}, err
	}

	if !user.IsActive {
		return SessionPrincipal{}, ErrAccountDisabled
	}
	if user.LockedUntil.Valid && user.LockedUntil.Time.After(time.Now().UTC()) {
		return SessionPrincipal{}, ErrAccountLocked
	}
	if !user.EmailVerifiedAt.Valid {
		return SessionPrincipal{}, ErrEmailUnverified
	}

	credential, err := s.queries.GetPasswordCredentialByUserID(ctx, user.ID)
	if err != nil {
		return SessionPrincipal{}, err
	}

	match, err := ComparePassword(input.Password, credential.PasswordHash)
	if err != nil {
		return SessionPrincipal{}, err
	}
	if !match {
		if err := s.handleFailedLogin(ctx, user, identifier, input.IPAddress, input.UserAgent); err != nil {
			return SessionPrincipal{}, err
		}
		return SessionPrincipal{}, ErrInvalidCredentials
	}

	if err := s.validateSecondFactor(ctx, user.ID, input.TOTPCode, input.RecoveryCode); err != nil {
		if err2 := s.handleFailedLogin(ctx, user, identifier, input.IPAddress, input.UserAgent); err2 != nil {
			return SessionPrincipal{}, err2
		}
		return SessionPrincipal{}, err
	}

	if err := s.recordLoginAttempt(ctx, user.ID, identifier, true, input.IPAddress, input.UserAgent); err != nil {
		return SessionPrincipal{}, err
	}
	if err := s.queries.UpdateUserLastLogin(ctx, user.ID); err != nil {
		return SessionPrincipal{}, err
	}

	roles, err := s.queries.ListUserRoleNames(ctx, user.ID)
	if err != nil {
		return SessionPrincipal{}, err
	}
	updatedUser, err := s.queries.GetUserByID(ctx, user.ID)
	if err != nil {
		return SessionPrincipal{}, err
	}

	return principalFromUser(updatedUser, roles), nil
}

func (s *Service) BeginTOTPSetup(ctx context.Context, userID int64) (TOTPSetup, error) {
	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		return TOTPSetup{}, err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.cfg.Security.TOTPIssuer,
		AccountName: user.Email,
	})
	if err != nil {
		return TOTPSetup{}, fmt.Errorf("generate totp secret: %w", err)
	}

	ciphertext, nonce, err := encryptSecret(key.Secret(), s.cfg.Security.EncryptionKey)
	if err != nil {
		return TOTPSetup{}, err
	}

	if _, err := s.queries.UpsertTotpConfiguration(ctx, sqlc.UpsertTotpConfigurationParams{
		UserID:           userID,
		SecretCiphertext: ciphertext,
		SecretNonce:      nonce,
		EnabledAt:        sql.NullTime{},
	}); err != nil {
		return TOTPSetup{}, err
	}

	return TOTPSetup{
		Secret:     key.Secret(),
		Issuer:     s.cfg.Security.TOTPIssuer,
		Account:    user.Email,
		OTPAuthURL: key.URL(),
	}, nil
}

func (s *Service) ConfirmTOTPSetup(ctx context.Context, userID int64, code string) ([]string, error) {
	configRow, err := s.queries.GetTotpConfigurationByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	secret, err := decryptSecret(configRow.SecretCiphertext, configRow.SecretNonce, s.cfg.Security.EncryptionKey)
	if err != nil {
		return nil, err
	}
	if !validateTOTPCode(secret, code) {
		return nil, ErrInvalidTOTP
	}

	recoveryCodes, err := generateRecoveryCodes(10)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	q := s.queries.WithTx(tx)
	if err := q.EnableTotpConfiguration(ctx, userID); err != nil {
		return nil, err
	}
	if err := q.DeleteTotpRecoveryCodesByUserID(ctx, userID); err != nil {
		return nil, err
	}
	for _, recoveryCode := range recoveryCodes {
		if _, err := q.CreateTotpRecoveryCode(ctx, sqlc.CreateTotpRecoveryCodeParams{UserID: userID, CodeHash: HashToken(recoveryCode)}); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return recoveryCodes, nil
}

func (s *Service) DisableTOTP(ctx context.Context, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	q := s.queries.WithTx(tx)
	if err := q.DeleteTotpRecoveryCodesByUserID(ctx, userID); err != nil {
		return err
	}
	if err := q.DeleteTotpConfigurationByUserID(ctx, userID); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	tokenRow, err := s.queries.GetUserToken(ctx, sqlc.GetUserTokenParams{
		TokenHash: HashToken(token),
		Kind:      sqlc.TokenKindEmailVerification,
	})
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	q := s.queries.WithTx(tx)
	if err := q.MarkUserEmailVerified(ctx, tokenRow.UserID); err != nil {
		return err
	}
	if err := q.UseUserToken(ctx, tokenRow.ID); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := s.queries.GetUserByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}

	plainToken, tokenHash, err := NewToken()
	if err != nil {
		return err
	}

	payload, err := json.Marshal(map[string]any{
		"token": plainToken,
		"email": user.Email,
	})
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	q := s.queries.WithTx(tx)
	if _, err := q.CreateUserToken(ctx, sqlc.CreateUserTokenParams{
		UserID:    user.ID,
		Kind:      sqlc.TokenKindPasswordReset,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().UTC().Add(s.cfg.Security.PasswordResetTTL),
	}); err != nil {
		return err
	}
	if _, err := q.EnqueueEmail(ctx, sqlc.EnqueueEmailParams{
		Template:    "password-reset",
		Recipient:   user.Email,
		Subject:     "Reset your password",
		Payload:     payload,
		AvailableAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Service) RequestAccountRecovery(ctx context.Context, email string) error {
	user, err := s.queries.GetUserByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}

	plainToken, tokenHash, err := NewToken()
	if err != nil {
		return err
	}

	payload, err := json.Marshal(map[string]any{
		"token": plainToken,
		"email": user.Email,
	})
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	q := s.queries.WithTx(tx)
	if _, err := q.CreateUserToken(ctx, sqlc.CreateUserTokenParams{
		UserID:    user.ID,
		Kind:      sqlc.TokenKindAccountRecovery,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().UTC().Add(s.cfg.Security.RecoveryTTL),
	}); err != nil {
		return err
	}
	if _, err := q.EnqueueEmail(ctx, sqlc.EnqueueEmailParams{
		Template:    "account-recovery",
		Recipient:   user.Email,
		Subject:     "Recover your account",
		Payload:     payload,
		AvailableAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Service) RecoverAccount(ctx context.Context, token string, password string) error {
	passwordHash, err := HashPassword(password)
	if err != nil {
		return err
	}

	tokenRow, err := s.queries.GetUserToken(ctx, sqlc.GetUserTokenParams{
		TokenHash: HashToken(token),
		Kind:      sqlc.TokenKindAccountRecovery,
	})
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	q := s.queries.WithTx(tx)
	if _, err := q.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: tokenRow.UserID, PasswordHash: passwordHash}); err != nil {
		return err
	}
	if err := q.RestoreUserAccess(ctx, tokenRow.UserID); err != nil {
		return err
	}
	if err := q.DeleteTotpRecoveryCodesByUserID(ctx, tokenRow.UserID); err != nil {
		return err
	}
	if err := q.DeleteTotpConfigurationByUserID(ctx, tokenRow.UserID); err != nil {
		return err
	}
	if err := q.UseUserToken(ctx, tokenRow.ID); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Service) ResetPassword(ctx context.Context, token string, password string) error {
	passwordHash, err := HashPassword(password)
	if err != nil {
		return err
	}

	tokenRow, err := s.queries.GetUserToken(ctx, sqlc.GetUserTokenParams{
		TokenHash: HashToken(token),
		Kind:      sqlc.TokenKindPasswordReset,
	})
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	q := s.queries.WithTx(tx)
	if _, err := q.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{UserID: tokenRow.UserID, PasswordHash: passwordHash}); err != nil {
		return err
	}
	if err := q.UseUserToken(ctx, tokenRow.ID); err != nil {
		return err
	}
	if err := q.LockUserUntil(ctx, sqlc.LockUserUntilParams{ID: tokenRow.UserID}); err != nil {
		return err
	}
	if err := q.RevokeAllUserSessions(ctx, tokenRow.UserID); err != nil {
		return err
	}
	if err := q.RevokeAllUserSessionRecords(ctx, tokenRow.UserID); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Service) CurrentUser(ctx context.Context, userID int64) (SessionPrincipal, error) {
	if userID == 0 {
		return SessionPrincipal{}, ErrUnauthorized
	}

	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		return SessionPrincipal{}, err
	}
	roles, err := s.queries.ListUserRoleNames(ctx, userID)
	if err != nil {
		return SessionPrincipal{}, err
	}
	return s.principalWithFactors(ctx, user, roles)
}

func (s *Service) RecordUserSession(ctx context.Context, userID int64, deviceID, token string, expiry time.Time) error {
	if userID == 0 || deviceID == "" || token == "" {
		return nil
	}

	if err := s.queries.RevokeDeviceSessions(ctx, sqlc.RevokeDeviceSessionsParams{UserID: userID, DeviceID: deviceID}); err != nil {
		return err
	}

	return s.queries.CreateUserSessionRecord(ctx, sqlc.CreateUserSessionRecordParams{
		Token:    token,
		UserID:   userID,
		DeviceID: deviceID,
		Expiry:   expiry.UTC(),
	})
}

func (s *Service) lookupUser(ctx context.Context, identifier string) (sqlc.User, error) {
	if strings.Contains(identifier, "@") {
		return s.queries.GetUserByEmail(ctx, identifier)
	}
	return s.queries.GetUserByUsername(ctx, identifier)
}

func (s *Service) enforceRateLimit(ctx context.Context, identifier, ip string) error {
	decision, err := s.limiter.Allow(ctx, "login:user:"+identifier)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return fmt.Errorf("rate limited: retry after %s", decision.RetryAfter)
	}

	if ip == "" {
		return nil
	}

	ipDecision, err := s.limiter.AllowWithConfig(ctx, "login:ip:"+ip, ratelimit.BucketConfig{
		Capacity:        float64(s.cfg.Security.FailedLoginThreshold * 4),
		RefillPerSecond: float64(s.cfg.Security.FailedLoginThreshold*4) / s.cfg.Security.FailedLoginWindow.Seconds(),
		CostPerRequest:  1,
		DenyRetryFloor:  time.Second,
	})
	if err != nil {
		return err
	}
	if !ipDecision.Allowed {
		return fmt.Errorf("rate limited: retry after %s", ipDecision.RetryAfter)
	}

	return nil
}

func (s *Service) handleFailedLogin(ctx context.Context, user sqlc.User, identifier, ipAddress, userAgent string) error {
	if err := s.recordLoginAttempt(ctx, user.ID, identifier, false, ipAddress, userAgent); err != nil {
		return err
	}
	if err := s.queries.IncrementFailedLogin(ctx, user.ID); err != nil {
		return err
	}

	count, err := s.queries.CountRecentFailedAttemptsByUser(ctx, sqlc.CountRecentFailedAttemptsByUserParams{
		UserID:    sql.NullInt64{Int64: user.ID, Valid: true},
		CreatedAt: time.Now().UTC().Add(-s.cfg.Security.FailedLoginWindow),
	})
	if err != nil {
		return err
	}

	if count >= int64(s.cfg.Security.FailedLoginThreshold) {
		return s.queries.LockUserUntil(ctx, sqlc.LockUserUntilParams{
			ID:             user.ID,
			LockedUntil:    sql.NullTime{Time: time.Now().UTC().Add(100 * 365 * 24 * time.Hour), Valid: true},
			DisabledReason: sql.NullString{String: "failed_login_attempts", Valid: true},
		})
	}

	return nil
}

func (s *Service) recordLoginAttempt(ctx context.Context, userID int64, username string, success bool, ipAddress, userAgent string) error {
	var nullableID sql.NullInt64
	if userID > 0 {
		nullableID = sql.NullInt64{Int64: userID, Valid: true}
	}
	_, err := s.queries.InsertLoginAttempt(ctx, sqlc.InsertLoginAttemptParams{
		UserID:    nullableID,
		Username:  username,
		Success:   success,
		IpAddress: inetValue(ipAddress),
		UserAgent: nullString(userAgent),
	})
	return err
}

func principalFromUser(user sqlc.User, roles []string) SessionPrincipal {
	return SessionPrincipal{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Roles:    roles,
		Verified: user.EmailVerifiedAt.Valid,
	}
}

func (s *Service) principalWithFactors(ctx context.Context, user sqlc.User, roles []string) (SessionPrincipal, error) {
	principal := principalFromUser(user, roles)
	configRow, err := s.queries.GetTotpConfigurationByUserID(ctx, user.ID)
	if err == nil && configRow.EnabledAt.Valid {
		principal.TOTPEnabled = true
		return principal, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return SessionPrincipal{}, err
	}
	return principal, nil
}

func (s *Service) validateSecondFactor(ctx context.Context, userID int64, code string, recoveryCode string) error {
	configRow, err := s.queries.GetTotpConfigurationByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if !configRow.EnabledAt.Valid {
		return nil
	}

	if strings.TrimSpace(recoveryCode) != "" {
		used, err := s.queries.ConsumeTotpRecoveryCode(ctx, sqlc.ConsumeTotpRecoveryCodeParams{UserID: userID, CodeHash: HashToken(strings.TrimSpace(recoveryCode))})
		if err != nil {
			return err
		}
		if used > 0 {
			return nil
		}
		return ErrInvalidTOTP
	}

	secret, err := decryptSecret(configRow.SecretCiphertext, configRow.SecretNonce, s.cfg.Security.EncryptionKey)
	if err != nil {
		return err
	}
	if strings.TrimSpace(code) == "" {
		return ErrTOTPRequired
	}
	if !validateTOTPCode(secret, code) {
		return ErrInvalidTOTP
	}
	return nil
}

func validateTOTPCode(secret, code string) bool {
	valid, err := totp.ValidateCustom(strings.TrimSpace(code), secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && valid
}

func generateRecoveryCodes(count int) ([]string, error) {
	codes := make([]string, 0, count)
	for range count {
		plain, _, err := NewToken()
		if err != nil {
			return nil, err
		}
		if len(plain) > 12 {
			plain = plain[:12]
		}
		codes = append(codes, strings.ToUpper(plain))
	}
	return codes, nil
}

func inetValue(value string) pqtype.Inet {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return pqtype.Inet{}
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return pqtype.Inet{IPNet: net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, Valid: true}
}

func nullString(value string) sql.NullString {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: trimmed, Valid: true}
}
