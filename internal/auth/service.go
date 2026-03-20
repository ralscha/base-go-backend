package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"base/internal/config"
	"base/internal/database"
	"base/internal/store/dbtype"
	"base/internal/store/sqlc"

	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	ratelimit "github.com/ralscha/ratelimiter-pg"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account is locked")
	ErrAccountDisabled    = errors.New("account is disabled")
	ErrEmailUnverified    = errors.New("email verification required")
	ErrRequestFailed      = errors.New("request failed")
	ErrTOTPRequired       = errors.New("two-factor authentication required")
	ErrInvalidTOTP        = errors.New("invalid two-factor code")
	ErrPasskeyCeremony    = errors.New("passkey ceremony not initialized")
	ErrUnauthorized       = errors.New("authentication required")
	ErrOAuthProvider      = errors.New("oauth provider is not configured")
	ErrOAuthState         = errors.New("oauth state is invalid or expired")
	ErrOAuthConflict      = errors.New("oauth account is already linked to another user")
	ErrOAuthProfile       = errors.New("oauth provider profile is incomplete")
)

type Service struct {
	db       *sql.DB
	queries  *sqlc.Queries
	limiter  *ratelimit.RateLimiter
	webAuthn *wa.WebAuthn
	oauth    map[string]OAuthProviderClient
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
	Email     string
	Password  string
	TOTPCode  string
	IPAddress string
	UserAgent string
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

	oauthProviders := newOAuthProviderClients(cfg.OAuth, http.DefaultClient)

	return &Service{
		db:       db,
		queries:  sqlc.New(db),
		limiter:  limiter,
		webAuthn: webAuthn,
		oauth:    oauthProviders,
		cfg:      cfg,
	}, nil
}

func (s *Service) RateLimiter() *ratelimit.RateLimiter {
	return s.limiter
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (SessionPrincipal, error) {
	username := input.Username
	email := input.Email

	passwordHash, err := HashPassword(input.Password)
	if err != nil {
		return SessionPrincipal{}, err
	}

	plainToken, tokenHash, err := NewToken()
	if err != nil {
		return SessionPrincipal{}, fmt.Errorf("create verification token: %w", err)
	}

	var principal SessionPrincipal
	if err := s.withTx(ctx, func(q *sqlc.Queries) error {
		user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Username: username, Email: email})
		if err != nil {
			return err
		}

		if _, err := q.SetUserPasswordHash(ctx, sqlc.SetUserPasswordHashParams{ID: user.ID, PasswordHash: sql.NullString{String: passwordHash, Valid: true}}); err != nil {
			return err
		}

		role, err := q.GetRoleByName(ctx, "user")
		if err != nil {
			return err
		}
		if err := q.AddUserRole(ctx, sqlc.AddUserRoleParams{UserID: user.ID, RoleID: role.ID}); err != nil {
			return err
		}

		if _, err := q.CreateUserToken(ctx, sqlc.CreateUserTokenParams{
			UserID:    user.ID,
			Kind:      sqlc.TokenKindEmailVerification,
			TokenHash: tokenHash,
			ExpiresAt: time.Now().UTC().Add(s.cfg.Security.EmailVerificationTTL),
		}); err != nil {
			return err
		}

		payload, err := json.Marshal(map[string]any{
			"token": plainToken,
			"email": user.Email,
		})
		if err != nil {
			return err
		}

		if _, err := q.EnqueueEmail(ctx, sqlc.EnqueueEmailParams{
			Template:    "verify-email",
			Recipient:   user.Email,
			Subject:     "Verify your account",
			Payload:     dbtype.RawMessage(payload),
			AvailableAt: time.Now().UTC(),
		}); err != nil {
			return err
		}

		roles, err := q.ListUserRoleNames(ctx, user.ID)
		if err != nil {
			return err
		}
		principal = principalFromUser(user, roles)
		return nil
	}); err != nil {
		return SessionPrincipal{}, err
	}

	return principal, nil
}

func (s *Service) LoginWithPassword(ctx context.Context, input LoginInput) (SessionPrincipal, error) {
	email := input.Email

	if err := s.enforceRateLimit(ctx, email, input.IPAddress); err != nil {
		return SessionPrincipal{}, err
	}

	user, err := s.queries.GetUserWithPasswordByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if err := compareWithInvalidCredentialsSentinel(input.Password); err != nil {
				return SessionPrincipal{}, err
			}
			return SessionPrincipal{}, ErrInvalidCredentials
		}
		return SessionPrincipal{}, err
	}

	match, err := ComparePassword(input.Password, user.PasswordHash.String)
	if err != nil {
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

	if !match {
		if err := s.handleFailedLogin(ctx, user); err != nil {
			return SessionPrincipal{}, err
		}
		return SessionPrincipal{}, ErrInvalidCredentials
	}

	if err := s.validateSecondFactor(ctx, user.ID, input.TOTPCode); err != nil {
		if err2 := s.handleFailedLogin(ctx, user); err2 != nil {
			return SessionPrincipal{}, err2
		}
		return SessionPrincipal{}, err
	}

	return s.completeUserAuthentication(ctx, s.queries, user.ID, true)
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

func (s *Service) ConfirmTOTPSetup(ctx context.Context, userID int64, code string) error {
	configRow, err := s.queries.GetTotpConfigurationByUserID(ctx, userID)
	if err != nil {
		return err
	}

	secret, err := decryptSecret(configRow.SecretCiphertext, configRow.SecretNonce, s.cfg.Security.EncryptionKey)
	if err != nil {
		return err
	}
	if !validateTOTPCode(secret, code) {
		return ErrInvalidTOTP
	}

	return s.withTx(ctx, func(q *sqlc.Queries) error {
		return q.EnableTotpConfiguration(ctx, userID)
	})
}

func (s *Service) DisableTOTP(ctx context.Context, userID int64) error {
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		return q.DeleteTotpConfigurationByUserID(ctx, userID)
	})
}

func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	tokenRow, err := s.queries.GetUserToken(ctx, sqlc.GetUserTokenParams{
		TokenHash: HashToken(token),
		Kind:      sqlc.TokenKindEmailVerification,
	})
	if err != nil {
		return err
	}

	return s.withTx(ctx, func(q *sqlc.Queries) error {
		if err := q.MarkUserEmailVerified(ctx, tokenRow.UserID); err != nil {
			return err
		}
		return q.UseUserToken(ctx, tokenRow.ID)
	})
}

func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := s.queries.GetUserByEmail(ctx, email)
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

	return s.withTx(ctx, func(q *sqlc.Queries) error {
		if _, err := q.CreateUserToken(ctx, sqlc.CreateUserTokenParams{
			UserID:    user.ID,
			Kind:      sqlc.TokenKindPasswordReset,
			TokenHash: tokenHash,
			ExpiresAt: time.Now().UTC().Add(s.cfg.Security.PasswordResetTTL),
		}); err != nil {
			return err
		}
		_, err := q.EnqueueEmail(ctx, sqlc.EnqueueEmailParams{
			Template:    "password-reset",
			Recipient:   user.Email,
			Subject:     "Reset your password",
			Payload:     dbtype.RawMessage(payload),
			AvailableAt: time.Now().UTC(),
		})
		return err
	})
}

func (s *Service) RequestAccountRecovery(ctx context.Context, email string) error {
	user, err := s.queries.GetUserByEmail(ctx, email)
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

	return s.withTx(ctx, func(q *sqlc.Queries) error {
		if _, err := q.CreateUserToken(ctx, sqlc.CreateUserTokenParams{
			UserID:    user.ID,
			Kind:      sqlc.TokenKindAccountRecovery,
			TokenHash: tokenHash,
			ExpiresAt: time.Now().UTC().Add(s.cfg.Security.RecoveryTTL),
		}); err != nil {
			return err
		}
		_, err := q.EnqueueEmail(ctx, sqlc.EnqueueEmailParams{
			Template:    "account-recovery",
			Recipient:   user.Email,
			Subject:     "Recover your account",
			Payload:     dbtype.RawMessage(payload),
			AvailableAt: time.Now().UTC(),
		})
		return err
	})
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
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRequestFailed
		}
		return err
	}

	return s.withTx(ctx, func(q *sqlc.Queries) error {
		if _, err := q.SetUserPasswordHash(ctx, sqlc.SetUserPasswordHashParams{ID: tokenRow.UserID, PasswordHash: sql.NullString{String: passwordHash, Valid: true}}); err != nil {
			return err
		}
		if err := q.RestoreUserAccess(ctx, tokenRow.UserID); err != nil {
			return err
		}
		if err := q.DeleteTotpConfigurationByUserID(ctx, tokenRow.UserID); err != nil {
			return err
		}
		return q.UseUserToken(ctx, tokenRow.ID)
	})
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
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRequestFailed
		}
		return err
	}

	return s.withTx(ctx, func(q *sqlc.Queries) error {
		if _, err := q.SetUserPasswordHash(ctx, sqlc.SetUserPasswordHashParams{ID: tokenRow.UserID, PasswordHash: sql.NullString{String: passwordHash, Valid: true}}); err != nil {
			return err
		}
		if err := q.UseUserToken(ctx, tokenRow.ID); err != nil {
			return err
		}
		return q.LockUserUntil(ctx, sqlc.LockUserUntilParams{ID: tokenRow.UserID})
	})
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

func (s *Service) UserRoleNames(ctx context.Context, userID int64) ([]string, error) {
	if userID == 0 {
		return nil, ErrUnauthorized
	}

	roles, err := s.queries.ListUserRoleNames(ctx, userID)
	if err != nil {
		return nil, err
	}

	return roles, nil
}

func (s *Service) OAuthAuthorizationURL(ctx context.Context, provider string, currentUserID int64) (string, []byte, string, error) {
	client, normalizedProvider, err := s.oauthProvider(provider)
	if err != nil {
		return "", nil, "", err
	}

	state, err := randomToken(s.cfg.OAuth.StateBytes)
	if err != nil {
		return "", nil, "", err
	}
	verifier, err := randomToken(s.cfg.OAuth.PKCEVerifierBytes)
	if err != nil {
		return "", nil, "", err
	}

	sessionJSON, err := encodeOAuthFlow(oauthFlowState{
		Provider:     normalizedProvider,
		State:        state,
		CodeVerifier: verifier,
		StartedAt:    time.Now().UTC(),
		LinkUserID:   currentUserID,
	})
	if err != nil {
		return "", nil, "", err
	}

	return client.AuthorizationURL(state, pkceCodeChallenge(verifier)), sessionJSON, modeForUserID(currentUserID), nil
}

func (s *Service) CompleteOAuthAuthentication(ctx context.Context, provider string, sessionJSON []byte, state string, code string, currentUserID int64) (OAuthAuthenticationResult, error) {
	flowState, err := decodeOAuthFlow(sessionJSON)
	if err != nil {
		return OAuthAuthenticationResult{}, err
	}
	if time.Since(flowState.StartedAt) > s.cfg.OAuth.StateTTL {
		return OAuthAuthenticationResult{}, ErrOAuthState
	}

	client, normalizedProvider, err := s.oauthProvider(provider)
	if err != nil {
		return OAuthAuthenticationResult{}, err
	}
	if flowState.Provider != normalizedProvider || !subtleCompare(flowState.State, state) || code == "" {
		return OAuthAuthenticationResult{}, ErrOAuthState
	}
	if flowState.LinkUserID != 0 && flowState.LinkUserID != currentUserID {
		return OAuthAuthenticationResult{}, ErrOAuthState
	}

	tokens, err := client.ExchangeCode(ctx, code, flowState.CodeVerifier)
	if err != nil {
		return OAuthAuthenticationResult{}, fmt.Errorf("exchange oauth code: %w", err)
	}
	profile, err := client.FetchProfile(ctx, tokens.AccessToken)
	if err != nil {
		return OAuthAuthenticationResult{}, fmt.Errorf("fetch oauth profile: %w", err)
	}
	if profile.Subject == "" || profile.Email == "" {
		return OAuthAuthenticationResult{}, ErrOAuthProfile
	}

	var result OAuthAuthenticationResult
	if err := s.withTx(ctx, func(q *sqlc.Queries) error {
		principal, r, err := s.completeOAuthFlow(ctx, q, normalizedProvider, flowState, profile, tokens)
		if err != nil {
			return err
		}
		result = r
		result.Principal = principal
		return nil
	}); err != nil {
		return OAuthAuthenticationResult{}, err
	}

	return result, nil
}

func (s *Service) enforceRateLimit(ctx context.Context, email, ip string) error {
	decision, err := s.limiter.Allow(ctx, "login:email:"+email)
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

func (s *Service) handleFailedLogin(ctx context.Context, user sqlc.User) error {
	updatedUser, err := s.queries.IncrementFailedLogin(ctx, user.ID)
	if err != nil {
		return err
	}

	if int64(updatedUser.FailedLoginCount) >= int64(s.cfg.Security.FailedLoginThreshold) {
		return s.queries.LockUserUntil(ctx, sqlc.LockUserUntilParams{
			ID:             user.ID,
			LockedUntil:    sql.NullTime{Time: time.Now().UTC().Add(100 * 365 * 24 * time.Hour), Valid: true},
			DisabledReason: sql.NullString{String: "failed_login_attempts", Valid: true},
		})
	}

	return nil
}

func (s *Service) oauthProvider(name string) (OAuthProviderClient, string, error) {
	provider, ok := s.oauth[name]
	if !ok {
		return nil, "", ErrOAuthProvider
	}
	return provider, name, nil
}

func (s *Service) completeUserAuthentication(ctx context.Context, queries *sqlc.Queries, userID int64, updateLastLogin bool) (SessionPrincipal, error) {
	if updateLastLogin {
		if err := queries.UpdateUserLastLogin(ctx, userID); err != nil {
			return SessionPrincipal{}, err
		}
	}

	roles, err := queries.ListUserRoleNames(ctx, userID)
	if err != nil {
		return SessionPrincipal{}, err
	}
	updatedUser, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		return SessionPrincipal{}, err
	}

	return s.principalWithFactors(ctx, updatedUser, roles)
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

func (s *Service) withTx(ctx context.Context, fn func(*sqlc.Queries) error) error {
	return database.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		return fn(s.queries.WithTx(tx))
	})
}

func (s *Service) validateSecondFactor(ctx context.Context, userID int64, code string) error {
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

	secret, err := decryptSecret(configRow.SecretCiphertext, configRow.SecretNonce, s.cfg.Security.EncryptionKey)
	if err != nil {
		return err
	}
	if code == "" {
		return ErrTOTPRequired
	}
	if !validateTOTPCode(secret, code) {
		return ErrInvalidTOTP
	}
	return nil
}

func validateTOTPCode(secret, code string) bool {
	valid, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && valid
}
