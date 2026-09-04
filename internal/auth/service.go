package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"base/internal/config"
	"base/internal/database"
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
	ErrTOTPAlreadyEnabled = errors.New("two-factor authentication is already enabled")
	ErrPasskeyCeremony    = errors.New("passkey ceremony not initialized")
	ErrPasskeyNotFound    = errors.New("passkey not found")
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
	AuthVersion int64    `json:"-"`
}

type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limited: retry after %s", e.RetryAfter)
}

type TOTPSetup struct {
	Secret     string `json:"secret"`
	Issuer     string `json:"issuer"`
	Account    string `json:"account"`
	OTPAuthURL string `json:"otpauth_url"`
}

type Passkey struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Transports []string  `json:"transports"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
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
	if cfg.Security.FailedLoginThreshold <= 0 {
		return nil, errors.New("security.failed_login_threshold must be greater than zero")
	}
	if cfg.Security.FailedLoginWindow <= 0 {
		return nil, errors.New("security.failed_login_window must be greater than zero")
	}

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
	username := strings.ToLower(strings.TrimSpace(input.Username))
	email := strings.ToLower(strings.TrimSpace(input.Email))

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
			Payload:     payload,
			AvailableAt: immediateEmailAvailableAt(),
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
	email := strings.ToLower(strings.TrimSpace(input.Email))

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
	configRow, err := s.queries.GetTotpConfigurationByUserID(ctx, userID)
	if err == nil && configRow.EnabledAt.Valid {
		return TOTPSetup{}, ErrTOTPAlreadyEnabled
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
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
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		tokenRow, err := q.ConsumeUserToken(ctx, sqlc.ConsumeUserTokenParams{
			TokenHash: HashToken(strings.TrimSpace(token)),
			Kind:      sqlc.TokenKindEmailVerification,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRequestFailed
		}
		if err != nil {
			return err
		}
		if err := q.MarkUserEmailVerified(ctx, tokenRow.UserID); err != nil {
			return err
		}
		return nil
	})
}

func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	return s.requestTokenEmail(ctx, email, tokenEmailRequest{
		kind: sqlc.TokenKindPasswordReset, ttl: s.cfg.Security.PasswordResetTTL,
		template: "password-reset", subject: "Reset your password",
	})
}

func (s *Service) RequestAccountRecovery(ctx context.Context, email string) error {
	return s.requestTokenEmail(ctx, email, tokenEmailRequest{
		kind: sqlc.TokenKindAccountRecovery, ttl: s.cfg.Security.RecoveryTTL,
		template: "account-recovery", subject: "Recover your account",
	})
}

func (s *Service) RequestEmailVerification(ctx context.Context, email string) error {
	return s.requestTokenEmail(ctx, email, tokenEmailRequest{
		kind: sqlc.TokenKindEmailVerification, ttl: s.cfg.Security.EmailVerificationTTL,
		template: "verify-email", subject: "Verify your account", onlyUnverified: true,
	})
}

func (s *Service) RecoverAccount(ctx context.Context, token string, password string) error {
	passwordHash, err := HashPassword(password)
	if err != nil {
		return err
	}

	return s.withTx(ctx, func(q *sqlc.Queries) error {
		tokenRow, err := q.ConsumeUserToken(ctx, sqlc.ConsumeUserTokenParams{
			TokenHash: HashToken(strings.TrimSpace(token)),
			Kind:      sqlc.TokenKindAccountRecovery,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRequestFailed
		}
		if err != nil {
			return err
		}
		if _, err := q.SetUserPasswordHash(ctx, sqlc.SetUserPasswordHashParams{ID: tokenRow.UserID, PasswordHash: sql.NullString{String: passwordHash, Valid: true}}); err != nil {
			return err
		}
		if err := q.RestoreUserAccess(ctx, tokenRow.UserID); err != nil {
			return err
		}
		if err := q.DeleteTotpConfigurationByUserID(ctx, tokenRow.UserID); err != nil {
			return err
		}
		_, err = q.IncrementUserAuthVersion(ctx, tokenRow.UserID)
		return err
	})
}

func (s *Service) ResetPassword(ctx context.Context, token string, password string) error {
	passwordHash, err := HashPassword(password)
	if err != nil {
		return err
	}

	return s.withTx(ctx, func(q *sqlc.Queries) error {
		tokenRow, err := q.ConsumeUserToken(ctx, sqlc.ConsumeUserTokenParams{
			TokenHash: HashToken(strings.TrimSpace(token)),
			Kind:      sqlc.TokenKindPasswordReset,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRequestFailed
		}
		if err != nil {
			return err
		}
		if _, err := q.SetUserPasswordHash(ctx, sqlc.SetUserPasswordHashParams{ID: tokenRow.UserID, PasswordHash: sql.NullString{String: passwordHash, Valid: true}}); err != nil {
			return err
		}
		if _, err := q.IncrementUserAuthVersion(ctx, tokenRow.UserID); err != nil {
			return err
		}
		return q.ResetLoginFailures(ctx, tokenRow.UserID)
	})
}

func (s *Service) CurrentUser(ctx context.Context, userID int64) (SessionPrincipal, error) {
	if userID == 0 {
		return SessionPrincipal{}, ErrUnauthorized
	}
	return s.completeUserAuthentication(ctx, s.queries, userID, false)
}

func (s *Service) ValidateSession(ctx context.Context, userID, authVersion int64) (bool, error) {
	if userID == 0 || authVersion == 0 {
		return false, nil
	}
	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if !userAccountIsUsable(user) {
		return false, nil
	}
	return user.AuthVersion == authVersion, nil
}

func (s *Service) UserRoleNames(ctx context.Context, userID int64) ([]string, error) {
	if userID == 0 {
		return nil, ErrUnauthorized
	}

	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if err := validateUserAccount(user); err != nil {
		return nil, err
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
	now := time.Now().UTC()
	if flowState.StartedAt.IsZero() || flowState.StartedAt.After(now.Add(time.Minute)) || now.Sub(flowState.StartedAt) > s.cfg.OAuth.StateTTL {
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
	if profile.Subject == "" || profile.Email == "" || !profile.EmailVerified {
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
		return &RateLimitError{RetryAfter: decision.RetryAfter}
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
		return &RateLimitError{RetryAfter: ipDecision.RetryAfter}
	}

	return nil
}

func (s *Service) handleFailedLogin(ctx context.Context, user sqlc.User) error {
	windowSeconds := max(int64(1), int64(s.cfg.Security.FailedLoginWindow/time.Second))
	updatedUser, err := s.queries.RecordFailedLogin(ctx, sqlc.RecordFailedLoginParams{
		ID:            user.ID,
		WindowSeconds: windowSeconds,
	})
	if err != nil {
		return err
	}

	if int64(updatedUser.FailedLoginCount) >= int64(s.cfg.Security.FailedLoginThreshold) {
		return s.queries.LockUserUntil(ctx, sqlc.LockUserUntilParams{
			ID:             user.ID,
			LockedUntil:    sql.NullTime{Time: time.Now().UTC().Add(s.cfg.Security.FailedLoginWindow), Valid: true},
			DisabledReason: sql.NullString{String: "failed_login_attempts", Valid: true},
		})
	}

	return nil
}

func (s *Service) oauthProvider(name string) (OAuthProviderClient, string, error) {
	normalizedName := strings.ToLower(strings.TrimSpace(name))
	provider, ok := s.oauth[normalizedName]
	if !ok {
		return nil, "", ErrOAuthProvider
	}
	return provider, normalizedName, nil
}

func (s *Service) completeUserAuthentication(ctx context.Context, queries *sqlc.Queries, userID int64, updateLastLogin bool) (SessionPrincipal, error) {
	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		return SessionPrincipal{}, err
	}
	if err := validateUserAccount(user); err != nil {
		return SessionPrincipal{}, err
	}

	if updateLastLogin {
		if err := queries.UpdateUserLastLogin(ctx, userID); err != nil {
			return SessionPrincipal{}, err
		}
		user, err = queries.GetUserByID(ctx, userID)
		if err != nil {
			return SessionPrincipal{}, err
		}
	}

	roles, err := queries.ListUserRoleNames(ctx, userID)
	if err != nil {
		return SessionPrincipal{}, err
	}

	return s.principalWithFactors(ctx, queries, user, roles)
}

func principalFromUser(user sqlc.User, roles []string) SessionPrincipal {
	return SessionPrincipal{
		UserID:      user.ID,
		Username:    user.Username,
		Email:       user.Email,
		Roles:       roles,
		Verified:    user.EmailVerifiedAt.Valid,
		AuthVersion: user.AuthVersion,
	}
}

func validateUserAccount(user sqlc.User) error {
	if !user.IsActive {
		return ErrAccountDisabled
	}
	if user.LockedUntil.Valid && user.LockedUntil.Time.After(time.Now().UTC()) {
		return ErrAccountLocked
	}
	if !user.EmailVerifiedAt.Valid {
		return ErrEmailUnverified
	}
	return nil
}

func userAccountIsUsable(user sqlc.User) bool {
	return user.IsActive &&
		(!user.LockedUntil.Valid || !user.LockedUntil.Time.After(time.Now().UTC())) &&
		user.EmailVerifiedAt.Valid
}

func (s *Service) principalWithFactors(ctx context.Context, queries *sqlc.Queries, user sqlc.User, roles []string) (SessionPrincipal, error) {
	principal := principalFromUser(user, roles)
	configRow, err := queries.GetTotpConfigurationByUserID(ctx, user.ID)
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

type tokenEmailRequest struct {
	kind           sqlc.TokenKind
	ttl            time.Duration
	template       string
	subject        string
	onlyUnverified bool
}

func (s *Service) requestTokenEmail(ctx context.Context, email string, request tokenEmailRequest) error {
	user, err := s.queries.GetUserByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if request.onlyUnverified && user.EmailVerifiedAt.Valid {
		return nil
	}

	plainToken, tokenHash, err := NewToken()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{"token": plainToken, "email": user.Email})
	if err != nil {
		return err
	}

	return s.withTx(ctx, func(q *sqlc.Queries) error {
		if err := q.ExpireUserTokens(ctx, sqlc.ExpireUserTokensParams{UserID: user.ID, Kind: request.kind}); err != nil {
			return err
		}
		if _, err := q.CreateUserToken(ctx, sqlc.CreateUserTokenParams{
			UserID: user.ID, Kind: request.kind, TokenHash: tokenHash,
			ExpiresAt: time.Now().UTC().Add(request.ttl),
		}); err != nil {
			return err
		}
		_, err := q.EnqueueEmail(ctx, sqlc.EnqueueEmailParams{
			Template: request.template, Recipient: user.Email, Subject: request.subject,
			Payload: payload, AvailableAt: immediateEmailAvailableAt(),
		})
		return err
	})
}

func immediateEmailAvailableAt() time.Time {
	// The outbox query compares against the database clock. A small backdate keeps
	// immediate emails visible even when the app host is slightly ahead of Postgres.
	return time.Now().UTC().Add(-time.Second)
}
