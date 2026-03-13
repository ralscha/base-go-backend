package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"base/internal/auth"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	ratelimit "github.com/ralscha/ratelimiter-pg"
)

const deviceCookieName = "base_device"

const (
	passkeyRegistrationSessionKey = "passkey_registration_session"
	passkeyLoginSessionKey        = "passkey_login_session" //nolint:gosec // session key name, not a credential
	oauthSessionKey               = "oauth_flow_session"    //nolint:gosec // session key name, not a credential
)

type AuthHandler struct {
	Service          *auth.Service
	Sessions         *scs.SessionManager
	Secure           bool
	LoginRateLimiter *ratelimit.RateLimiter
}

func (h AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	principal, err := h.Service.Register(r.Context(), auth.RegisterInput{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		handleAuthError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"user":    principal,
		"message": "registration complete; verify email before login",
	})
}

func (h AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	decision, err := h.LoginRateLimiter.Allow(r.Context(), fmt.Sprintf("login:ip:%s", ip))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rate_limit_error", "rate limiter unavailable")
		return
	}
	if !decision.Allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%.0f", decision.RetryAfter.Seconds()))
		writeError(w, http.StatusTooManyRequests, "too_many_requests", "too many login attempts; try again later")
		return
	}

	var req struct {
		Identifier   string `json:"identifier"`
		Password     string `json:"password"`
		TOTPCode     string `json:"totp_code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	deviceID := ensureDeviceID(w, r, h.Secure)
	principal, err := h.Service.LoginWithPassword(r.Context(), auth.LoginInput{
		Identifier:   req.Identifier,
		Password:     req.Password,
		TOTPCode:     req.TOTPCode,
		RecoveryCode: req.RecoveryCode,
		IPAddress:    clientIP(r),
		UserAgent:    r.UserAgent(),
	})
	if err != nil {
		handleAuthError(w, err)
		return
	}

	if err := h.completeLogin(r.Context(), principal, deviceID); err != nil {
		writeError(w, http.StatusInternalServerError, "session_error", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"user": principal})
}

func (h AuthHandler) BeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	options, sessionJSON, err := h.Service.BeginPasskeyRegistration(r.Context(), h.Sessions.GetInt64(r.Context(), "user_id"))
	if err != nil {
		handleAuthError(w, err)
		return
	}

	h.Sessions.Put(r.Context(), passkeyRegistrationSessionKey, string(sessionJSON))
	writeJSON(w, http.StatusOK, map[string]any{"options": options})
}

func (h AuthHandler) FinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Credential json.RawMessage `json:"credential"`
		Name       string          `json:"name"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	sessionJSON := []byte(h.Sessions.GetString(r.Context(), passkeyRegistrationSessionKey))
	if err := h.Service.FinishPasskeyRegistration(r.Context(), h.Sessions.GetInt64(r.Context(), "user_id"), sessionJSON, req.Credential, req.Name); err != nil {
		handleAuthError(w, err)
		return
	}

	h.Sessions.Remove(r.Context(), passkeyRegistrationSessionKey)
	writeJSON(w, http.StatusCreated, map[string]any{"registered": true})
}

func (h AuthHandler) BeginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	options, sessionJSON, err := h.Service.BeginPasskeyLogin()
	if err != nil {
		handleAuthError(w, err)
		return
	}

	h.Sessions.Put(r.Context(), passkeyLoginSessionKey, string(sessionJSON))
	writeJSON(w, http.StatusOK, map[string]any{"options": options})
}

func (h AuthHandler) StartOAuth(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	authorizationURL, sessionJSON, mode, err := h.Service.OAuthAuthorizationURL(r.Context(), provider, h.Sessions.GetInt64(r.Context(), "user_id"))
	if err != nil {
		handleAuthError(w, err)
		return
	}

	h.Sessions.Put(r.Context(), oauthSessionKey, string(sessionJSON))
	writeJSON(w, http.StatusOK, map[string]any{
		"provider":          provider,
		"mode":              mode,
		"authorization_url": authorizationURL,
	})
}

func (h AuthHandler) CompleteOAuth(w http.ResponseWriter, r *http.Request) {
	sessionJSON := []byte(h.Sessions.GetString(r.Context(), oauthSessionKey))
	h.Sessions.Remove(r.Context(), oauthSessionKey)

	result, err := h.Service.CompleteOAuthAuthentication(
		r.Context(),
		chi.URLParam(r, "provider"),
		sessionJSON,
		strings.TrimSpace(r.URL.Query().Get("state")),
		strings.TrimSpace(r.URL.Query().Get("code")),
		h.Sessions.GetInt64(r.Context(), "user_id"),
	)
	if err != nil {
		handleAuthError(w, err)
		return
	}

	if result.Mode == "login" {
		deviceID := ensureDeviceID(w, r, h.Secure)
		if err := h.completeLogin(r.Context(), result.Principal, deviceID); err != nil {
			writeError(w, http.StatusInternalServerError, "session_error", err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user":     result.Principal,
		"provider": result.Provider,
		"mode":     result.Mode,
		"created":  result.Created,
		"linked":   result.Linked,
	})
}

func (h AuthHandler) FinishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Credential   json.RawMessage `json:"credential"`
		TOTPCode     string          `json:"totp_code"`
		RecoveryCode string          `json:"recovery_code"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	sessionJSON := []byte(h.Sessions.GetString(r.Context(), passkeyLoginSessionKey))
	deviceID := ensureDeviceID(w, r, h.Secure)
	principal, err := h.Service.FinishPasskeyLogin(r.Context(), sessionJSON, req.Credential, req.TOTPCode, req.RecoveryCode, r.UserAgent(), clientIP(r))
	if err != nil {
		handleAuthError(w, err)
		return
	}

	if err := h.completeLogin(r.Context(), principal, deviceID); err != nil {
		writeError(w, http.StatusInternalServerError, "session_error", err.Error())
		return
	}

	h.Sessions.Remove(r.Context(), passkeyLoginSessionKey)
	writeJSON(w, http.StatusOK, map[string]any{"user": principal})
}

func (h AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.Sessions.Destroy(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "logout_failed", "could not destroy session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logged_out": true})
}

func (h AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		writeError(w, http.StatusBadRequest, "missing_token", "verification token is required")
		return
	}
	if err := h.Service.VerifyEmail(r.Context(), token); err != nil {
		handleAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verified": true})
}

func (h AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	if err := h.Service.RequestPasswordReset(r.Context(), req.Email); err != nil {
		handleAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"requested": true})
}

func (h AuthHandler) RequestAccountRecovery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	if err := h.Service.RequestAccountRecovery(r.Context(), req.Email); err != nil {
		handleAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"requested": true})
}

func (h AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	if err := h.Service.ResetPassword(r.Context(), req.Token, req.Password); err != nil {
		handleAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"password_reset": true})
}

func (h AuthHandler) RecoverAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	if err := h.Service.RecoverAccount(r.Context(), req.Token, req.Password); err != nil {
		handleAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"recovered": true,
		"message":   "account recovered; two-factor authentication has been disabled",
	})
}

func (h AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	principal, err := h.Service.CurrentUser(r.Context(), h.Sessions.GetInt64(r.Context(), "user_id"))
	if err != nil {
		handleAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": principal})
}

func (h AuthHandler) SetupTOTP(w http.ResponseWriter, r *http.Request) {
	setup, err := h.Service.BeginTOTPSetup(r.Context(), h.Sessions.GetInt64(r.Context(), "user_id"))
	if err != nil {
		handleAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"totp": setup})
}

func (h AuthHandler) EnableTOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	recoveryCodes, err := h.Service.ConfirmTOTPSetup(r.Context(), h.Sessions.GetInt64(r.Context(), "user_id"), req.Code)
	if err != nil {
		handleAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": recoveryCodes})
}

func (h AuthHandler) DisableTOTP(w http.ResponseWriter, r *http.Request) {
	if err := h.Service.DisableTOTP(r.Context(), h.Sessions.GetInt64(r.Context(), "user_id")); err != nil {
		handleAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"totp_disabled": true})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer func() { _ = r.Body.Close() }()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "invalid JSON body")
		return err
	}
	return nil
}

func handleAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrUnauthorized):
		writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", err.Error())
	case errors.Is(err, auth.ErrAccountLocked):
		writeError(w, http.StatusLocked, "account_locked", err.Error())
	case errors.Is(err, auth.ErrAccountDisabled):
		writeError(w, http.StatusForbidden, "account_disabled", err.Error())
	case errors.Is(err, auth.ErrEmailUnverified):
		writeError(w, http.StatusForbidden, "email_unverified", err.Error())
	case errors.Is(err, auth.ErrTOTPRequired):
		writeError(w, http.StatusUnauthorized, "totp_required", err.Error())
	case errors.Is(err, auth.ErrInvalidTOTP):
		writeError(w, http.StatusUnauthorized, "invalid_totp", err.Error())
	case errors.Is(err, auth.ErrPasskeyCeremony):
		writeError(w, http.StatusBadRequest, "passkey_ceremony_missing", err.Error())
	case errors.Is(err, auth.ErrOAuthProvider):
		writeError(w, http.StatusBadRequest, "oauth_provider_invalid", err.Error())
	case errors.Is(err, auth.ErrOAuthState):
		writeError(w, http.StatusBadRequest, "oauth_state_invalid", err.Error())
	case errors.Is(err, auth.ErrOAuthConflict):
		writeError(w, http.StatusConflict, "oauth_conflict", err.Error())
	case errors.Is(err, auth.ErrOAuthProfile):
		writeError(w, http.StatusBadRequest, "oauth_profile_invalid", err.Error())
	case errors.Is(err, auth.ErrWeakPassword):
		writeError(w, http.StatusBadRequest, "weak_password", err.Error())
	case errors.Is(err, auth.ErrRequestFailed):
		writeError(w, http.StatusBadRequest, "request_failed", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
	}
}

func (h AuthHandler) completeLogin(ctx context.Context, principal auth.SessionPrincipal, deviceID string) error {
	if err := h.Sessions.RenewToken(ctx); err != nil {
		return errors.New("could not renew session")
	}

	h.Sessions.Put(ctx, "user_id", principal.UserID)
	h.Sessions.Put(ctx, "username", principal.Username)
	h.Sessions.Put(ctx, "roles", principal.Roles)
	h.Sessions.Put(ctx, "device_id", deviceID)

	if err := h.Service.RecordUserSession(ctx, principal.UserID, deviceID, h.Sessions.Token(ctx), time.Now().UTC().Add(h.Sessions.Lifetime)); err != nil {
		return errors.New("could not record session")
	}

	return nil
}

func ensureDeviceID(w http.ResponseWriter, r *http.Request, secure bool) string {
	if cookie, err := r.Cookie(deviceCookieName); err == nil && strings.TrimSpace(cookie.Value) != "" {
		return cookie.Value
	}

	deviceID := uuid.NewString()
	http.SetCookie(w, &http.Cookie{
		Name:     deviceCookieName,
		Value:    deviceID,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   31536000,
	})
	return deviceID
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}
