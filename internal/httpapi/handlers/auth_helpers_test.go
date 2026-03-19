package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"base/internal/auth"
)

func TestDecodeJSONRejectsInvalidBody(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"unexpected":true}`))

	var payload struct {
		Expected string `json:"expected"`
	}
	err := decodeJSON(recorder, request, &payload)
	if err == nil {
		t.Fatal("decodeJSON() error = nil, want invalid JSON error")
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}

	var response envelope
	if unmarshalErr := json.Unmarshal(recorder.Body.Bytes(), &response); unmarshalErr != nil {
		t.Fatalf("json.Unmarshal() error = %v", unmarshalErr)
	}
	if response.Error == nil || response.Error.Code != "invalid_json" {
		t.Fatalf("response = %+v, want invalid_json error", response)
	}
}

func TestDecodeJSONParsesValidBody(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"expected":"value"}`))

	var payload struct {
		Expected string `json:"expected"`
	}
	if err := decodeJSON(recorder, request, &payload); err != nil {
		t.Fatalf("decodeJSON() error = %v", err)
	}
	if payload.Expected != "value" {
		t.Fatalf("payload.Expected = %q, want value", payload.Expected)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
}

func TestHandleAuthErrorMappings(t *testing.T) {
	testCases := []struct {
		name    string
		err     error
		status  int
		code    string
		message string
	}{
		{name: "unauthorized", err: auth.ErrUnauthorized, status: http.StatusUnauthorized, code: "unauthorized", message: auth.ErrUnauthorized.Error()},
		{name: "invalid credentials", err: auth.ErrInvalidCredentials, status: http.StatusUnauthorized, code: "invalid_credentials", message: auth.ErrInvalidCredentials.Error()},
		{name: "locked", err: auth.ErrAccountLocked, status: http.StatusLocked, code: "account_locked", message: auth.ErrAccountLocked.Error()},
		{name: "disabled", err: auth.ErrAccountDisabled, status: http.StatusForbidden, code: "account_disabled", message: auth.ErrAccountDisabled.Error()},
		{name: "email unverified", err: auth.ErrEmailUnverified, status: http.StatusForbidden, code: "email_unverified", message: auth.ErrEmailUnverified.Error()},
		{name: "totp required", err: auth.ErrTOTPRequired, status: http.StatusUnauthorized, code: "totp_required", message: auth.ErrTOTPRequired.Error()},
		{name: "invalid totp", err: auth.ErrInvalidTOTP, status: http.StatusUnauthorized, code: "invalid_totp", message: auth.ErrInvalidTOTP.Error()},
		{name: "passkey", err: auth.ErrPasskeyCeremony, status: http.StatusBadRequest, code: "passkey_ceremony_missing", message: auth.ErrPasskeyCeremony.Error()},
		{name: "oauth provider", err: auth.ErrOAuthProvider, status: http.StatusBadRequest, code: "oauth_provider_invalid", message: auth.ErrOAuthProvider.Error()},
		{name: "oauth state", err: auth.ErrOAuthState, status: http.StatusBadRequest, code: "oauth_state_invalid", message: auth.ErrOAuthState.Error()},
		{name: "oauth conflict", err: auth.ErrOAuthConflict, status: http.StatusConflict, code: "oauth_conflict", message: auth.ErrOAuthConflict.Error()},
		{name: "oauth profile", err: auth.ErrOAuthProfile, status: http.StatusBadRequest, code: "oauth_profile_invalid", message: auth.ErrOAuthProfile.Error()},
		{name: "weak password", err: auth.ErrWeakPassword, status: http.StatusBadRequest, code: "weak_password", message: auth.ErrWeakPassword.Error()},
		{name: "request failed", err: auth.ErrRequestFailed, status: http.StatusBadRequest, code: "request_failed", message: auth.ErrRequestFailed.Error()},
		{name: "default", err: errors.New("boom"), status: http.StatusInternalServerError, code: "internal_error", message: "an unexpected error occurred"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handleAuthError(recorder, testCase.err)

			if recorder.Code != testCase.status {
				t.Fatalf("status = %d, want %d", recorder.Code, testCase.status)
			}

			var response envelope
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if response.Error == nil {
				t.Fatal("response.Error = nil, want error payload")
			}
			if response.Error.Code != testCase.code || response.Error.Message != testCase.message {
				t.Fatalf("response.Error = %+v, want code=%q message=%q", response.Error, testCase.code, testCase.message)
			}
		})
	}
}

func TestEnsureDeviceIDUsesCookieAndSetsOneWhenMissing(t *testing.T) {
	t.Run("existing cookie", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{Name: deviceCookieName, Value: "device-123"})
		recorder := httptest.NewRecorder()

		deviceID := ensureDeviceID(recorder, request, true)
		if deviceID != "device-123" {
			t.Fatalf("ensureDeviceID() = %q, want existing cookie", deviceID)
		}
		if len(recorder.Result().Cookies()) != 0 {
			t.Fatalf("ensureDeviceID() set unexpected cookies: %v", recorder.Result().Cookies())
		}
	})

	t.Run("missing cookie", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		recorder := httptest.NewRecorder()

		deviceID := ensureDeviceID(recorder, request, true)
		if strings.TrimSpace(deviceID) == "" {
			t.Fatal("ensureDeviceID() returned empty device ID")
		}

		cookies := recorder.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("len(cookies) = %d, want 1", len(cookies))
		}
		cookie := cookies[0]
		if cookie.Name != deviceCookieName || cookie.Value != deviceID || !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 31536000 {
			t.Fatalf("cookie = %+v, want configured device cookie", cookie)
		}
	})
}

func TestClientIP(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "192.168.1.9:8080"
	if got := clientIP(request); got != "192.168.1.9" {
		t.Fatalf("clientIP(host:port) = %q, want 192.168.1.9", got)
	}

	request.RemoteAddr = " 10.0.0.8 "
	if got := clientIP(request); got != "10.0.0.8" {
		t.Fatalf("clientIP(raw) = %q, want 10.0.0.8", got)
	}
}

func TestVerifyEmailRequiresToken(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/verify-email", nil)

	AuthHandler{}.VerifyEmail(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}

	var response envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if response.Error == nil || response.Error.Code != "missing_token" {
		t.Fatalf("response = %+v, want missing_token error", response)
	}
}

func TestHandlerMethodsRejectInvalidJSON(t *testing.T) {
	testCases := []struct {
		name    string
		handler func(AuthHandler, http.ResponseWriter, *http.Request)
	}{
		{name: "register", handler: AuthHandler.Register},
		{name: "request password reset", handler: AuthHandler.RequestPasswordReset},
		{name: "request account recovery", handler: AuthHandler.RequestAccountRecovery},
		{name: "reset password", handler: AuthHandler.ResetPassword},
		{name: "recover account", handler: AuthHandler.RecoverAccount},
		{name: "enable totp", handler: AuthHandler.EnableTOTP},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"unexpected":true}`))

			testCase.handler(AuthHandler{}, recorder, request)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}

			var response envelope
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if response.Error == nil || response.Error.Code != "invalid_json" {
				t.Fatalf("response = %+v, want invalid_json error", response)
			}
		})
	}
}
