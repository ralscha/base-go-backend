package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"base/internal/auth"
	"base/internal/validation"
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

func TestWriteValidationError(t *testing.T) {
	recorder := httptest.NewRecorder()
	validationErr := validation.New()
	validationErr.Add("email", "required")

	writeValidationError(recorder, validationErr)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}

	var response envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if response.Error == nil {
		t.Fatal("response.Error = nil, want error payload")
	}
	if response.Error.Code != "validation_failed" || response.Error.Message != "email is required" {
		t.Fatalf("response.Error = %+v, want code=%q message=%q", response.Error, "validation_failed", "email is required")
	}
	wantFields := validation.FieldErrors{"email": map[string]any{"required": true}}
	if !reflect.DeepEqual(response.Error.Fields, wantFields) {
		t.Fatalf("response.Error.Fields = %+v, want %+v", response.Error.Fields, wantFields)
	}
}

func TestValidationHelpers(t *testing.T) {
	testCases := []struct {
		name     string
		validate func() error
		wantErr  string
		wantMap  validation.FieldErrors
	}{
		{name: "register missing username", validate: func() error { return registerRequest{Email: "user@example.com", Password: "Password12345"}.validate() }, wantErr: "username is required", wantMap: validation.FieldErrors{"username": map[string]any{"required": true}}},
		{name: "register invalid username and password", validate: func() error {
			return registerRequest{Username: "ab", Email: "user@example.com", Password: "short"}.validate()
		}, wantErr: "request validation failed", wantMap: validation.FieldErrors{"username": map[string]any{"minlength": map[string]any{"requiredLength": minUsernameLength, "actualLength": 2}}, "password": map[string]any{"minlength": map[string]any{"requiredLength": minPasswordLength, "actualLength": 5}}}},
		{name: "register invalid email", validate: func() error {
			return registerRequest{Username: "user", Email: "invalid", Password: "Password12345"}.validate()
		}, wantErr: "email must be a valid email address", wantMap: validation.FieldErrors{"email": map[string]any{"email": true}}},
		{name: "login invalid totp", validate: func() error {
			return loginRequest{Email: "user@example.com", Password: "Password12345", TOTPCode: "12ab"}.validate()
		}, wantErr: "totp_code format is invalid", wantMap: validation.FieldErrors{"totp_code": map[string]any{"pattern": map[string]any{"requiredPattern": `^[0-9]{6}$`}}}},
		{name: "email only invalid", validate: func() error { return emailRequest{Email: "not-an-email"}.validate() }, wantErr: "email must be a valid email address", wantMap: validation.FieldErrors{"email": map[string]any{"email": true}}},
		{name: "token password missing token", validate: func() error { return tokenPasswordRequest{Password: "Password12345"}.validate() }, wantErr: "token is required", wantMap: validation.FieldErrors{"token": map[string]any{"required": true}}},
		{name: "totp setup missing code", validate: func() error { return enableTOTPRequest{Code: " "}.validate() }, wantErr: "code is required", wantMap: validation.FieldErrors{"code": map[string]any{"required": true}}},
		{name: "passkey missing credential", validate: func() error { return passkeyRegistrationRequest{}.validate() }, wantErr: "credential is required", wantMap: validation.FieldErrors{"credential": map[string]any{"required": true}}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.validate()
			if err == nil {
				t.Fatal("validation error = nil, want non-nil")
			}
			var validationErr *validation.Errors
			if !errors.As(err, &validationErr) {
				t.Fatalf("validation error type = %T, want *validation.Errors", err)
			}
			if validationErr.Error() != testCase.wantErr {
				t.Fatalf("validation error = %q, want %q", validationErr.Error(), testCase.wantErr)
			}
			if !reflect.DeepEqual(validationErr.FieldMap(), testCase.wantMap) {
				t.Fatalf("validation fields = %+v, want %+v", validationErr.FieldMap(), testCase.wantMap)
			}
		})
	}

	valid := registerRequest{Username: "user", Email: "user@example.com", Password: "Password12345"}
	if err := valid.validate(); err != nil {
		t.Fatalf("registerRequest.validate() error = %v, want nil", err)
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

func TestHandlePasswordLoginErrorMasksCredentialFailures(t *testing.T) {
	testCases := []struct {
		name string
		err  error
	}{
		{name: "invalid credentials", err: auth.ErrInvalidCredentials},
		{name: "locked", err: auth.ErrAccountLocked},
		{name: "disabled", err: auth.ErrAccountDisabled},
		{name: "email unverified", err: auth.ErrEmailUnverified},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handlePasswordLoginError(recorder, testCase.err)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
			}

			var response envelope
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if response.Error == nil {
				t.Fatal("response.Error = nil, want error payload")
			}
			if response.Error.Code != "invalid_credentials" || response.Error.Message != standardLoginFailureMessage {
				t.Fatalf("response.Error = %+v, want code=%q message=%q", response.Error, "invalid_credentials", standardLoginFailureMessage)
			}
		})
	}
}

func TestHandlePasswordLoginErrorPreservesSecondFactorErrors(t *testing.T) {
	testCases := []struct {
		name    string
		err     error
		status  int
		code    string
		message string
	}{
		{name: "totp required", err: auth.ErrTOTPRequired, status: http.StatusUnauthorized, code: "totp_required", message: auth.ErrTOTPRequired.Error()},
		{name: "invalid totp", err: auth.ErrInvalidTOTP, status: http.StatusUnauthorized, code: "invalid_totp", message: auth.ErrInvalidTOTP.Error()},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handlePasswordLoginError(recorder, testCase.err)

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

func TestHandlerMethodsRejectInvalidPayloads(t *testing.T) {
	testCases := []struct {
		name        string
		handler     func(AuthHandler, http.ResponseWriter, *http.Request)
		body        string
		wantMessage string
		wantFields  validation.FieldErrors
	}{
		{name: "register multiple invalid fields", handler: AuthHandler.Register, body: `{"username":"ab","email":"invalid","password":"short"}`, wantMessage: "request validation failed", wantFields: validation.FieldErrors{"username": map[string]any{"minlength": map[string]any{"requiredLength": float64(minUsernameLength), "actualLength": float64(2)}}, "email": map[string]any{"email": true}, "password": map[string]any{"minlength": map[string]any{"requiredLength": float64(minPasswordLength), "actualLength": float64(5)}}}},
		{name: "request password reset invalid email", handler: AuthHandler.RequestPasswordReset, body: `{"email":"invalid"}`, wantMessage: "email must be a valid email address", wantFields: validation.FieldErrors{"email": map[string]any{"email": true}}},
		{name: "request account recovery missing email", handler: AuthHandler.RequestAccountRecovery, body: `{"email":""}`, wantMessage: "email is required", wantFields: validation.FieldErrors{"email": map[string]any{"required": true}}},
		{name: "reset password short password", handler: AuthHandler.ResetPassword, body: `{"token":"abc","password":"short"}`, wantMessage: "password must be at least 12 characters", wantFields: validation.FieldErrors{"password": map[string]any{"minlength": map[string]any{"requiredLength": float64(minPasswordLength), "actualLength": float64(5)}}}},
		{name: "recover account missing password", handler: AuthHandler.RecoverAccount, body: `{"token":"abc"}`, wantMessage: "password is required", wantFields: validation.FieldErrors{"password": map[string]any{"required": true}}},
		{name: "enable totp invalid code", handler: AuthHandler.EnableTOTP, body: `{"code":"12ab"}`, wantMessage: "code format is invalid", wantFields: validation.FieldErrors{"code": map[string]any{"pattern": map[string]any{"requiredPattern": `^[0-9]{6}$`}}}},
		{name: "finish passkey registration missing credential", handler: AuthHandler.FinishPasskeyRegistration, body: `{"name":"Laptop key"}`, wantMessage: "credential is required", wantFields: validation.FieldErrors{"credential": map[string]any{"required": true}}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testCase.body))

			testCase.handler(AuthHandler{}, recorder, request)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}

			var response envelope
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if response.Error == nil {
				t.Fatal("response.Error = nil, want error payload")
			}
			if response.Error.Code != "validation_failed" || response.Error.Message != testCase.wantMessage {
				t.Fatalf("response.Error = %+v, want code=%q message=%q", response.Error, "validation_failed", testCase.wantMessage)
			}
			if !reflect.DeepEqual(response.Error.Fields, testCase.wantFields) {
				t.Fatalf("response.Error.Fields = %+v, want %+v", response.Error.Fields, testCase.wantFields)
			}
		})
	}
}

func TestRequireJSONValueAcceptsStructuredJSON(t *testing.T) {
	credential := json.RawMessage(fmt.Appendf(nil, `{%q:%q}`, "id", "cred"))

	if err := (passkeyRegistrationRequest{Credential: credential}).validate(); err != nil {
		t.Fatalf("passkeyRegistrationRequest.validate() error = %v, want nil", err)
	}
}
