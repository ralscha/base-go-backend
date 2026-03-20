package handlers

import (
	"bytes"
	"encoding/json"
	"net/mail"
	"strings"
	"unicode"
)

const (
	minUsernameLength    = 3
	maxUsernameLength    = 32
	minPasswordLength    = 12
	maxPasskeyNameLength = 64
	totpCodeLength       = 6
)

type registerRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (r *registerRequest) normalize() {
	r.Username = strings.TrimSpace(r.Username)
	r.Email = strings.TrimSpace(r.Email)
}

func (r registerRequest) validate() error {
	err := newValidationErrors()
	validateUsername(err, r.Username)
	validateEmail(err, r.Email)
	validatePassword(err, r.Password)
	return err.errOrNil()
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

func (r *loginRequest) normalize() {
	r.Email = strings.TrimSpace(r.Email)
	r.TOTPCode = strings.TrimSpace(r.TOTPCode)
}

func (r loginRequest) validate() error {
	err := newValidationErrors()
	validateEmail(err, r.Email)
	validateRequiredPassword(err, r.Password)
	validateSecondFactor(err, r.TOTPCode)
	return err.errOrNil()
}

type passkeyRegistrationRequest struct {
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"`
}

func (r *passkeyRegistrationRequest) normalize() {
	r.Name = strings.TrimSpace(r.Name)
}

func (r passkeyRegistrationRequest) validate() error {
	err := newValidationErrors()
	validateCredential(err, r.Credential)
	if len(r.Name) > maxPasskeyNameLength {
		err.add("name", "maxlength", maxPasskeyNameLength, len(r.Name))
	}
	return err.errOrNil()
}

type passkeyLoginRequest struct {
	Credential json.RawMessage `json:"credential"`
	TOTPCode   string          `json:"totp_code"`
}

func (r *passkeyLoginRequest) normalize() {
	r.TOTPCode = strings.TrimSpace(r.TOTPCode)
}

func (r passkeyLoginRequest) validate() error {
	err := newValidationErrors()
	validateCredential(err, r.Credential)
	validateSecondFactor(err, r.TOTPCode)
	return err.errOrNil()
}

type emailRequest struct {
	Email string `json:"email"`
}

func (r *emailRequest) normalize() {
	r.Email = strings.TrimSpace(r.Email)
}

func (r emailRequest) validate() error {
	err := newValidationErrors()
	validateEmail(err, r.Email)
	return err.errOrNil()
}

type tokenPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (r *tokenPasswordRequest) normalize() {
	r.Token = strings.TrimSpace(r.Token)
}

func (r tokenPasswordRequest) validate() error {
	err := newValidationErrors()
	validateRequired(err, "token", r.Token)
	validatePassword(err, r.Password)
	return err.errOrNil()
}

type enableTOTPRequest struct {
	Code string `json:"code"`
}

func (r *enableTOTPRequest) normalize() {
	r.Code = strings.TrimSpace(r.Code)
}

func (r enableTOTPRequest) validate() error {
	err := newValidationErrors()
	validateTOTPCode(err, "code", r.Code)
	return err.errOrNil()
}

func validateRequired(err *validationErrors, field, value string) {
	if strings.TrimSpace(value) == "" {
		err.add(field, "required")
	}
}

func validateUsername(err *validationErrors, value string) {
	validateRequired(err, "username", value)
	if err.has("username", "required") {
		return
	}
	if len(value) < minUsernameLength {
		err.add("username", "minlength", minUsernameLength, len(value))
	}
	if len(value) > maxUsernameLength {
		err.add("username", "maxlength", maxUsernameLength, len(value))
	}
	if strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		err.add("username", "pattern", `^\S+$`)
	}
}

func validateEmail(err *validationErrors, value string) {
	validateRequired(err, "email", value)
	if err.has("email", "required") {
		return
	}
	parsed, parseErr := mail.ParseAddress(value)
	if parseErr != nil || parsed.Address != value {
		err.add("email", "email")
	}
}

func validateRequiredPassword(err *validationErrors, value string) {
	validateRequired(err, "password", value)
}

func validatePassword(err *validationErrors, value string) {
	validateRequired(err, "password", value)
	if err.has("password", "required") {
		return
	}
	actualLength := len(strings.TrimSpace(value))
	if actualLength < minPasswordLength {
		err.add("password", "minlength", minPasswordLength, actualLength)
	}
}

func validateCredential(err *validationErrors, value json.RawMessage) {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		err.add("credential", "required")
	}
}

func validateSecondFactor(err *validationErrors, totpCode string) {
	if totpCode != "" {
		validateTOTPCode(err, "totp_code", totpCode)
	}
}

func validateTOTPCode(err *validationErrors, field, value string) {
	validateRequired(err, field, value)
	if err.has(field, "required") {
		return
	}
	if len(value) != totpCodeLength {
		err.add(field, "pattern", `^[0-9]{6}$`)
		return
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			err.add(field, "pattern", `^[0-9]{6}$`)
			return
		}
	}
}
