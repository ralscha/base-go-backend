package handlers

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"base/internal/validation"
)

var (
	reUsernamePattern = regexp.MustCompile(`^\S+$`)
	reTOTPCode        = regexp.MustCompile(`^[0-9]{6}$`)
)

const (
	minUsernameLength    = 3
	maxUsernameLength    = 32
	minPasswordLength    = 12
	maxPasskeyNameLength = 64
)

type registerRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (r *registerRequest) Normalize() {
	r.Username = strings.ToLower(strings.TrimSpace(r.Username))
	r.Email = strings.ToLower(strings.TrimSpace(r.Email))
}

func (r registerRequest) Validate() error {
	err := validation.New()
	validateUsername(err, r.Username)
	validateEmail(err, r.Email)
	validatePassword(err, r.Password)
	return err.ErrOrNil()
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

func (r *loginRequest) Normalize() {
	r.Email = strings.ToLower(strings.TrimSpace(r.Email))
	r.TOTPCode = strings.TrimSpace(r.TOTPCode)
}

func (r loginRequest) Validate() error {
	err := validation.New()
	validateEmail(err, r.Email)
	validateRequiredPassword(err, r.Password)
	validateSecondFactor(err, r.TOTPCode)
	return err.ErrOrNil()
}

type passkeyRegistrationRequest struct {
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"`
}

func (r *passkeyRegistrationRequest) Normalize() {
	r.Name = strings.TrimSpace(r.Name)
}

func (r passkeyRegistrationRequest) Validate() error {
	err := validation.New()
	validateCredential(err, r.Credential)
	if len(r.Name) > maxPasskeyNameLength {
		err.Add("name", "maxlength", maxPasskeyNameLength, len(r.Name))
	}
	return err.ErrOrNil()
}

type passkeyLoginRequest struct {
	Credential json.RawMessage `json:"credential"`
	TOTPCode   string          `json:"totp_code"`
}

func (r *passkeyLoginRequest) Normalize() {
	r.TOTPCode = strings.TrimSpace(r.TOTPCode)
}

func (r passkeyLoginRequest) Validate() error {
	err := validation.New()
	validateCredential(err, r.Credential)
	validateSecondFactor(err, r.TOTPCode)
	return err.ErrOrNil()
}

type emailRequest struct {
	Email string `json:"email"`
}

func (r *emailRequest) Normalize() {
	r.Email = strings.ToLower(strings.TrimSpace(r.Email))
}

func (r emailRequest) Validate() error {
	err := validation.New()
	validateEmail(err, r.Email)
	return err.ErrOrNil()
}

type tokenPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (r *tokenPasswordRequest) Normalize() {
	r.Token = strings.TrimSpace(r.Token)
}

func (r tokenPasswordRequest) Validate() error {
	err := validation.New()
	if hasError := err.NotBlank("token", r.Token); hasError {
		return err.ErrOrNil()
	}
	validatePassword(err, r.Password)
	return err.ErrOrNil()
}

type enableTOTPRequest struct {
	Code string `json:"code"`
}

func (r *enableTOTPRequest) Normalize() {
	r.Code = strings.TrimSpace(r.Code)
}

func (r enableTOTPRequest) Validate() error {
	err := validation.New()
	validateTOTPCode(err, "code", r.Code)
	return err.ErrOrNil()
}

func validateUsername(err *validation.Errors, value string) {
	if hasError := err.NotBlank("username", value); hasError {
		return
	}
	err.MinRunes("username", value, minUsernameLength)
	err.MaxRunes("username", value, maxUsernameLength)
	err.Matches("username", value, reUsernamePattern)
}

func validateEmail(err *validation.Errors, value string) {
	if hasError := err.NotBlank("email", value); hasError {
		return
	}
	err.IsEmail("email", value)
}

func validateRequiredPassword(err *validation.Errors, value string) {
	err.NotBlank("password", value)
}

func validatePassword(err *validation.Errors, value string) {
	if hasError := err.NotBlank("password", value); hasError {
		return
	}
	err.MinRunes("password", strings.TrimSpace(value), minPasswordLength)
}

func validateCredential(err *validation.Errors, value json.RawMessage) {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		err.Add("credential", "required")
	}
}

func validateSecondFactor(err *validation.Errors, totpCode string) {
	if totpCode != "" {
		validateTOTPCode(err, "totp_code", totpCode)
	}
}

func validateTOTPCode(err *validation.Errors, field, value string) {
	if hasError := err.NotBlank(field, value); hasError {
		return
	}
	err.Matches(field, value, reTOTPCode)
}
