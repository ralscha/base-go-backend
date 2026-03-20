package jsonio

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"base/internal/validation"
)

func TestDecodeJSON(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"Example"}`))

		var payload struct {
			Name string `json:"name"`
		}
		if err := DecodeJSON(recorder, request, &payload); err != nil {
			t.Fatalf("DecodeJSON() error = %v", err)
		}
		if payload.Name != "Example" {
			t.Fatalf("payload.Name = %q, want Example", payload.Name)
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
		}
	})

	t.Run("rejects malformed JSON", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":`))

		var payload struct {
			Name string `json:"name"`
		}
		err := DecodeJSON(recorder, request, &payload)
		if err == nil {
			t.Fatal("DecodeJSON() error = nil, want non-nil")
		}

		response := decodeEnvelope(t, recorder)
		assertAPIError(t, recorder, response, http.StatusBadRequest, "invalid_json", "invalid JSON body", nil)
	})

	t.Run("rejects unknown fields", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"Example","unexpected":true}`))

		var payload struct {
			Name string `json:"name"`
		}
		err := DecodeJSON(recorder, request, &payload)
		if err == nil {
			t.Fatal("DecodeJSON() error = nil, want non-nil")
		}

		response := decodeEnvelope(t, recorder)
		assertAPIError(t, recorder, response, http.StatusBadRequest, "invalid_json", "invalid JSON body", nil)
	})
}

func TestDecodeAndValidate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":" Example ","code":" 123456 "}`))

		payload := &decodeAndValidatePayload{}
		if err := DecodeAndValidate(recorder, request, payload); err != nil {
			t.Fatalf("DecodeAndValidate() error = %v", err)
		}
		if payload.Name != "example" {
			t.Fatalf("payload.Name = %q, want example", payload.Name)
		}
		if payload.Code != "123456" {
			t.Fatalf("payload.Code = %q, want 123456", payload.Code)
		}
		if !payload.normalized {
			t.Fatal("Normalize() was not called")
		}
		if !payload.validated {
			t.Fatal("Validate() was not called")
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
		}
	})

	t.Run("writes validation error", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":" ","code":"abc"}`))

		payload := &decodeAndValidatePayload{}
		err := DecodeAndValidate(recorder, request, payload)
		if err == nil {
			t.Fatal("DecodeAndValidate() error = nil, want non-nil")
		}
		if !payload.normalized {
			t.Fatal("Normalize() was not called")
		}
		if !payload.validated {
			t.Fatal("Validate() was not called")
		}

		response := decodeEnvelope(t, recorder)
		wantFields := validation.FieldErrors{
			"code": map[string]any{"pattern": map[string]any{"requiredPattern": `^[0-9]{6}$`}},
			"name": map[string]any{"required": true},
		}
		assertAPIError(t, recorder, response, http.StatusBadRequest, "validation_failed", "request validation failed", wantFields)
	})
}

type decodeAndValidatePayload struct {
	Name       string `json:"name"`
	Code       string `json:"code"`
	normalized bool
	validated  bool
}

func (p *decodeAndValidatePayload) Normalize() {
	p.normalized = true
	p.Name = strings.TrimSpace(strings.ToLower(p.Name))
	p.Code = strings.TrimSpace(p.Code)
}

func (p *decodeAndValidatePayload) Validate() error {
	p.validated = true
	err := validation.New()
	err.NotBlank("name", p.Name)
	if strings.TrimSpace(p.Code) == "" || !digitsOnly(p.Code) || len(p.Code) != 6 {
		err.Add("code", "pattern", `^[0-9]{6}$`)
	}
	return err.ErrOrNil()
}

func digitsOnly(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
