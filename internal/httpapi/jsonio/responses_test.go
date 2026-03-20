package jsonio

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"base/internal/validation"
)

func TestWriteJSON(t *testing.T) {
	recorder := httptest.NewRecorder()

	WriteJSON(recorder, http.StatusCreated, map[string]any{"status": "created"})

	response := decodeEnvelope(t, recorder)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusCreated)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}
	data, ok := response.Data.(map[string]any)
	if !ok {
		t.Fatalf("response.Data type = %T, want object", response.Data)
	}
	if data["status"] != "created" {
		t.Fatalf("response.Data = %+v, want status=created", data)
	}
}

func TestWriteErrorWithFields(t *testing.T) {
	recorder := httptest.NewRecorder()
	fields := validation.FieldErrors{"email": map[string]any{"required": true}}

	WriteErrorWithFields(recorder, http.StatusConflict, "conflict", "request conflict", fields)

	response := decodeEnvelope(t, recorder)
	assertAPIError(t, recorder, response, http.StatusConflict, "conflict", "request conflict", fields)
}

func TestWriteValidationError(t *testing.T) {
	t.Run("validation errors", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		validationErr := validation.New()
		validationErr.Add("email", "required")

		WriteValidationError(recorder, validationErr)

		response := decodeEnvelope(t, recorder)
		wantFields := validation.FieldErrors{"email": map[string]any{"required": true}}
		assertAPIError(t, recorder, response, http.StatusBadRequest, "validation_failed", "email is required", wantFields)
	})

	t.Run("generic error", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		WriteValidationError(recorder, errors.New("boom"))

		response := decodeEnvelope(t, recorder)
		assertAPIError(t, recorder, response, http.StatusBadRequest, "validation_failed", "boom", nil)
	})
}

func decodeEnvelope(t *testing.T, recorder *httptest.ResponseRecorder) envelope {
	t.Helper()

	var response envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	return response
}

func assertAPIError(t *testing.T, recorder *httptest.ResponseRecorder, response envelope, wantStatus int, wantCode, wantMessage string, wantFields validation.FieldErrors) {
	t.Helper()

	if recorder.Code != wantStatus {
		t.Fatalf("status = %d, want %d", recorder.Code, wantStatus)
	}
	if response.Error == nil {
		t.Fatal("response.Error = nil, want error payload")
	}
	if response.Error.Code != wantCode {
		t.Fatalf("response.Error.Code = %q, want %q", response.Error.Code, wantCode)
	}
	if response.Error.Message != wantMessage {
		t.Fatalf("response.Error.Message = %q, want %q", response.Error.Message, wantMessage)
	}
	if !reflect.DeepEqual(response.Error.Fields, wantFields) {
		t.Fatalf("response.Error.Fields = %+v, want %+v", response.Error.Fields, wantFields)
	}
}
