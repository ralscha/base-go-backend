package jsonio

import (
	"encoding/json"
	"errors"
	"net/http"

	"base/internal/validation"
)

type envelope struct {
	Data  any       `json:"data,omitempty"`
	Error *APIError `json:"error,omitempty"`
}

type APIError struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Fields  validation.FieldErrors `json:"fields,omitempty"`
}

func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{Data: data})
}

func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteErrorWithFields(w, status, code, message, nil)
}

func WriteErrorWithFields(w http.ResponseWriter, status int, code, message string, fields validation.FieldErrors) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{Error: &APIError{Code: code, Message: message, Fields: fields}})
}

func WriteValidationError(w http.ResponseWriter, err error) {
	if validationErr, ok := errors.AsType[*validation.Errors](err); ok {
		WriteErrorWithFields(w, http.StatusBadRequest, "validation_failed", validationErr.Error(), validationErr.FieldMap())
		return
	}
	WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
}
