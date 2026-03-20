package handlers

import (
	"encoding/json"
	"net/http"

	"base/internal/validation"
)

type envelope struct {
	Data  any       `json:"data,omitempty"`
	Error *apiError `json:"error,omitempty"`
}

type apiError struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Fields  validation.FieldErrors `json:"fields,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{Data: data})
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeErrorWithFields(w, status, code, message, nil)
}

func writeErrorWithFields(w http.ResponseWriter, status int, code, message string, fields validation.FieldErrors) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{Error: &apiError{Code: code, Message: message, Fields: fields}})
}
