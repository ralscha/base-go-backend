package handlers

import "base/internal/httpapi/jsonio"

type testEnvelope struct {
	Data  any              `json:"data,omitempty"`
	Error *jsonio.APIError `json:"error,omitempty"`
}
