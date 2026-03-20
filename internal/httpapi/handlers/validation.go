package handlers

import (
	"errors"
	"net/http"

	"base/internal/validation"
)

func writeValidationError(w http.ResponseWriter, err error) {
	var validationErr *validation.Errors
	if errors.As(err, &validationErr) {
		writeErrorWithFields(w, http.StatusBadRequest, "validation_failed", validationErr.Error(), validationErr.FieldMap())
		return
	}
	writeError(w, http.StatusBadRequest, "validation_failed", err.Error())
}
