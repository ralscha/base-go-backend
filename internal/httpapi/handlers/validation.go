package handlers

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
)

type validationFieldErrors map[string]map[string]any

type validationErrors struct {
	fields validationFieldErrors
}

func newValidationErrors() *validationErrors {
	return &validationErrors{fields: make(validationFieldErrors)}
}

func (e *validationErrors) Error() string {
	if len(e.fields) != 1 {
		return "request validation failed"
	}
	for field, fieldErrors := range e.fields {
		if len(fieldErrors) != 1 {
			break
		}
		for code, value := range fieldErrors {
			return validationMessage(field, code, value)
		}
	}
	return "request validation failed"
}

func (e *validationErrors) add(field, code string, args ...any) {
	fieldErrors, ok := e.fields[field]
	if !ok {
		fieldErrors = make(map[string]any)
		e.fields[field] = fieldErrors
	}
	if _, exists := fieldErrors[code]; exists {
		return
	}
	fieldErrors[code] = validationValue(code, args...)
}

func (e *validationErrors) has(field, code string) bool {
	fieldErrors, ok := e.fields[field]
	if !ok {
		return false
	}
	_, exists := fieldErrors[code]
	return exists
}

func (e *validationErrors) errOrNil() error {
	if len(e.fields) == 0 {
		return nil
	}
	return e
}

func (e *validationErrors) fieldMap() validationFieldErrors {
	if len(e.fields) == 0 {
		return nil
	}
	fields := make(validationFieldErrors, len(e.fields))
	for field, fieldErrors := range e.fields {
		copied := make(map[string]any, len(fieldErrors))
		for code, value := range fieldErrors {
			copied[code] = cloneValidationValue(value)
		}
		fields[field] = copied
	}
	return fields
}

func validationValue(code string, args ...any) any {
	switch code {
	case "required", "email":
		return true
	case "minlength", "maxlength":
		payload := map[string]any{}
		if len(args) > 0 {
			payload["requiredLength"] = args[0]
		}
		if len(args) > 1 {
			payload["actualLength"] = args[1]
		}
		return payload
	case "pattern":
		payload := map[string]any{}
		if len(args) > 0 {
			payload["requiredPattern"] = args[0]
		}
		return payload
	case "exclusive":
		payload := map[string]any{}
		if len(args) > 0 {
			payload["other"] = args[0]
		}
		return payload
	default:
		if len(args) == 0 {
			return true
		}
		if len(args) == 1 {
			return args[0]
		}
		return args
	}
}

func cloneValidationValue(value any) any {
	payload, ok := value.(map[string]any)
	if !ok {
		return value
	}
	cloned := make(map[string]any, len(payload))
	maps.Copy(cloned, payload)
	return cloned
}

func validationMessage(field, code string, value any) string {
	switch code {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "email":
		return fmt.Sprintf("%s must be a valid email address", field)
	case "minlength":
		if payload, ok := value.(map[string]any); ok {
			return fmt.Sprintf("%s must be at least %v characters", field, payload["requiredLength"])
		}
	case "maxlength":
		if payload, ok := value.(map[string]any); ok {
			return fmt.Sprintf("%s must be %v characters or fewer", field, payload["requiredLength"])
		}
	case "pattern":
		if field == "email" {
			return "email must be a valid email address"
		}
		return fmt.Sprintf("%s format is invalid", field)
	case "exclusive":
		if payload, ok := value.(map[string]any); ok {
			return fmt.Sprintf("provide either %s or %v, not both", field, payload["other"])
		}
	}
	return "request validation failed"
}

func writeValidationError(w http.ResponseWriter, err error) {
	var validationErr *validationErrors
	if errors.As(err, &validationErr) {
		writeErrorWithFields(w, http.StatusBadRequest, "validation_failed", validationErr.Error(), validationErr.fieldMap())
		return
	}
	writeError(w, http.StatusBadRequest, "validation_failed", err.Error())
}
