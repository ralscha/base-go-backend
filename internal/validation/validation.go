package validation

import (
	"cmp"
	"fmt"
	"maps"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	requestValidationFailedMessage = "request validation failed"
	codeRequired                   = "required"
	codeEmail                      = "email"
	fieldEmail                     = "email"
)

type FieldErrors map[string]map[string]any

type Errors struct {
	fields FieldErrors
}

func (e *Errors) NotBlank(field, value string) bool {
	if strings.TrimSpace(value) == "" {
		e.Add(field, codeRequired)
		return true
	}
	return false
}

func (e *Errors) MinRunes(field, value string, min int) {
	if utf8.RuneCountInString(value) < min {
		e.Add(field, "minlength", min, utf8.RuneCountInString(value))
	}
}

func (e *Errors) MaxRunes(field, value string, max int) {
	if utf8.RuneCountInString(value) > max {
		e.Add(field, "maxlength", max, utf8.RuneCountInString(value))
	}
}

func (e *Errors) IsEmail(field, value string) {
	parsed, parseErr := mail.ParseAddress(value)
	if parseErr != nil || parsed.Address != value {
		e.Add(field, codeEmail)
	}
}

func Between[T cmp.Ordered](e *Errors, field string, value, min, max T) {
	if value < min || value > max {
		e.Add(field, "between", min, max)
	}
}

func (e *Errors) Matches(field, value string, pattern *regexp.Regexp) {
	if !pattern.MatchString(value) {
		e.Add(field, "pattern", pattern.String())
	}
}

func (e *Errors) In(field, value string, options ...string) {
	if slices.Contains(options, value) {
		return
	}
	e.Add(field, "in", options)
}

func Exclusive(e *Errors, field1, value1, field2, value2 string) {
	if (value1 != "" && value2 != "") || (value1 == "" && value2 == "") {
		e.Add(field1, "exclusive", field2)
		e.Add(field2, "exclusive", field1)
	}
}

func New() *Errors {
	return &Errors{fields: make(FieldErrors)}
}

func (e *Errors) Error() string {
	if len(e.fields) != 1 {
		return requestValidationFailedMessage
	}
	for field, fieldErrors := range e.fields {
		if len(fieldErrors) != 1 {
			break
		}
		for code, value := range fieldErrors {
			return message(field, code, value)
		}
	}
	return requestValidationFailedMessage
}

func (e *Errors) Add(field, code string, args ...any) {
	fieldErrors, ok := e.fields[field]
	if !ok {
		fieldErrors = make(map[string]any)
		e.fields[field] = fieldErrors
	}
	if _, exists := fieldErrors[code]; exists {
		return
	}
	fieldErrors[code] = value(code, args...)
}

func (e *Errors) ErrOrNil() error {
	if len(e.fields) == 0 {
		return nil
	}
	return e
}

func (e *Errors) FieldMap() FieldErrors {
	if len(e.fields) == 0 {
		return nil
	}
	fields := make(FieldErrors, len(e.fields))
	for field, fieldErrors := range e.fields {
		copied := make(map[string]any, len(fieldErrors))
		for code, fieldValue := range fieldErrors {
			copied[code] = cloneValue(fieldValue)
		}
		fields[field] = copied
	}
	return fields
}

func value(code string, args ...any) any {
	switch code {
	case codeRequired, codeEmail:
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
	case "between":
		payload := map[string]any{}
		if len(args) > 0 {
			payload["min"] = args[0]
		}
		if len(args) > 1 {
			payload["max"] = args[1]
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

func cloneValue(fieldValue any) any {
	payload, ok := fieldValue.(map[string]any)
	if !ok {
		return fieldValue
	}
	cloned := make(map[string]any, len(payload))
	maps.Copy(cloned, payload)
	return cloned
}

func message(field, code string, fieldValue any) string {
	switch code {
	case codeRequired:
		return fmt.Sprintf("%s is required", field)
	case codeEmail:
		return fmt.Sprintf("%s must be a valid email address", field)
	case "minlength":
		if payload, ok := fieldValue.(map[string]any); ok {
			return fmt.Sprintf("%s must be at least %v characters", field, payload["requiredLength"])
		}
	case "maxlength":
		if payload, ok := fieldValue.(map[string]any); ok {
			return fmt.Sprintf("%s must be %v characters or fewer", field, payload["requiredLength"])
		}
	case "pattern":
		if field == fieldEmail {
			return "email must be a valid email address"
		}
		return fmt.Sprintf("%s format is invalid", field)
	case "between":
		if payload, ok := fieldValue.(map[string]any); ok {
			return fmt.Sprintf("%s must be between %v and %v", field, payload["min"], payload["max"])
		}
	case "exclusive":
		if payload, ok := fieldValue.(map[string]any); ok {
			return fmt.Sprintf("provide either %s or %v, not both", field, payload["other"])
		}
	}
	return requestValidationFailedMessage
}
