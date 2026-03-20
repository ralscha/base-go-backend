package validation

import (
	"reflect"
	"regexp"
	"testing"
)

func TestErrorsNotBlank(t *testing.T) {
	t.Run("blank adds required error", func(t *testing.T) {
		errors := New()

		blank := errors.NotBlank("name", " \t\n")

		if !blank {
			t.Fatal("NotBlank() = false, want true for blank value")
		}
		want := FieldErrors{"name": map[string]any{"required": true}}
		if !reflect.DeepEqual(errors.FieldMap(), want) {
			t.Fatalf("FieldMap() = %#v, want %#v", errors.FieldMap(), want)
		}
	})

	t.Run("non blank leaves errors unchanged", func(t *testing.T) {
		errors := New()

		blank := errors.NotBlank("name", "Alice")

		if blank {
			t.Fatal("NotBlank() = true, want false for non-blank value")
		}
		if got := errors.FieldMap(); got != nil {
			t.Fatalf("FieldMap() = %#v, want nil", got)
		}
	})
}

func TestErrorsRuneLengthValidators(t *testing.T) {
	errors := New()
	errors.MinRunes("nickname", "go", 3)
	errors.MaxRunes("nickname", "你好啊", 2)

	got := errors.FieldMap()
	want := FieldErrors{
		"nickname": map[string]any{
			"minlength": map[string]any{"requiredLength": 3, "actualLength": 2},
			"maxlength": map[string]any{"requiredLength": 2, "actualLength": 3},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FieldMap() = %#v, want %#v", got, want)
	}
}

func TestErrorsIsEmail(t *testing.T) {
	t.Run("accepts plain address", func(t *testing.T) {
		errors := New()

		errors.IsEmail("email", "alice@example.com")

		if got := errors.FieldMap(); got != nil {
			t.Fatalf("FieldMap() = %#v, want nil", got)
		}
	})

	t.Run("rejects named address form", func(t *testing.T) {
		errors := New()

		errors.IsEmail("email", "Alice <alice@example.com>")

		want := FieldErrors{"email": map[string]any{"email": true}}
		if !reflect.DeepEqual(errors.FieldMap(), want) {
			t.Fatalf("FieldMap() = %#v, want %#v", errors.FieldMap(), want)
		}
	})
}

func TestBetween(t *testing.T) {
	errors := New()

	Between(errors, "age", 17, 18, 65)
	Between(errors, "score", 100, 0, 100)

	want := FieldErrors{"age": map[string]any{"between": map[string]any{"min": 18, "max": 65}}}
	if !reflect.DeepEqual(errors.FieldMap(), want) {
		t.Fatalf("FieldMap() = %#v, want %#v", errors.FieldMap(), want)
	}
}

func TestErrorsMatches(t *testing.T) {
	errors := New()
	pattern := regexp.MustCompile(`^[a-z]+$`)

	errors.Matches("username", "alice-1", pattern)

	want := FieldErrors{"username": map[string]any{"pattern": map[string]any{"requiredPattern": pattern.String()}}}
	if !reflect.DeepEqual(errors.FieldMap(), want) {
		t.Fatalf("FieldMap() = %#v, want %#v", errors.FieldMap(), want)
	}
}

func TestErrorsIn(t *testing.T) {
	errors := New()
	errors.In("role", "guest", "admin", "member")
	errors.In("status", "active", "active", "disabled")

	want := FieldErrors{"role": map[string]any{"in": []string{"admin", "member"}}}
	if !reflect.DeepEqual(errors.FieldMap(), want) {
		t.Fatalf("FieldMap() = %#v, want %#v", errors.FieldMap(), want)
	}
}

func TestExclusive(t *testing.T) {
	t.Run("adds errors when both missing", func(t *testing.T) {
		errors := New()

		Exclusive(errors, "email", "", "phone", "")

		want := FieldErrors{
			"email": map[string]any{"exclusive": map[string]any{"other": "phone"}},
			"phone": map[string]any{"exclusive": map[string]any{"other": "email"}},
		}
		if !reflect.DeepEqual(errors.FieldMap(), want) {
			t.Fatalf("FieldMap() = %#v, want %#v", errors.FieldMap(), want)
		}
	})

	t.Run("does nothing when exactly one value set", func(t *testing.T) {
		errors := New()

		Exclusive(errors, "email", "alice@example.com", "phone", "")

		if got := errors.FieldMap(); got != nil {
			t.Fatalf("FieldMap() = %#v, want nil", got)
		}
	})
}

func TestErrorsAddErrOrNilAndFieldMap(t *testing.T) {
	errors := New()

	if err := errors.ErrOrNil(); err != nil {
		t.Fatalf("ErrOrNil() = %v, want nil", err)
	}

	errors.Add("password", "minlength", 12, 8)
	errors.Add("password", "minlength", 20, 1)

	err := errors.ErrOrNil()
	if err == nil {
		t.Fatal("ErrOrNil() = nil, want validation error")
	}

	fields := errors.FieldMap()
	payload, ok := fields["password"]["minlength"].(map[string]any)
	if !ok {
		t.Fatalf("minlength payload type = %T, want map[string]any", fields["password"]["minlength"])
	}
	payload["requiredLength"] = 99

	freshFields := errors.FieldMap()
	freshPayload := freshFields["password"]["minlength"].(map[string]any)
	if freshPayload["requiredLength"] != 12 {
		t.Fatalf("FieldMap() returned aliased payload, got requiredLength=%v", freshPayload["requiredLength"])
	}
}

func TestErrorsError(t *testing.T) {
	t.Run("single field single error returns specific message", func(t *testing.T) {
		errors := New()
		errors.Add("email", "required")

		if got := errors.Error(); got != "email is required" {
			t.Fatalf("Error() = %q, want %q", got, "email is required")
		}
	})

	t.Run("multiple errors return generic message", func(t *testing.T) {
		errors := New()
		errors.Add("email", "required")
		errors.Add("email", "email")

		if got := errors.Error(); got != requestValidationFailedMessage {
			t.Fatalf("Error() = %q, want %q", got, requestValidationFailedMessage)
		}
	})
}

func TestMessage(t *testing.T) {
	tests := []struct {
		name       string
		field      string
		code       string
		fieldValue any
		want       string
	}{
		{
			name:       "required",
			field:      "email",
			code:       codeRequired,
			fieldValue: true,
			want:       "email is required",
		},
		{
			name:       "email",
			field:      "email",
			code:       codeEmail,
			fieldValue: true,
			want:       "email must be a valid email address",
		},
		{
			name:       "email pattern",
			field:      fieldEmail,
			code:       "pattern",
			fieldValue: map[string]any{"requiredPattern": ".+"},
			want:       "email must be a valid email address",
		},
		{
			name:       "exclusive",
			field:      "email",
			code:       "exclusive",
			fieldValue: map[string]any{"other": "phone"},
			want:       "provide either email or phone, not both",
		},
		{
			name:       "unknown",
			field:      "email",
			code:       "unknown",
			fieldValue: true,
			want:       requestValidationFailedMessage,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := message(tc.field, tc.code, tc.fieldValue); got != tc.want {
				t.Fatalf("message() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValueAndCloneValue(t *testing.T) {
	if got := value("custom"); got != true {
		t.Fatalf("value(custom) = %#v, want true", got)
	}

	if got := value("custom", "one"); got != "one" {
		t.Fatalf("value(custom, one) = %#v, want %#v", got, "one")
	}

	multiple := value("custom", "one", 2)
	if !reflect.DeepEqual(multiple, []any{"one", 2}) {
		t.Fatalf("value(custom, one, 2) = %#v, want %#v", multiple, []any{"one", 2})
	}

	payload := map[string]any{"requiredLength": 10}
	cloned, ok := cloneValue(payload).(map[string]any)
	if !ok {
		t.Fatalf("cloneValue(map) type = %T, want map[string]any", cloneValue(payload))
	}
	cloned["requiredLength"] = 1
	if payload["requiredLength"] != 10 {
		t.Fatalf("cloneValue() mutated original map, got %v", payload["requiredLength"])
	}

	if got := cloneValue("plain"); got != "plain" {
		t.Fatalf("cloneValue(string) = %#v, want %#v", got, "plain")
	}
}
