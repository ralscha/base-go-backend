package dbtype

import (
	"bytes"
	"testing"
)

func TestRawMessageScanCopiesBytes(t *testing.T) {
	original := []byte(`{"status":"ok"}`)
	var message RawMessage

	if err := message.Scan(original); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	original[2] = 'X'
	if got := string(message); got != `{"status":"ok"}` {
		t.Fatalf("Scan() stored %q, want original contents", got)
	}
}

func TestRawMessageScanHandlesNilAndString(t *testing.T) {
	var message RawMessage
	if err := message.Scan(nil); err != nil {
		t.Fatalf("Scan(nil) error = %v", err)
	}

	if err := message.Scan(`{"hello":"world"}`); err != nil {
		t.Fatalf("Scan(string) error = %v", err)
	}
	if got := string(message); got != `{"hello":"world"}` {
		t.Fatalf("Scan(string) = %q, want valid JSON contents", got)
	}
}

func TestRawMessageScanRejectsUnsupportedType(t *testing.T) {
	var message RawMessage
	if err := message.Scan(123); err == nil {
		t.Fatal("Scan() error = nil, want unsupported type error")
	}
}

func TestRawMessageValueAndMarshalJSON(t *testing.T) {
	var nilMessage RawMessage
	value, err := nilMessage.Value()
	if err != nil {
		t.Fatalf("Value() error = %v", err)
	}
	if value != nil {
		t.Fatalf("Value() = %v, want nil", value)
	}

	marshaledNil, err := nilMessage.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON(nil) error = %v", err)
	}
	if string(marshaledNil) != "null" {
		t.Fatalf("MarshalJSON(nil) = %q, want null", string(marshaledNil))
	}

	message := RawMessage(`{"count":2}`)
	value, err = message.Value()
	if err != nil {
		t.Fatalf("Value() error = %v", err)
	}
	if value != `{"count":2}` {
		t.Fatalf("Value() = %v, want JSON string", value)
	}

	marshaled, err := message.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	if !bytes.Equal(marshaled, message) {
		t.Fatalf("MarshalJSON() = %s, want %s", marshaled, message)
	}
}

func TestRawMessageUnmarshalJSON(t *testing.T) {
	var message RawMessage
	if err := message.UnmarshalJSON([]byte(`{"active":true}`)); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got := string(message); got != `{"active":true}` {
		t.Fatalf("UnmarshalJSON() = %q, want valid JSON contents", got)
	}

	if err := message.UnmarshalJSON([]byte(`{"active":`)); err == nil {
		t.Fatal("UnmarshalJSON() error = nil, want invalid JSON error")
	}
	if got := string(message); got != `{"active":true}` {
		t.Fatalf("UnmarshalJSON() modified message on invalid input, got %q", got)
	}
}
