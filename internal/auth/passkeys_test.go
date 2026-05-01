package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"base/internal/store/dbtype"
	"base/internal/store/sqlc"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

func TestDecodePasskeySession(t *testing.T) {
	if _, err := decodePasskeySession(nil); !errors.Is(err, ErrPasskeyCeremony) {
		t.Fatalf("decodePasskeySession(nil) error = %v, want %v", err, ErrPasskeyCeremony)
	}

	want := wa.SessionData{
		Challenge:            "challenge-token",
		UserID:               []byte("user-id"),
		UserVerification:     "preferred",
		AllowedCredentialIDs: [][]byte{[]byte("cred-1")},
	}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal(SessionData) error = %v", err)
	}

	got, err := decodePasskeySession(encoded)
	if err != nil {
		t.Fatalf("decodePasskeySession() error = %v", err)
	}
	if got.Challenge != want.Challenge {
		t.Fatalf("Challenge = %q, want %q", got.Challenge, want.Challenge)
	}
	if string(got.UserID) != string(want.UserID) {
		t.Fatalf("UserID = %q, want %q", string(got.UserID), string(want.UserID))
	}
	if got.UserVerification != want.UserVerification {
		t.Fatalf("UserVerification = %q, want %q", got.UserVerification, want.UserVerification)
	}
	if len(got.AllowedCredentialIDs) != 1 || string(got.AllowedCredentialIDs[0]) != "cred-1" {
		t.Fatalf("AllowedCredentialIDs = %v, want credential list", got.AllowedCredentialIDs)
	}

	if _, err := decodePasskeySession([]byte(`{"challenge":`)); err == nil {
		t.Fatal("decodePasskeySession(invalid JSON) error = nil, want decode error")
	}
}

func TestJSONRequest(t *testing.T) {
	req := jsonRequest([]byte(`{"hello":"world"}`))
	if req.Method != "POST" {
		t.Fatalf("Method = %q, want POST", req.Method)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll(req.Body) error = %v", err)
	}
	if string(body) != `{"hello":"world"}` {
		t.Fatalf("Body = %q, want JSON payload", string(body))
	}
}

func TestCredentialFromRowUsesStoredCredentialDataWhenValid(t *testing.T) {
	want := wa.Credential{
		ID:              []byte("credential-id"),
		PublicKey:       []byte("public-key"),
		AttestationType: "none",
		Transport:       []protocol.AuthenticatorTransport{protocol.USB},
		Authenticator: wa.Authenticator{
			SignCount:    7,
			CloneWarning: true,
		},
	}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	got := credentialFromRow(sqlc.PasskeyCredential{
		CredentialData:      encoded,
		AttestationType:     want.AttestationType,
		CredentialID:        want.ID,
		CredentialPublicKey: want.PublicKey,
		SignCount:           int64(want.Authenticator.SignCount),
		CloneWarning:        want.Authenticator.CloneWarning,
		Transports:          []string{"usb"},
	})
	if !bytes.Equal(got.ID, want.ID) {
		t.Fatalf("ID = %q, want %q", got.ID, want.ID)
	}
	if !bytes.Equal(got.PublicKey, want.PublicKey) {
		t.Fatalf("PublicKey = %q, want %q", got.PublicKey, want.PublicKey)
	}
	if got.AttestationType != want.AttestationType {
		t.Fatalf("AttestationType = %q, want %q", got.AttestationType, want.AttestationType)
	}
	if len(got.Transport) != 1 || got.Transport[0] != protocol.USB {
		t.Fatalf("Transport = %v, want [%v]", got.Transport, protocol.USB)
	}
	if got.Authenticator.SignCount != want.Authenticator.SignCount || got.Authenticator.CloneWarning != want.Authenticator.CloneWarning {
		t.Fatalf("Authenticator = %+v, want %+v", got.Authenticator, want.Authenticator)
	}
}

func TestCredentialFromRowFallsBackToColumns(t *testing.T) {
	aaguid := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	got := credentialFromRow(sqlc.PasskeyCredential{
		CredentialID:        []byte("credential-id"),
		CredentialPublicKey: []byte("public-key"),
		AttestationType:     "basic",
		Aaguid:              uuid.NullUUID{UUID: aaguid, Valid: true},
		SignCount:           9,
		CloneWarning:        true,
		Transports:          []string{"usb", "nfc"},
		CredentialData:      dbtype.RawMessage(`{"broken":`),
	})

	if !bytes.Equal(got.ID, []byte("credential-id")) {
		t.Fatalf("ID = %q, want credential-id", got.ID)
	}
	if !bytes.Equal(got.PublicKey, []byte("public-key")) {
		t.Fatalf("PublicKey = %q, want public-key", got.PublicKey)
	}
	if got.AttestationType != "basic" {
		t.Fatalf("AttestationType = %q, want basic", got.AttestationType)
	}
	if got.Authenticator.SignCount != 9 || !got.Authenticator.CloneWarning {
		t.Fatalf("Authenticator = %+v, want sign count 9 and clone warning true", got.Authenticator)
	}
	if !bytes.Equal(got.Authenticator.AAGUID, aaguid[:]) {
		t.Fatalf("AAGUID = %v, want %v", got.Authenticator.AAGUID, aaguid[:])
	}
	if len(got.Transport) != 2 || got.Transport[0] != protocol.USB || got.Transport[1] != protocol.NFC {
		t.Fatalf("Transport = %v, want [usb nfc]", got.Transport)
	}
}
