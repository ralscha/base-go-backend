package auth

import (
	"database/sql"
	"encoding/binary"
	"testing"

	"base/internal/store/sqlc"

	wa "github.com/go-webauthn/webauthn/webauthn"
)

func TestPasskeyUserWebAuthnMethods(t *testing.T) {
	credential := wa.Credential{ID: []byte("cred-1")}
	user := &passkeyUser{
		user:        sqlc.User{ID: 42, Username: "alice", Email: "alice@example.com"},
		credentials: []wa.Credential{credential},
	}

	if got := user.WebAuthnName(); got != "alice" {
		t.Fatalf("WebAuthnName() = %q, want alice", got)
	}
	if got := user.WebAuthnDisplayName(); got != "alice@example.com" {
		t.Fatalf("WebAuthnDisplayName() = %q, want alice@example.com", got)
	}
	if got := user.WebAuthnCredentials(); len(got) != 1 || string(got[0].ID) != "cred-1" {
		t.Fatalf("WebAuthnCredentials() = %v, want credential list", got)
	}

	encodedID := user.WebAuthnID()
	if len(encodedID) != 8 {
		t.Fatalf("len(WebAuthnID()) = %d, want 8", len(encodedID))
	}
	if got := binary.BigEndian.Uint64(encodedID); got != uint64(42) {
		t.Fatalf("WebAuthnID() decodes to %d, want 42", got)
	}
}

func TestErrorsIsNoRowsExactMatch(t *testing.T) {
	if !errorsIsNoRows(sql.ErrNoRows) {
		t.Fatal("errorsIsNoRows(sql.ErrNoRows) = false, want true")
	}
	if errorsIsNoRows(sql.ErrConnDone) {
		t.Fatal("errorsIsNoRows(sql.ErrConnDone) = true, want false")
	}
}
