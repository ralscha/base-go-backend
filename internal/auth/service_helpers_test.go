package auth

import (
	"database/sql"
	"encoding/binary"
	"net"
	"testing"

	"base/internal/store/sqlc"

	wa "github.com/go-webauthn/webauthn/webauthn"
)

func TestInetValue(t *testing.T) {
	v4 := inetValue(" 192.168.1.10 ")
	if !v4.Valid {
		t.Fatal("inetValue(v4) returned invalid value")
	}
	if got := v4.IPNet.IP.String(); got != "192.168.1.10" {
		t.Fatalf("inetValue(v4) IP = %q, want 192.168.1.10", got)
	}
	ones, bits := v4.IPNet.Mask.Size()
	if ones != 32 || bits != 32 {
		t.Fatalf("inetValue(v4) mask = %d/%d, want 32/32", ones, bits)
	}

	v6 := inetValue("2001:db8::1")
	if !v6.Valid {
		t.Fatal("inetValue(v6) returned invalid value")
	}
	ones, bits = v6.IPNet.Mask.Size()
	if ones != 128 || bits != 128 {
		t.Fatalf("inetValue(v6) mask = %d/%d, want 128/128", ones, bits)
	}

	invalid := inetValue("not-an-ip")
	if invalid.Valid {
		t.Fatal("inetValue(invalid) returned valid value")
	}
	if invalid.IPNet.IP != nil && !invalid.IPNet.IP.Equal(net.IP{}) {
		t.Fatalf("inetValue(invalid) IP = %v, want zero value", invalid.IPNet.IP)
	}
}

func TestNullString(t *testing.T) {
	if got := nullString("  value  "); !got.Valid || got.String != "value" {
		t.Fatalf("nullString(trimmed) = %+v, want valid trimmed string", got)
	}
	if got := nullString("   "); got.Valid {
		t.Fatalf("nullString(blank) = %+v, want invalid", got)
	}
}

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
	if got := int64(binary.BigEndian.Uint64(encodedID)); got != 42 {
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
