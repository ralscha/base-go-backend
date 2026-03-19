package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestEncryptDecryptSecretRoundTrip(t *testing.T) {
	key := strings.Repeat("k", 32)

	ciphertext, nonce, err := encryptSecret("top-secret", key)
	if err != nil {
		t.Fatalf("encryptSecret() error = %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("encryptSecret() returned empty ciphertext")
	}
	if len(nonce) == 0 {
		t.Fatal("encryptSecret() returned empty nonce")
	}

	plaintext, err := decryptSecret(ciphertext, nonce, key)
	if err != nil {
		t.Fatalf("decryptSecret() error = %v", err)
	}
	if plaintext != "top-secret" {
		t.Fatalf("decryptSecret() = %q, want %q", plaintext, "top-secret")
	}
}

func TestEncryptSecretRejectsShortKey(t *testing.T) {
	if _, _, err := encryptSecret("secret", "short-key"); !errors.Is(err, ErrInvalidEncryptionKey) {
		t.Fatalf("encryptSecret() error = %v, want %v", err, ErrInvalidEncryptionKey)
	}
}

func TestDecryptSecretRejectsTamperedCiphertext(t *testing.T) {
	key := strings.Repeat("z", 32)
	ciphertext, nonce, err := encryptSecret("top-secret", key)
	if err != nil {
		t.Fatalf("encryptSecret() error = %v", err)
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0xff

	if _, err := decryptSecret(tampered, nonce, key); err == nil {
		t.Fatal("decryptSecret() error = nil, want authentication failure")
	}
}
