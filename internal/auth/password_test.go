package auth

import (
	"errors"
	"testing"
)

func TestHashPasswordAndCompare(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	match, err := ComparePassword("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("ComparePassword() error = %v", err)
	}
	if !match {
		t.Fatal("expected password to match generated hash")
	}
}

func TestHashPasswordWeakPassword(t *testing.T) {
	if _, err := HashPassword("short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("HashPassword() error = %v, want %v", err, ErrWeakPassword)
	}
}

func TestCompareWithInvalidCredentialsSentinel(t *testing.T) {
	if err := compareWithInvalidCredentialsSentinel("some password value"); err != nil {
		t.Fatalf("compareWithInvalidCredentialsSentinel() error = %v", err)
	}
}
