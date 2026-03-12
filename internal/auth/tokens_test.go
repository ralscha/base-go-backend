package auth

import "testing"

func TestNewToken(t *testing.T) {
	plain, hash, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
	if plain == "" {
		t.Fatal("expected plain token to be populated")
	}
	if hash == "" {
		t.Fatal("expected token hash to be populated")
	}
	if got := HashToken(plain); got != hash {
		t.Fatalf("HashToken() = %q, want %q", got, hash)
	}
}
