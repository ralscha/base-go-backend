package auth

import (
	"errors"
	"strings"

	"github.com/alexedwards/argon2id"
)

var ErrWeakPassword = errors.New("password must be at least 12 characters")

var invalidCredentialsSentinelHash = mustCreateInvalidCredentialsSentinelHash()

func HashPassword(password string) (string, error) {
	if len(strings.TrimSpace(password)) < 12 {
		return "", ErrWeakPassword
	}

	params := *argon2id.DefaultParams
	params.Iterations = 3
	return argon2id.CreateHash(password, &params)
}

func ComparePassword(password, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}

func compareWithInvalidCredentialsSentinel(password string) error {
	_, err := ComparePassword(password, invalidCredentialsSentinelHash)
	return err
}

func mustCreateInvalidCredentialsSentinelHash() string {
	params := *argon2id.DefaultParams
	params.Iterations = 3

	hash, err := argon2id.CreateHash("invalid-credentials-sentinel", &params)
	if err != nil {
		panic(err)
	}

	return hash
}
