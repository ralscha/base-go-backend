package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var ErrInvalidEncryptionKey = errors.New("security encryption key must be at least 32 characters")

func encryptSecret(secret, key string) ([]byte, []byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	return aead.Seal(nil, nonce, []byte(secret), nil), nonce, nil
}

func decryptSecret(ciphertext, nonce []byte, key string) (string, error) {
	aead, err := newGCM(key)
	if err != nil {
		return "", err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func newGCM(key string) (cipher.AEAD, error) {
	if len(key) < 32 {
		return nil, ErrInvalidEncryptionKey
	}

	block, err := aes.NewCipher([]byte(key[:32]))
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}

	return cipher.NewGCM(block)
}
