package redisutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// HashForStorage returns the lowercase hex SHA-256 of val.
// Store this as the Redis key or value so the raw secret never appears in Redis.
// On lookup, hash the submitted value the same way.
func HashForStorage(val string) string {
	sum := sha256.Sum256([]byte(val))
	return hex.EncodeToString(sum[:])
}

// Encrypt encrypts plaintext with AES-256-GCM using key (must be exactly 32 bytes).
// Returns standard base64-encoded nonce||ciphertext||tag. Each call produces a
// unique ciphertext due to a random nonce.
func Encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt reverses Encrypt. Returns an error if the ciphertext is malformed,
// the key is wrong, or the GCM tag check fails.
func Decrypt(key []byte, ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	pt, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
