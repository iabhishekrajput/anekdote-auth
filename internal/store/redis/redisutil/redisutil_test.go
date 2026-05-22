package redisutil_test

import (
	"testing"

	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis/redisutil"
)

func TestHashForStorage(t *testing.T) {
	h1 := redisutil.HashForStorage("test123")
	h2 := redisutil.HashForStorage("test123")
	if h1 != h2 {
		t.Error("same input must produce same hash")
	}
	h3 := redisutil.HashForStorage("different")
	if h1 == h3 {
		t.Error("different inputs must produce different hashes")
	}
	if len(h1) != 64 {
		t.Errorf("SHA-256 hex should be 64 chars, got %d", len(h1))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	plaintext := "super-secret-oauth-client-key"
	ct1, err := redisutil.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := redisutil.Decrypt(key, ct1)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != plaintext {
		t.Errorf("Decrypt: got %q want %q", got, plaintext)
	}

	// Each encryption produces a unique ciphertext (random nonce).
	ct2, _ := redisutil.Encrypt(key, plaintext)
	if ct1 == ct2 {
		t.Error("two encryptions of the same plaintext must differ")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key := make([]byte, 32)
	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xFF

	ct, err := redisutil.Encrypt(key, "secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = redisutil.Decrypt(wrongKey, ct)
	if err == nil {
		t.Error("Decrypt with wrong key should return an error")
	}
}

func TestDecryptMalformed(t *testing.T) {
	key := make([]byte, 32)
	_, err := redisutil.Decrypt(key, "not-base64!!")
	if err == nil {
		t.Error("Decrypt of malformed ciphertext should return an error")
	}
}
