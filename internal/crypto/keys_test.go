package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadKeys_Success(t *testing.T) {
	// Create temporary directory for keys
	tempDir := t.TempDir()
	privPath := filepath.Join(tempDir, "private.pem")
	pubPath := filepath.Join(tempDir, "public.pem")

	// Generate RSA keypair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Write Private Key PEM
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		t.Fatalf("failed to write private key: %v", err)
	}

	// Write Public Key PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		t.Fatalf("failed to write public key: %v", err)
	}

	// Test Loading
	ks, err := LoadKeys(privPath, pubPath)
	if err != nil {
		t.Fatalf("LoadKeys failed: %v", err)
	}

	if ks.PrivateKey == nil || ks.PublicKey == nil {
		t.Errorf("expected KeyStore to be populated, got nil fields")
	}

	// Verify the loaded key matches
	if ks.PrivateKey.N.Cmp(privateKey.N) != 0 {
		t.Errorf("loaded private key modulus doesn't match")
	}
}

func TestLoadKeys_MissingFiles(t *testing.T) {
	_, err := LoadKeys("does-not-exist.pem", "also-does-not-exist.pem")
	if err == nil {
		t.Errorf("expected error when file is missing, got nil")
	}
}
