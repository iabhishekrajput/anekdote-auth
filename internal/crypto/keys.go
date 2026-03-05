package crypto

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type KeyStore struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	KeyID      string
}

func LoadKeys(privPath, pubPath string) (*KeyStore, error) {
	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		return nil, err
	}
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privBytes)
	if err != nil {
		return nil, err
	}

	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, err
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubBytes)
	if err != nil {
		return nil, err
	}

	derBytes := x509.MarshalPKCS1PublicKey(pubKey)
	hash := sha256.Sum256(derBytes)
	keyID := base64.RawURLEncoding.EncodeToString(hash[:])

	return &KeyStore{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		KeyID:      keyID,
	}, nil
}
