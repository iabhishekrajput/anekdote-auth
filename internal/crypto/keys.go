package crypto

import (
	"crypto/rsa"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type KeyStore struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
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

	return &KeyStore{
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}
