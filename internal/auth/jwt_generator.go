package auth

import (
	"context"
	"errors"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
)

// JWTGenerator implements oauth2.AccessGenerate
type JWTGenerator struct {
	keyStore *crypto.KeyStore
	issuer   string
}

func NewJWTGenerator(keyStore *crypto.KeyStore, issuer string) *JWTGenerator {
	return &JWTGenerator{
		keyStore: keyStore,
		issuer:   issuer,
	}
}

// Token creates a signed JWT Access Token and an optional ID Token
func (g *JWTGenerator) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	jti := uuid.New().String()

	// 1. Generate Access Token (JWT)
	claims := jwt.MapClaims{
		"iss":   g.issuer,
		"sub":   data.UserID,         // Resource Owner ID
		"aud":   data.Client.GetID(), // Client ID
		"exp":   time.Now().Add(data.TokenInfo.GetAccessExpiresIn()).Unix(),
		"iat":   time.Now().Unix(),
		"jti":   jti, // JWT ID for fast revocation tracking
		"scope": data.TokenInfo.GetScope(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "anekdote-key-1" // Standard for JWKS mapping

	access, err = token.SignedString(g.keyStore.PrivateKey)
	if err != nil {
		return "", "", errors.New("internal server error signing jwt")
	}

	// 2. Refresh Token (Opaque string, no need for it to be a massive JWT)
	if isGenRefresh {
		refresh = uuid.New().String()
	}

	return access, refresh, nil
}
