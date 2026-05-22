package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	oredis "github.com/go-oauth2/redis/v4"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
)

func TestBuildServer(t *testing.T) {
	// Initialize with nils/dummys just to ensure wiring works and doesn't panic
	srv, gen := BuildServer(
		&postgres.ClientStore{},
		&oredis.TokenStore{},
		&redis.RevocationStore{},
		&crypto.KeyStore{},
		nil, // orgReader — nil is valid (no org membership checks)
		"http://localhost",
		nil, // rdb — nil disables token-index tracking
		nil, // userStore — nil disables scope claim injection
	)

	if srv == nil {
		t.Fatalf("expected non-nil server")
	}
	if gen == nil {
		t.Fatalf("expected non-nil JWTGenerator")
	}

	// Request validation testing
	if srv.ClientInfoHandler == nil {
		t.Errorf("expected client info handler to be populated")
	}
}

func TestJWTGenerator_Token(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key")
	}
	keyStore := &crypto.KeyStore{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}

	gen := NewJWTGenerator(keyStore, "http://issuer", nil, nil, nil)

	client := &models.Client{ID: "client-id"}
	tokenInfo := &models.Token{
		AccessExpiresIn: time.Hour,
		Scope:           "read write",
	}

	data := &oauth2.GenerateBasic{
		Client:    client,
		UserID:    "user-123",
		TokenInfo: tokenInfo,
		Request:   &http.Request{},
	}

	access, refresh, err := gen.Token(context.Background(), data, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if access == "" {
		t.Errorf("expected non-empty access token")
	}
	if refresh == "" {
		t.Errorf("expected non-empty refresh token")
	}

	// Test without refresh
	_, refresh, err = gen.Token(context.Background(), data, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if refresh != "" {
		t.Errorf("expected empty refresh token")
	}
}
