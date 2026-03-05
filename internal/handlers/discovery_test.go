package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
)

func setupDiscoveryMockedHandler(t *testing.T) *DiscoveryHandler {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key")
	}
	keyStore := &crypto.KeyStore{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}

	return NewDiscoveryHandler(keyStore)
}

func TestWellKnownJWKS(t *testing.T) {
	handler := setupDiscoveryMockedHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.WellKnownJWKS(rr, req, nil)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", status)
	}

	var jwks JWKS
	if err := json.NewDecoder(rr.Body).Decode(&jwks); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(jwks.Keys) == 0 {
		t.Fatalf("expected at least 1 key in JWKS, got 0")
	}

	key := jwks.Keys[0]
	if key.Kty != "RSA" {
		t.Errorf("expected key type RSA, got %s", key.Kty)
	}
	if key.Use != "sig" {
		t.Errorf("expected use sig, got %s", key.Use)
	}
	if key.Alg != "RS256" {
		t.Errorf("expected alg RS256, got %s", key.Alg)
	}
}

func TestOpenIDConfiguration(t *testing.T) {
	handler := setupDiscoveryMockedHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	handler.OpenIDConfiguration(rr, req, nil)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", status)
	}

	var config OIDCConfig
	if err := json.NewDecoder(rr.Body).Decode(&config); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if config.Issuer == "" {
		t.Errorf("expected non-empty issuer")
	}
	if config.AuthorizationEndpoint == "" {
		t.Errorf("expected non-empty authorization_endpoint")
	}
	if config.JwksURI == "" {
		t.Errorf("expected non-empty jwks_uri")
	}
}
