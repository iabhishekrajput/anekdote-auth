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

const testAppURL = "https://example.test"

func setupDiscoveryMockedHandler(t *testing.T) *DiscoveryHandler {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key")
	}
	keyStore := &crypto.KeyStore{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}

	return NewDiscoveryHandler(keyStore, testAppURL)
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

	want := map[string]string{
		"issuer":                 testAppURL,
		"authorization_endpoint": testAppURL + "/authorize",
		"token_endpoint":         testAppURL + "/token",
		"userinfo_endpoint":      testAppURL + "/userinfo",
		"jwks_uri":               testAppURL + "/.well-known/jwks.json",
		"revocation_endpoint":    testAppURL + "/revoke",
	}
	got := map[string]string{
		"issuer":                 config.Issuer,
		"authorization_endpoint": config.AuthorizationEndpoint,
		"token_endpoint":         config.TokenEndpoint,
		"userinfo_endpoint":      config.UserinfoEndpoint,
		"jwks_uri":               config.JwksURI,
		"revocation_endpoint":    config.RevocationEndpoint,
	}
	for field, expected := range want {
		if got[field] != expected {
			t.Errorf("%s: expected %q, got %q", field, expected, got[field])
		}
	}

	// response_types_supported must be ["code"] only — implicit/hybrid flows are not implemented
	if len(config.ResponseTypesSupported) != 1 || config.ResponseTypesSupported[0] != "code" {
		t.Errorf("response_types_supported: expected [\"code\"], got %v", config.ResponseTypesSupported)
	}

	// Required new fields must be populated
	if len(config.ScopesSupported) == 0 {
		t.Error("scopes_supported: must not be empty")
	}
	if len(config.ClaimsSupported) == 0 {
		t.Error("claims_supported: must not be empty")
	}
	if len(config.GrantTypesSupported) == 0 {
		t.Error("grant_types_supported: must not be empty")
	}
	if len(config.CodeChallengeMethodsSupported) == 0 {
		t.Error("code_challenge_methods_supported: must not be empty")
	}
}

// TestOpenIDConfigurationUsesAppURLOverRequestScheme locks in the fix for the
// "scheme echoed from request" regression — behind a TLS-terminating proxy the
// inbound request is plain HTTP, but the discovery document must still publish
// the configured public URL (https) so RFC 8414 §2 clients accept the issuer.
func TestOpenIDConfigurationUsesAppURLOverRequestScheme(t *testing.T) {
	handler := setupDiscoveryMockedHandler(t)

	req := httptest.NewRequest(http.MethodGet, "http://origin-pod.cluster.local/.well-known/openid-configuration", nil)
	req.Host = "origin-pod.cluster.local"
	req.TLS = nil
	rr := httptest.NewRecorder()

	handler.OpenIDConfiguration(rr, req, nil)

	var config OIDCConfig
	if err := json.NewDecoder(rr.Body).Decode(&config); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	for field, value := range map[string]string{
		"issuer":                 config.Issuer,
		"authorization_endpoint": config.AuthorizationEndpoint,
		"token_endpoint":         config.TokenEndpoint,
		"jwks_uri":               config.JwksURI,
		"revocation_endpoint":    config.RevocationEndpoint,
	} {
		if value == "" {
			t.Errorf("%s: unexpectedly empty", field)
			continue
		}
		if value[:8] != "https://" {
			t.Errorf("%s: expected https:// prefix, got %q", field, value)
		}
		if value[:len(testAppURL)] != testAppURL {
			t.Errorf("%s: expected to start with %q, got %q", field, testAppURL, value)
		}
	}
}
