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
	jwtpkg "github.com/golang-jwt/jwt/v5"
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

	gen := NewJWTGenerator(keyStore, "http://issuer", nil, nil, nil, nil, nil)

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

// TestJWTGenerator_OrgIDInjection_ClientCredentials verifies that when a
// client_credentials grant is issued with an OrgClientInfo that has a non-nil
// OrgID, the resulting access token contains an org_id claim.
func TestJWTGenerator_OrgIDInjection_ClientCredentials(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	keyStore := &crypto.KeyStore{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		KeyID:      "test-kid",
	}
	gen := NewJWTGenerator(keyStore, "http://issuer", nil, nil, nil, nil, nil)

	orgID := "org-service-acct"
	// Simulate a service account: UserID is empty (client_credentials), OrgClientInfo with OrgID set.
	innerClient := &models.Client{ID: "sa-client", Secret: ""}
	wrappedClient := &postgres.OrgClientInfo{ClientInfo: innerClient, OrgID: &orgID}

	tokenInfo := &models.Token{
		AccessExpiresIn: time.Hour,
		Scope:           "read:client_claims",
	}
	data := &oauth2.GenerateBasic{
		Client:    wrappedClient,
		UserID:    "", // empty = client_credentials
		TokenInfo: tokenInfo,
		Request:   &http.Request{},
	}

	access, _, err := gen.Token(context.Background(), data, false)
	if err != nil {
		t.Fatalf("Token(): unexpected error: %v", err)
	}
	if access == "" {
		t.Fatal("expected non-empty access token")
	}

	// Parse the JWT and verify org_id claim.
	parsed, _, parseErr := new(jwtpkg.Parser).ParseUnverified(access, jwtpkg.MapClaims{})
	if parseErr != nil {
		t.Fatalf("parse JWT: %v", parseErr)
	}
	mc, ok := parsed.Claims.(jwtpkg.MapClaims)
	if !ok {
		t.Fatal("expected MapClaims")
	}
	if mc["org_id"] != orgID {
		t.Errorf("expected org_id=%q in access token, got %v", orgID, mc["org_id"])
	}
}

// TestJWTGenerator_OrgIDInjection_NotInjectedForPlainClient verifies that
// org_id is NOT injected when using a plain models.Client (not OrgClientInfo)
// even for a client_credentials grant.
func TestJWTGenerator_OrgIDInjection_NotInjectedForPlainClient(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	keyStore := &crypto.KeyStore{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		KeyID:      "test-kid",
	}
	gen := NewJWTGenerator(keyStore, "http://issuer", nil, nil, nil, nil, nil)

	// Plain client — not an OrgClientInfo, so org_id injection guard won't fire
	plainClient := &models.Client{ID: "plain-client", Secret: ""}

	tokenInfo := &models.Token{
		AccessExpiresIn: time.Hour,
		Scope:           "openid",
	}
	data := &oauth2.GenerateBasic{
		Client:    plainClient,
		UserID:    "", // client_credentials
		TokenInfo: tokenInfo,
		Request:   &http.Request{},
	}

	access, _, err := gen.Token(context.Background(), data, false)
	if err != nil {
		t.Fatalf("Token(): unexpected error: %v", err)
	}

	parsed, _, _ := new(jwtpkg.Parser).ParseUnverified(access, jwtpkg.MapClaims{})
	mc, _ := parsed.Claims.(jwtpkg.MapClaims)
	// org_id must not appear for a plain client
	if _, has := mc["org_id"]; has {
		t.Errorf("org_id must not be injected for a plain client (non-OrgClientInfo), got %v", mc["org_id"])
	}
}

// TestJWTGenerator_OrgIDInjection_NilOrgID verifies no org_id is injected
// when OrgClientInfo has a nil OrgID (public / multi-org client).
func TestJWTGenerator_OrgIDInjection_NilOrgID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	keyStore := &crypto.KeyStore{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		KeyID:      "test-kid",
	}
	gen := NewJWTGenerator(keyStore, "http://issuer", nil, nil, nil, nil, nil)

	innerClient := &models.Client{ID: "multi-org-client", Secret: ""}
	wrappedClient := &postgres.OrgClientInfo{ClientInfo: innerClient, OrgID: nil}

	tokenInfo := &models.Token{
		AccessExpiresIn: time.Hour,
		Scope:           "openid",
	}
	data := &oauth2.GenerateBasic{
		Client:    wrappedClient,
		UserID:    "", // client_credentials but no org bound
		TokenInfo: tokenInfo,
		Request:   &http.Request{},
	}

	access, _, err := gen.Token(context.Background(), data, false)
	if err != nil {
		t.Fatalf("Token(): unexpected error: %v", err)
	}

	parsed, _, _ := new(jwtpkg.Parser).ParseUnverified(access, jwtpkg.MapClaims{})
	mc, _ := parsed.Claims.(jwtpkg.MapClaims)
	if _, has := mc["org_id"]; has {
		t.Errorf("org_id must not be present when OrgClientInfo.OrgID is nil, got %v", mc["org_id"])
	}
}
