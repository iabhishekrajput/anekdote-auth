package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/auth"
)

// setupOAuth2HandlerWithIDToken is like setupOAuth2MockedHandler but wires the
// JWTGenerator as the IDTokenGenerator so that id_token is emitted on /token.
// The generator uses nil claimsReader so id_token generation requires no SQL.
func setupOAuth2HandlerWithIDToken(t *testing.T) (*OAuth2Handler, sqlmock.Sqlmock, func()) {
	t.Helper()
	h, mock, mr := setupOAuth2MockedHandler(t)
	jwtGen := auth.NewJWTGenerator(h.keyStore, "http://localhost:8080", nil, nil, nil, nil, nil)
	h.idTokenGen = jwtGen
	return h, mock, func() { mr.Close() }
}

// TestOAuth2FullFlow exercises the complete Authorization Code + PKCE flow:
//
//  1. GET /authorize → consent form (200)
//  2. POST /authorize?accept=true → redirect with authorization code (302)
//  3. POST /token with code + verifier → JWT access token (200)
//  4. JWT signature verified against the server's RSA public key
//  5. POST /revoke → 200; JTI added to blocklist
//  6. Blocklist confirmed via RevocationStore
func TestOAuth2FullFlow(t *testing.T) {
	handler, mock, mr := setupOAuth2MockedHandler(t)
	defer mr.Close()

	const (
		clientID    = "flow-client"
		redirectURI = "http://localhost/callback"
		// Plain PKCE: code_challenge == code_verifier (must be 43-128 chars)
		codeVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // 43 chars
		codeChallenge = codeVerifier                                  // plain method
	)

	userID := uuid.New().String()
	sessionID, err := handler.sessionStore.Create(context.Background(), userID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// ─── Step 1: GET /authorize ── renders consent form ──────────────────────
	authorizeURL := "/authorize?client_id=" + clientID +
		"&response_type=code" +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code_challenge=" + codeChallenge +
		"&code_challenge_method=plain" +
		"&scope=openid+profile"

	req1 := httptest.NewRequest(http.MethodGet, authorizeURL, nil)
	req1.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})
	rr1 := httptest.NewRecorder()
	handler.Authorize(rr1, req1, nil)

	// GetClient is called by our display code (GET path), sqlmock returns error → gracefully skipped.
	// So no expectation needed for step 1. The consent form must still render (200).
	if rr1.Code != http.StatusOK {
		t.Fatalf("step 1 GET /authorize: expected 200, got %d\nbody: %s", rr1.Code, rr1.Body.String())
	}
	if !strings.Contains(rr1.Body.String(), "Authorize") {
		t.Error("step 1: expected consent page body to contain 'Authorize'")
	}

	// ─── Step 2: POST /authorize?accept=true ─────────────────────────────────
	// go-oauth2 calls GetClient once (via GenerateAuthToken → GetByID) to validate redirect_uri.
	mock.ExpectQuery(`SELECT name, secret, domain, public, org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs(clientID).
		WillReturnRows(sqlmock.NewRows([]string{"name", "secret", "domain", "public", "org_id"}).
			AddRow("Flow Client", "", redirectURI, true, nil))

	postForm := url.Values{}
	postForm.Set("client_id", clientID)
	postForm.Set("response_type", "code")
	postForm.Set("redirect_uri", redirectURI)
	postForm.Set("code_challenge", codeChallenge)
	postForm.Set("code_challenge_method", "plain")
	postForm.Set("scope", "openid profile")
	postForm.Set("accept", "true")

	req2 := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(postForm.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})
	rr2 := httptest.NewRecorder()
	handler.Authorize(rr2, req2, nil)

	if rr2.Code != http.StatusFound {
		t.Fatalf("step 2 POST /authorize: expected 302, got %d\nbody: %s", rr2.Code, rr2.Body.String())
	}
	loc := rr2.Header().Get("Location")
	if loc == "" {
		t.Fatal("step 2: missing Location header")
	}
	locURL, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("step 2: parse Location %q: %v", loc, err)
	}
	code := locURL.Query().Get("code")
	if code == "" {
		t.Fatalf("step 2: no 'code' in Location %q", loc)
	}

	// ─── Step 3: POST /token ─────────────────────────────────────────────────
	// go-oauth2 calls GetClient once (via GenerateAccessToken → GetByID).
	mock.ExpectQuery(`SELECT name, secret, domain, public, org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs(clientID).
		WillReturnRows(sqlmock.NewRows([]string{"name", "secret", "domain", "public", "org_id"}).
			AddRow("Flow Client", "", redirectURI, true, nil))
	// JWTGenerator.Token calls GetCustomClaims for the access token.
	mock.ExpectQuery(`SELECT key, value_type, value, COALESCE\(scope_gate,''\), COALESCE\(destinations,'token'\) FROM client_claim_definitions WHERE client_id = \$1`).
		WithArgs(clientID).
		WillReturnRows(sqlmock.NewRows([]string{"key", "value_type", "value", "coalesce", "coalesce"}))

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("client_id", clientID)
	tokenForm.Set("code", code)
	tokenForm.Set("redirect_uri", redirectURI)
	tokenForm.Set("code_verifier", codeVerifier)

	req3 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr3 := httptest.NewRecorder()
	handler.Token(rr3, req3, nil)

	if rr3.Code != http.StatusOK {
		t.Fatalf("step 3 POST /token: expected 200, got %d\nbody: %s", rr3.Code, rr3.Body.String())
	}

	var tokenResp map[string]any
	if err := json.Unmarshal(rr3.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("step 3: parse token response JSON: %v", err)
	}
	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("step 3: missing or empty access_token in response: %v", tokenResp)
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Errorf("step 3: expected token_type=Bearer, got %v", tokenResp["token_type"])
	}

	// ─── Step 4: Validate JWT signature ──────────────────────────────────────
	parsed, err := jwt.Parse(accessToken, func(tok *jwt.Token) (any, error) {
		return handler.keyStore.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("step 4: JWT parse/verify: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("step 4: JWT is not valid")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("step 4: unexpected claims type")
	}
	if claims["sub"] != userID {
		t.Errorf("step 4: expected sub=%s, got %v", userID, claims["sub"])
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		t.Fatal("step 4: missing jti claim")
	}

	// ─── Step 5: POST /revoke ─────────────────────────────────────────────────
	revokeForm := url.Values{}
	revokeForm.Set("token", accessToken)

	req5 := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(revokeForm.Encode()))
	req5.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr5 := httptest.NewRecorder()
	handler.Revoke(rr5, req5, nil)

	if rr5.Code != http.StatusOK {
		t.Errorf("step 5 POST /revoke: expected 200, got %d", rr5.Code)
	}

	// ─── Step 6: Verify blocklist ─────────────────────────────────────────────
	revoked, err := handler.revocStore.IsRevoked(context.Background(), jti)
	if err != nil {
		t.Fatalf("step 6: IsJTIRevoked: %v", err)
	}
	if !revoked {
		t.Error("step 6: expected JTI to be in revocation blocklist after /revoke")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled sqlmock expectations: %v", err)
	}
}

// runNonceFlow runs the authorize→token sequence with an optional nonce and returns
// the parsed id_token claims.  The caller is responsible for setting up the mock
// expectations on `mock` before calling.
func runNonceFlow(t *testing.T, handler *OAuth2Handler, mock sqlmock.Sqlmock, nonce string) jwt.MapClaims {
	t.Helper()

	const (
		clientID      = "nonce-client"
		redirectURI   = "http://localhost/callback"
		codeVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		codeChallenge = codeVerifier
	)

	userID := uuid.New().String()
	sessionID, err := handler.sessionStore.Create(context.Background(), userID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// POST /authorize with accept=true
	mock.ExpectQuery(`SELECT name, secret, domain, public, org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs(clientID).
		WillReturnRows(sqlmock.NewRows([]string{"name", "secret", "domain", "public", "org_id"}).
			AddRow("Nonce Client", "", redirectURI, true, nil))

	postForm := url.Values{}
	postForm.Set("client_id", clientID)
	postForm.Set("response_type", "code")
	postForm.Set("redirect_uri", redirectURI)
	postForm.Set("code_challenge", codeChallenge)
	postForm.Set("code_challenge_method", "plain")
	postForm.Set("scope", "openid profile")
	postForm.Set("accept", "true")
	if nonce != "" {
		postForm.Set("nonce", nonce)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(postForm.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})
	rr2 := httptest.NewRecorder()
	handler.Authorize(rr2, req2, nil)

	if rr2.Code != http.StatusFound {
		t.Fatalf("POST /authorize: expected 302, got %d\nbody: %s", rr2.Code, rr2.Body.String())
	}
	locURL, _ := url.Parse(rr2.Header().Get("Location"))
	code := locURL.Query().Get("code")
	if code == "" {
		t.Fatalf("POST /authorize: no code in Location %q", rr2.Header().Get("Location"))
	}

	// POST /token
	mock.ExpectQuery(`SELECT name, secret, domain, public, org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs(clientID).
		WillReturnRows(sqlmock.NewRows([]string{"name", "secret", "domain", "public", "org_id"}).
			AddRow("Nonce Client", "", redirectURI, true, nil))
	// Access token custom claims — real jwtGen has clientStore as claimsReader.
	mock.ExpectQuery(`SELECT key, value_type, value, COALESCE\(scope_gate,''\), COALESCE\(destinations,'token'\) FROM client_claim_definitions WHERE client_id = \$1`).
		WithArgs(clientID).
		WillReturnRows(sqlmock.NewRows([]string{"key", "value_type", "value", "coalesce", "coalesce"}))

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("client_id", clientID)
	tokenForm.Set("code", code)
	tokenForm.Set("redirect_uri", redirectURI)
	tokenForm.Set("code_verifier", codeVerifier)

	req3 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr3 := httptest.NewRecorder()
	handler.Token(rr3, req3, nil)

	if rr3.Code != http.StatusOK {
		t.Fatalf("POST /token: expected 200, got %d\nbody: %s", rr3.Code, rr3.Body.String())
	}

	var tokenResp map[string]any
	if err := json.Unmarshal(rr3.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("parse token response: %v", err)
	}
	idTokenStr, ok := tokenResp["id_token"].(string)
	if !ok || idTokenStr == "" {
		t.Fatalf("expected id_token in response, got: %v", tokenResp)
	}

	parser := jwt.NewParser()
	parsed, _, parseErr := parser.ParseUnverified(idTokenStr, jwt.MapClaims{})
	if parseErr != nil {
		t.Fatalf("parse id_token: %v", parseErr)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("unexpected claims type in id_token")
	}
	return claims
}

// TestOAuth2Nonce_HappyPath verifies that a nonce sent in /authorize is echoed
// back in the id_token nonce claim after /token exchange.
func TestOAuth2Nonce_HappyPath(t *testing.T) {
	handler, mock, cleanup := setupOAuth2HandlerWithIDToken(t)
	defer cleanup()

	claims := runNonceFlow(t, handler, mock, "test-nonce-xyz")

	if claims["nonce"] != "test-nonce-xyz" {
		t.Errorf("expected nonce=test-nonce-xyz in id_token, got %v", claims["nonce"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled sqlmock expectations: %v", err)
	}
}

// TestOAuth2Nonce_NotPresent verifies that when no nonce is sent in /authorize,
// the id_token contains no nonce claim.
func TestOAuth2Nonce_NotPresent(t *testing.T) {
	handler, mock, cleanup := setupOAuth2HandlerWithIDToken(t)
	defer cleanup()

	claims := runNonceFlow(t, handler, mock, "")

	if _, has := claims["nonce"]; has {
		t.Errorf("expected no nonce claim in id_token when none sent, got %v", claims["nonce"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled sqlmock expectations: %v", err)
	}
}

// failingNonceStore wraps a real NonceRevokeStore and replaces ConsumeNonce with
// a hard error, simulating a Redis failure during nonce retrieval at /token time.
type failingNonceStore struct {
	NonceRevokeStore
}

func (f *failingNonceStore) ConsumeNonce(_ context.Context, _ string) (string, error) {
	return "", errors.New("redis unavailable")
}

// TestOAuth2Nonce_FailClosed verifies that a Redis failure during ConsumeNonce at
// /token time causes the entire token response to fail (fail-closed), rather than
// silently omitting the nonce and issuing an id_token without nonce binding.
func TestOAuth2Nonce_FailClosed(t *testing.T) {
	handler, mock, cleanup := setupOAuth2HandlerWithIDToken(t)
	defer cleanup()

	// Replace the revoc store with one whose ConsumeNonce always errors.
	handler.revocStore = &failingNonceStore{handler.revocStore}

	const (
		clientID      = "nonce-client"
		redirectURI   = "http://localhost/callback"
		codeVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		codeChallenge = codeVerifier
	)

	userID := uuid.New().String()
	sessionID, err := handler.sessionStore.Create(context.Background(), userID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// POST /authorize with accept=true to get an auth code.
	mock.ExpectQuery(`SELECT name, secret, domain, public, org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs(clientID).
		WillReturnRows(sqlmock.NewRows([]string{"name", "secret", "domain", "public", "org_id"}).
			AddRow("Nonce Client", "", redirectURI, true, nil))

	postForm := url.Values{}
	postForm.Set("client_id", clientID)
	postForm.Set("response_type", "code")
	postForm.Set("redirect_uri", redirectURI)
	postForm.Set("code_challenge", codeChallenge)
	postForm.Set("code_challenge_method", "plain")
	postForm.Set("scope", "openid profile")
	postForm.Set("accept", "true")
	postForm.Set("nonce", "fail-closed-nonce")

	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(postForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})
	rr := httptest.NewRecorder()
	handler.Authorize(rr, req, nil)

	if rr.Code != http.StatusFound {
		t.Fatalf("POST /authorize: expected 302, got %d", rr.Code)
	}
	locURL, _ := url.Parse(rr.Header().Get("Location"))
	code := locURL.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in Location %q", rr.Header().Get("Location"))
	}

	// POST /token — ConsumeNonce errors, so the whole request must fail (non-200).
	mock.ExpectQuery(`SELECT name, secret, domain, public, org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs(clientID).
		WillReturnRows(sqlmock.NewRows([]string{"name", "secret", "domain", "public", "org_id"}).
			AddRow("Nonce Client", "", redirectURI, true, nil))
	mock.ExpectQuery(`SELECT key, value_type, value, COALESCE\(scope_gate,''\), COALESCE\(destinations,'token'\) FROM client_claim_definitions WHERE client_id = \$1`).
		WithArgs(clientID).
		WillReturnRows(sqlmock.NewRows([]string{"key", "value_type", "value", "coalesce", "coalesce"}))

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("client_id", clientID)
	tokenForm.Set("code", code)
	tokenForm.Set("redirect_uri", redirectURI)
	tokenForm.Set("code_verifier", codeVerifier)

	req2 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	handler.Token(rr2, req2, nil)

	if rr2.Code == http.StatusOK {
		t.Errorf("expected non-200 when ConsumeNonce fails (fail-closed), got 200; body: %s", rr2.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled sqlmock expectations: %v", err)
	}
}

// Ensure failingNonceStore compiles against the interface.
var _ NonceRevokeStore = (*failingNonceStore)(nil)
