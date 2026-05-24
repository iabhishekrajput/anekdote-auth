package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

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

	userID := uuid.New()
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
	if claims["sub"] != userID.String() {
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
