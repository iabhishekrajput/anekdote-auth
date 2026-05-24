package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/iabhishekrajput/anekdote-auth/internal/models"
	redisstore "github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
)

// ── Mock implementations ────────────────────────────────────────────────────

type mockUIUserStore struct {
	user    *models.User
	findErr error
	calls   int
}

func (m *mockUIUserStore) GetByID(_ uuid.UUID) (*models.User, error) {
	m.calls++
	return m.user, m.findErr
}

type mockUIRevStore struct {
	revoked bool
	err     error
}

func (m *mockUIRevStore) IsRevoked(_ context.Context, _ string) (bool, error) {
	return m.revoked, m.err
}

// ── Test helpers ─────────────────────────────────────────────────────────────

func setupUserInfoHandler(t *testing.T) (*UserInfoHandler, *crypto.KeyStore, *mockUIUserStore, *mockUIRevStore) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	derBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	hash := sha256.Sum256(derBytes)
	keyID := base64.RawURLEncoding.EncodeToString(hash[:])

	ks := &crypto.KeyStore{
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
		KeyID:      keyID,
	}
	us := &mockUIUserStore{}
	rs := &mockUIRevStore{}
	return NewUserInfoHandler(us, ks, rs, nil), ks, us, rs
}

func makeToken(t *testing.T, ks *crypto.KeyStore, sub, scope, jti string, expiry time.Duration) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":   "http://test",
		"sub":   sub,
		"aud":   "client-id",
		"exp":   time.Now().Add(expiry).Unix(),
		"iat":   time.Now().Unix(),
		"jti":   jti,
		"scope": scope,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = ks.KeyID
	signed, err := tok.SignedString(ks.PrivateKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func doUserInfo(t *testing.T, h *UserInfoHandler, method, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/userinfo", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rr := httptest.NewRecorder()
	h.UserInfo(rr, req, nil)
	return rr
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestUserInfo_ValidToken_OpenIDOnly(t *testing.T) {
	h, ks, us, _ := setupUserInfoHandler(t)
	userID := uuid.New()
	us.user = &models.User{ID: userID, UpdatedAt: time.Now()}
	tok := makeToken(t, ks, userID.String(), "openid", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["sub"] != userID.String() {
		t.Errorf("sub: expected %s, got %v", userID, resp["sub"])
	}
	if _, ok := resp["email"]; ok {
		t.Error("email should not be present for openid-only scope")
	}
	if _, ok := resp["name"]; ok {
		t.Error("name should not be present for openid-only scope")
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Error("Cache-Control: no-store must be set")
	}
}

func TestUserInfo_ValidToken_EmailScope(t *testing.T) {
	h, ks, us, _ := setupUserInfoHandler(t)
	userID := uuid.New()
	us.user = &models.User{ID: userID, Email: "user@example.com", IsVerified: true, UpdatedAt: time.Now()}
	tok := makeToken(t, ks, userID.String(), "openid email", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["email"] != "user@example.com" {
		t.Errorf("email: expected user@example.com, got %v", resp["email"])
	}
	if resp["email_verified"] != true {
		t.Errorf("email_verified: expected true, got %v", resp["email_verified"])
	}
}

func TestUserInfo_ValidToken_ProfileScope(t *testing.T) {
	h, ks, us, _ := setupUserInfoHandler(t)
	userID := uuid.New()
	now := time.Now()
	us.user = &models.User{ID: userID, Name: "Alice", UpdatedAt: now}
	tok := makeToken(t, ks, userID.String(), "openid profile", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["name"] != "Alice" {
		t.Errorf("name: expected Alice, got %v", resp["name"])
	}
	if _, ok := resp["updated_at"]; !ok {
		t.Error("updated_at must be present for profile scope")
	}
}

func TestUserInfo_ValidToken_AllScopes(t *testing.T) {
	h, ks, us, _ := setupUserInfoHandler(t)
	userID := uuid.New()
	us.user = &models.User{ID: userID, Name: "Bob", Email: "bob@example.com", IsVerified: false, UpdatedAt: time.Now()}
	tok := makeToken(t, ks, userID.String(), "openid profile email", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["sub"] == "" {
		t.Error("sub must be present")
	}
	if resp["name"] != "Bob" {
		t.Errorf("name: expected Bob, got %v", resp["name"])
	}
	if resp["email"] != "bob@example.com" {
		t.Errorf("email: expected bob@example.com, got %v", resp["email"])
	}
}

func TestUserInfo_MissingAuthHeader(t *testing.T) {
	h, _, _, _ := setupUserInfoHandler(t)
	rr := doUserInfo(t, h, http.MethodGet, "")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	wwwAuth := rr.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("WWW-Authenticate header must be present on 401")
	}
	// Missing token: no error= parameter, just realm (RFC 6750 §3.1)
	if wwwAuth != `Bearer realm="anekdote-auth"` {
		t.Errorf("WWW-Authenticate: expected realm-only, got %q", wwwAuth)
	}
}

func TestUserInfo_MalformedAuthHeader(t *testing.T) {
	h, _, _, _ := setupUserInfoHandler(t)
	rr := doUserInfo(t, h, http.MethodGet, "Basic dXNlcjpwYXNz")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-Bearer scheme, got %d", rr.Code)
	}
}

func TestUserInfo_BearerPrefixOnly(t *testing.T) {
	h, _, _, _ := setupUserInfoHandler(t)
	rr := doUserInfo(t, h, http.MethodGet, "Bearer ")

	// Empty token after "Bearer " is treated as malformed header
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty Bearer token, got %d", rr.Code)
	}
}

func TestUserInfo_MalformedJWT(t *testing.T) {
	h, _, _, _ := setupUserInfoHandler(t)
	rr := doUserInfo(t, h, http.MethodGet, "Bearer not.a.jwt")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	assertWWWAuthError(t, rr, "invalid_token")
}

func TestUserInfo_WrongKid(t *testing.T) {
	h, ks, _, _ := setupUserInfoHandler(t)
	// Sign with the right key but put a wrong kid in the header
	claims := jwt.MapClaims{
		"iss": "http://test", "sub": uuid.NewString(), "aud": "c",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"jti": uuid.NewString(), "scope": "openid",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "wrong-kid-value"
	signed, _ := tok.SignedString(ks.PrivateKey)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+signed)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong kid, got %d", rr.Code)
	}
	assertWWWAuthError(t, rr, "invalid_token")
}

func TestUserInfo_MissingKid(t *testing.T) {
	h, ks, _, _ := setupUserInfoHandler(t)
	claims := jwt.MapClaims{
		"iss": "http://test", "sub": uuid.NewString(), "aud": "c",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"jti": uuid.NewString(), "scope": "openid",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// No kid header set — tok.Header["kid"] is absent
	delete(tok.Header, "kid")
	signed, _ := tok.SignedString(ks.PrivateKey)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+signed)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing kid, got %d", rr.Code)
	}
}

func TestUserInfo_WrongAlgorithm(t *testing.T) {
	h, _, _, _ := setupUserInfoHandler(t)
	// HS256 token — should be rejected by WithValidMethods
	secret := []byte("supersecret")
	claims := jwt.MapClaims{
		"iss": "http://test", "sub": uuid.NewString(), "aud": "c",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"jti": uuid.NewString(), "scope": "openid",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := tok.SignedString(secret)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+signed)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for HS256 token, got %d", rr.Code)
	}
}

func TestUserInfo_ExpiredToken(t *testing.T) {
	h, ks, _, _ := setupUserInfoHandler(t)
	tok := makeToken(t, ks, uuid.NewString(), "openid", uuid.NewString(), -time.Minute)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired token, got %d", rr.Code)
	}
	assertWWWAuthError(t, rr, "invalid_token")
}

func TestUserInfo_RevokedToken_DoesNotCallUserStore(t *testing.T) {
	h, ks, us, rs := setupUserInfoHandler(t)
	rs.revoked = true
	tok := makeToken(t, ks, uuid.NewString(), "openid", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked token, got %d", rr.Code)
	}
	if us.calls != 0 {
		t.Errorf("userStore.GetByID must not be called for revoked tokens, got %d calls", us.calls)
	}
	assertWWWAuthError(t, rr, "invalid_token")
}

func TestUserInfo_RedisRevocationError_FailClosed(t *testing.T) {
	h, ks, us, rs := setupUserInfoHandler(t)
	rs.err = goredis.ErrClosed
	tok := makeToken(t, ks, uuid.NewString(), "openid", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (fail closed) on Redis error, got %d", rr.Code)
	}
	if us.calls != 0 {
		t.Errorf("userStore.GetByID must not be called when revocation check fails, got %d calls", us.calls)
	}
}

func TestUserInfo_DisabledUser(t *testing.T) {
	h, ks, us, _ := setupUserInfoHandler(t)
	disabledAt := time.Now()
	userID := uuid.New()
	us.user = &models.User{ID: userID, DisabledAt: &disabledAt}
	tok := makeToken(t, ks, userID.String(), "openid", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for disabled user, got %d", rr.Code)
	}
	assertWWWAuthError(t, rr, "invalid_token")
}

func TestUserInfo_ClientCredentialsToken_EmptySub(t *testing.T) {
	h, ks, _, _ := setupUserInfoHandler(t)
	tok := makeToken(t, ks, "", "openid", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for empty sub (client_credentials), got %d", rr.Code)
	}
}

func TestUserInfo_InvalidUUIDSub(t *testing.T) {
	h, ks, _, _ := setupUserInfoHandler(t)
	tok := makeToken(t, ks, "not-a-uuid", "openid", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid UUID sub, got %d", rr.Code)
	}
}

func TestUserInfo_UserNotFound(t *testing.T) {
	h, ks, us, _ := setupUserInfoHandler(t)
	us.findErr = goredis.ErrClosed // any error
	tok := makeToken(t, ks, uuid.NewString(), "openid", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for user not found, got %d", rr.Code)
	}
}

func TestUserInfo_ScopeExactMatch_EmailRead_NotEmail(t *testing.T) {
	h, ks, us, _ := setupUserInfoHandler(t)
	userID := uuid.New()
	us.user = &models.User{ID: userID, Email: "user@example.com", UpdatedAt: time.Now()}
	// "email_read" must NOT trigger email claim — exact word match only
	tok := makeToken(t, ks, userID.String(), "openid email_read", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if _, ok := resp["email"]; ok {
		t.Error("email must not be present for 'email_read' scope (exact-word match required)")
	}
}

func TestUserInfo_EmptyScope(t *testing.T) {
	h, ks, us, _ := setupUserInfoHandler(t)
	userID := uuid.New()
	us.user = &models.User{ID: userID, UpdatedAt: time.Now()}
	tok := makeToken(t, ks, userID.String(), "", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["sub"] != userID.String() {
		t.Errorf("sub must be present even with empty scope")
	}
	if len(resp) != 1 {
		t.Errorf("expected only sub in response for empty scope, got %v", resp)
	}
}

func TestUserInfo_EmptyName_ProfileScope(t *testing.T) {
	h, ks, us, _ := setupUserInfoHandler(t)
	userID := uuid.New()
	us.user = &models.User{ID: userID, Name: "", UpdatedAt: time.Now()}
	tok := makeToken(t, ks, userID.String(), "openid profile", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if _, ok := resp["name"]; ok {
		t.Error("name claim must be omitted when user.Name is empty string")
	}
	if _, ok := resp["updated_at"]; !ok {
		t.Error("updated_at must be present for profile scope even when name is empty")
	}
}

func TestUserInfo_QueryParamTokenRejected(t *testing.T) {
	h, ks, us, _ := setupUserInfoHandler(t)
	userID := uuid.New()
	us.user = &models.User{ID: userID}
	tok := makeToken(t, ks, userID.String(), "openid", uuid.NewString(), time.Hour)

	// Token in query param (not Authorization header) — must be rejected
	req := httptest.NewRequest(http.MethodGet, "/userinfo?access_token="+tok, nil)
	rr := httptest.NewRecorder()
	h.UserInfo(rr, req, nil)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when token is in query param, got %d", rr.Code)
	}
}

func TestUserInfo_POST_AlsoWorks(t *testing.T) {
	h, ks, us, _ := setupUserInfoHandler(t)
	userID := uuid.New()
	us.user = &models.User{ID: userID, UpdatedAt: time.Now()}
	tok := makeToken(t, ks, userID.String(), "openid", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodPost, "Bearer "+tok)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for POST /userinfo, got %d", rr.Code)
	}
}

func TestUserInfo_ContentType(t *testing.T) {
	h, ks, us, _ := setupUserInfoHandler(t)
	userID := uuid.New()
	us.user = &models.User{ID: userID, UpdatedAt: time.Now()}
	tok := makeToken(t, ks, userID.String(), "openid", uuid.NewString(), time.Hour)

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)

	ct := rr.Header().Get("Content-Type")
	if ct == "" {
		t.Error("Content-Type must be set")
	}
}

// TestUserInfo_RevokedToken_WithRealRedis ensures the revocation check works
// against a real miniredis instance (not just the mock).
func TestUserInfo_RevokedToken_WithRealRedis(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()

	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	revStore := redisstore.NewRevocationStore(rdb)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	derBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	hash := sha256.Sum256(derBytes)
	keyID := base64.RawURLEncoding.EncodeToString(hash[:])
	ks := &crypto.KeyStore{PrivateKey: privKey, PublicKey: &privKey.PublicKey, KeyID: keyID}

	userID := uuid.New()
	us := &mockUIUserStore{user: &models.User{ID: userID, UpdatedAt: time.Now()}}
	h := NewUserInfoHandler(us, ks, revStore, rdb)

	jti := uuid.NewString()
	tok := makeToken(t, ks, userID.String(), "openid", jti, time.Hour)

	// Revoke the JTI
	if rErr := revStore.RevokeJTI(context.Background(), jti, time.Hour); rErr != nil {
		t.Fatalf("RevokeJTI: %v", rErr)
	}

	rr := doUserInfo(t, h, http.MethodGet, "Bearer "+tok)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked token, got %d", rr.Code)
	}
	if us.calls != 0 {
		t.Error("userStore.GetByID must not be called for revoked token")
	}
}

// ── Assertion helpers ────────────────────────────────────────────────────────

func assertWWWAuthError(t *testing.T, rr *httptest.ResponseRecorder, expectedError string) {
	t.Helper()
	wwwAuth := rr.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Errorf("WWW-Authenticate header missing on 401")
		return
	}
	// Must contain error="<expectedError>"
	want := `error="` + expectedError + `"`
	if !containsSubstr(wwwAuth, want) {
		t.Errorf("WWW-Authenticate: expected to contain %q, got %q", want, wwwAuth)
	}
}

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstrInner(s, sub))
}

func containsSubstrInner(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
