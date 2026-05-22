package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	oredis "github.com/go-oauth2/redis/v4"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/auth"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/iabhishekrajput/anekdote-auth/internal/models"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	redisStore "github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
)

// mockOrgStore is a minimal oauth2OrgStore for testing the org-denial path.
type mockOrgStore struct {
	membership string
	memberErr  error
	org        *models.Org
}

func (m *mockOrgStore) GetMembership(_ context.Context, _, _ uuid.UUID) (string, error) {
	return m.membership, m.memberErr
}

func (m *mockOrgStore) GetOrgByID(_ context.Context, _ uuid.UUID) (*models.Org, error) {
	if m.org != nil {
		return m.org, nil
	}
	return nil, errors.New("not found")
}

func setupOAuth2HandlerWithOrgStore(t *testing.T, orgStore oauth2OrgStore) (*OAuth2Handler, sqlmock.Sqlmock, *miniredis.Miniredis) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	sessionStore := redisStore.NewSessionStore(rdb)
	revocStore := redisStore.NewRevocationStore(rdb)
	clientStore := postgres.NewClientStore(db)
	tokenStore := oredis.NewRedisStore(rdb.Options(), "token:")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	keyStore := &crypto.KeyStore{PrivateKey: privateKey, PublicKey: &privateKey.PublicKey}
	srv := auth.BuildServer(clientStore, tokenStore, revocStore, keyStore, nil, "http://localhost:8080", rdb)
	handler := NewOAuth2Handler(srv, sessionStore, revocStore, keyStore, orgStore)
	return handler, mock, mr
}

func setupOAuth2MockedHandler(t *testing.T) (*OAuth2Handler, sqlmock.Sqlmock, *miniredis.Miniredis) {
	// 1. Mock Database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}

	// 2. Mock Redis for custom stores
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub redis connection", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	// Setup custom stores
	sessionStore := redisStore.NewSessionStore(rdb)
	revocStore := redisStore.NewRevocationStore(rdb)

	clientStore := postgres.NewClientStore(db)

	// Setup go-oauth2 stores
	tokenStore := oredis.NewRedisStore(rdb.Options(), "token:")

	// 3. Mock Crypto KeyStore
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key")
	}
	keyStore := &crypto.KeyStore{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}

	// 4. Build Server
	srv := auth.BuildServer(clientStore, tokenStore, revocStore, keyStore, nil, "http://localhost:8080", rdb)

	// 5. Build Handler
	handler := NewOAuth2Handler(srv, sessionStore, revocStore, keyStore, nil)

	return handler, mock, mr
}

func TestAuthorize_NotLoggedIn(t *testing.T) {
	handler, _, mr := setupOAuth2MockedHandler(t)
	defer mr.Close()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/auth?client_id=123&response_type=code", nil)
	rr := httptest.NewRecorder()

	handler.Authorize(rr, req, nil)

	if status := rr.Code; status != http.StatusFound {
		t.Errorf("expected redirect (302) when not logged in, got %d", status)
	}

	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Errorf("expected redirect to /login, got %s", loc)
	}
}

func TestAuthorize_LoggedIn_Consent(t *testing.T) {
	handler, mock, mr := setupOAuth2MockedHandler(t)
	defer mr.Close()

	userID := uuid.New()
	sessionID, _ := handler.sessionStore.Create(context.Background(), userID)

	// HandleAuthorizeRequest might not query the client store immediately before
	// dropping into the userAuthorizeHandler. No sqlmock query expectation needed here.

	// code_challenge is required (ForcePKCE=true). Min length 43. Method defaults to plain.
	// The consent handler returns "" to halt processing before GetAuthorizeToken, so the
	// verifier is never checked — any valid-length challenge works here.
	req := httptest.NewRequest(http.MethodGet, "/oauth2/auth?client_id=test-client&response_type=code&redirect_uri=http://localhost/callback&code_challenge=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=plain", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})
	rr := httptest.NewRecorder()

	handler.Authorize(rr, req, nil)

	// it should execute userAuthorizeHandler which returns NO error and empty userID to halt go-oauth2 processing
	// and render the consent form internally. Thus, we expect HTTP 200 OK
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("expected 200 OK for consent screen rendering, got %d", status)
	}

	// Ensure expectations met
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestRevoke_InvalidToken(t *testing.T) {
	handler, _, mr := setupOAuth2MockedHandler(t)
	defer mr.Close()

	formData := url.Values{}
	formData.Set("token", "invalid-token")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Revoke(rr, req, nil)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("expected 200 OK even for invalid tokens per RFC 7009, got %d", status)
	}
}

func TestToken_InvalidRequest(t *testing.T) {
	handler, _, mr := setupOAuth2MockedHandler(t)
	defer mr.Close()

	formData := url.Values{}
	formData.Set("grant_type", "invalid_grant")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Token(rr, req, nil)

	if status := rr.Code; status != http.StatusBadRequest && status != http.StatusUnauthorized && status != http.StatusInternalServerError {
		// go-oauth2 typically returns 400 Bad Request or 401 Unauthorized for invalid grant types
		t.Errorf("expected error status for invalid token request, got %d", status)
	}
}

// TestAuthorize_OrgClient_NonMember_RendersAccessDenied verifies that the
// "return ”, nil" contract in userAuthorizeHandler is upheld: when a user is
// not a member of the org that owns the client, we render OAuthAccessDeniedPage
// and return ("", nil) so go-oauth2 does NOT overwrite the response.
func TestAuthorize_OrgClient_NonMember_RendersAccessDenied(t *testing.T) {
	orgID := uuid.New()
	orgStore := &mockOrgStore{
		membership: "",
		memberErr:  errors.New("not a member"),
		org:        &models.Org{DisplayName: "Acme Corp"},
	}

	handler, mock, mr := setupOAuth2HandlerWithOrgStore(t, orgStore)
	defer mr.Close()

	userID := uuid.New()
	sessionID, _ := handler.sessionStore.Create(context.Background(), userID)

	// Mock: GetByID returns an org-scoped client
	mock.ExpectQuery(`SELECT secret, domain, public, org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs("org-client-123").
		WillReturnRows(sqlmock.NewRows([]string{"secret", "domain", "public", "org_id"}).
			AddRow("hashed_secret", "https://app.example.com", false, orgID))

	req := httptest.NewRequest(http.MethodGet,
		"/authorize?client_id=org-client-123&response_type=code&redirect_uri=https://app.example.com/callback&code_challenge=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=plain",
		nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})
	rr := httptest.NewRecorder()

	handler.Authorize(rr, req, nil)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (org-denial page), got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Access denied") {
		t.Error("expected 'Access denied' heading in response body")
	}
	if rr.Header().Get("Location") != "" {
		t.Errorf("expected no redirect, but got Location: %s", rr.Header().Get("Location"))
	}
}
