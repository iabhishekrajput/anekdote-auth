package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	redisStore "github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
)

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
	srv := auth.BuildServer(clientStore, tokenStore, revocStore, keyStore, "http://localhost:8080")

	// 5. Build Handler
	handler := NewOAuth2Handler(srv, sessionStore, revocStore, keyStore)

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

	req := httptest.NewRequest(http.MethodGet, "/oauth2/auth?client_id=test-client&response_type=code&redirect_uri=http://localhost/callback", nil)
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
