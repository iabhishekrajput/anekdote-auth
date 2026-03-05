package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	oredis "github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
	"github.com/julienschmidt/httprouter"
)

func setupMiddlewareTestenv(t *testing.T) (*oredis.SessionStore, *miniredis.Miniredis) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := oredis.NewSessionStore(client)

	return store, mr
}

func mockHandler() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}
}

func TestRequireAuth_NoSession(t *testing.T) {
	store, mr := setupMiddlewareTestenv(t)
	defer mr.Close()

	handler := RequireAuth(store, mockHandler())

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()

	handler(rr, req, nil)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302 Found, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/login?req=/protected" {
		t.Errorf("unexpected redirect location: %s", rr.Header().Get("Location"))
	}
}

func TestRequireAuth_ValidSession(t *testing.T) {
	store, mr := setupMiddlewareTestenv(t)
	defer mr.Close()

	userID := uuid.New()
	sessionID, _ := store.Create(context.Background(), userID)

	handler := RequireAuth(store, mockHandler())

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})
	rr := httptest.NewRecorder()

	handler(rr, req, nil)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr.Code)
	}
}

func TestRedirectIfAuthenticated_LoggedIn(t *testing.T) {
	store, mr := setupMiddlewareTestenv(t)
	defer mr.Close()

	userID := uuid.New()
	sessionID, _ := store.Create(context.Background(), userID)

	handler := RedirectIfAuthenticated(store, mockHandler())

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})
	rr := httptest.NewRecorder()

	handler(rr, req, nil)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302 Found, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/account" {
		t.Errorf("unexpected redirect location: %s", rr.Header().Get("Location"))
	}
}

func TestRedirectIfAuthenticated_NotLoggedIn(t *testing.T) {
	store, mr := setupMiddlewareTestenv(t)
	defer mr.Close()

	handler := RedirectIfAuthenticated(store, mockHandler())

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()

	handler(rr, req, nil)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr.Code)
	}
}
