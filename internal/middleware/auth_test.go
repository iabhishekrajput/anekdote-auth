package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	pgstore "github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
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

func TestRequireAdmin_NoSession(t *testing.T) {
	store, mr := setupMiddlewareTestenv(t)
	defer mr.Close()

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	userStore := pgstore.NewUserStore(db)

	handler := RequireAdmin(store, userStore, mockHandler())

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rr := httptest.NewRecorder()

	handler(rr, req, nil)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/login?req=/admin" {
		t.Errorf("unexpected redirect: %s", loc)
	}
}

func TestRequireAdmin_NonAdminEmail(t *testing.T) {
	store, mr := setupMiddlewareTestenv(t)
	defer mr.Close()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	userStore := pgstore.NewUserStore(db)

	userID := uuid.New()
	sessionID, _ := store.Create(context.Background(), userID)

	rows := sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "is_admin", "admin_role", "password_changed", "disabled_at", "deleted_at", "created_at", "updated_at"}).
		AddRow(userID, "regular@example.com", "Regular User", "hash", true, false, nil, true, nil, nil, time.Now(), time.Now())
	mock.ExpectQuery(`SELECT (.+) FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(rows)

	handler := RequireAdmin(store, userStore, mockHandler())

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})
	rr := httptest.NewRecorder()

	handler(rr, req, nil)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", rr.Code)
	}
}

func TestRequireAdmin_ValidAdmin(t *testing.T) {
	store, mr := setupMiddlewareTestenv(t)
	defer mr.Close()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	userStore := pgstore.NewUserStore(db)

	userID := uuid.New()
	sessionID, _ := store.Create(context.Background(), userID)

	rows := sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "is_admin", "admin_role", "password_changed", "disabled_at", "deleted_at", "created_at", "updated_at"}).
		AddRow(userID, "admin@example.com", "Admin User", "hash", true, true, "superadmin", true, nil, nil, time.Now(), time.Now())
	mock.ExpectQuery(`SELECT (.+) FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(rows)

	handler := RequireAdmin(store, userStore, mockHandler())

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})
	rr := httptest.NewRecorder()

	handler(rr, req, nil)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for valid admin, got %d", rr.Code)
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
