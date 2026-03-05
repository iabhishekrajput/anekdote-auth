package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/types"
	"golang.org/x/crypto/bcrypt"
)

func setupAccountMockedHandler(t *testing.T) (*AccountHandler, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}

	userStore := postgres.NewUserStore(db)
	handler := NewAccountHandler(userStore)

	return handler, mock
}

// helper to wrap requests with user context
func withUserContext(req *http.Request, userID uuid.UUID) *http.Request {
	ctx := context.WithValue(req.Context(), types.UserContextKey, userID)
	return req.WithContext(ctx)
}

func TestViewAccount_Success(t *testing.T) {
	handler, mock := setupAccountMockedHandler(t)

	userID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	rows := sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "created_at", "updated_at"}).
		AddRow(userID, "test@example.com", "Test User", "hash", true, time.Now(), time.Now())

	mock.ExpectQuery(`SELECT (.+) FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(rows)

	handler.ViewAccount(rr, req, nil)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", status)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUpdateProfile_Success(t *testing.T) {
	handler, mock := setupAccountMockedHandler(t)

	userID := uuid.New()
	formData := url.Values{}
	formData.Set("name", "New Name")

	req := httptest.NewRequest(http.MethodPost, "/account/profile", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	mock.ExpectExec(`UPDATE users SET name = \$1(.+)WHERE id = \$2`).
		WithArgs("New Name", userID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	handler.UpdateProfile(rr, req, nil)

	if status := rr.Code; status != http.StatusFound {
		t.Errorf("expected 302 Redirect, got %d", status)
	}

	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "message=Profile+updated") {
		t.Errorf("expected success message in redirect, got %s", loc)
	}
}

func TestUpdatePassword_Success(t *testing.T) {
	handler, mock := setupAccountMockedHandler(t)

	userID := uuid.New()
	formData := url.Values{}

	oldPass := "ValidOldPass123!"
	newPass := "ValidNewPass123!"

	hash, _ := bcrypt.GenerateFromPassword([]byte(oldPass), bcrypt.DefaultCost)

	formData.Set("old_password", oldPass)
	formData.Set("new_password", newPass)

	req := httptest.NewRequest(http.MethodPost, "/account/password", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	rows := sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "created_at", "updated_at"}).
		AddRow(userID, "test@example.com", "Test User", string(hash), true, time.Now(), time.Now())

	mock.ExpectQuery(`SELECT (.+) FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(rows)

	mock.ExpectExec(`UPDATE users SET password_hash = \$1(.+)WHERE id = \$2`).
		WithArgs(sqlmock.AnyArg(), userID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	handler.UpdatePassword(rr, req, nil)

	if status := rr.Code; status != http.StatusFound {
		t.Errorf("expected 302 Redirect, got %d", status)
	}

	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "message=Password+updated") {
		t.Errorf("expected success message in redirect, got %s", loc)
	}
}
