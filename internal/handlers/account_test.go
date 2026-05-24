package handlers

import (
	"context"
	"errors"
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

var errSimulated = errors.New("simulated db error")

func setupAccountMockedHandler(t *testing.T) (*AccountHandler, sqlmock.Sqlmock, sqlmock.Sqlmock) {
	userDB, userMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub user database connection", err)
	}
	orgDB, orgMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub org database connection", err)
	}

	userStore := postgres.NewUserStore(userDB)
	orgStore := postgres.NewOrgStore(orgDB)
	handler := NewAccountHandler(userStore, orgStore, nil, nil, nil)

	return handler, userMock, orgMock
}

// helper to wrap requests with user context
func withUserContext(req *http.Request, userID uuid.UUID) *http.Request {
	ctx := context.WithValue(req.Context(), types.UserContextKey, userID)
	return req.WithContext(ctx)
}

func TestViewAccount_Success(t *testing.T) {
	handler, userMock, orgMock := setupAccountMockedHandler(t)

	userID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	userRows := sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "is_admin", "admin_role", "password_changed", "disabled_at", "deleted_at", "created_at", "updated_at"}).
		AddRow(userID, "test@example.com", "Test User", "hash", true, false, nil, true, nil, nil, time.Now(), time.Now())

	userMock.ExpectQuery(`SELECT (.+) FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(userRows)

	orgRows := sqlmock.NewRows([]string{"id", "slug", "display_name", "owner_id", "created_at", "updated_at", "role", "member_count"})
	orgMock.ExpectQuery(`SELECT (.+) FROM org_memberships`).
		WithArgs(userID).
		WillReturnRows(orgRows)

	handler.ViewAccount(rr, req, nil)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", status)
	}

	if err := userMock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled user expectations: %s", err)
	}
	if err := orgMock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled org expectations: %s", err)
	}
}

func TestViewAccount_OrgStoreFails(t *testing.T) {
	handler, userMock, orgMock := setupAccountMockedHandler(t)

	userID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	userRows := sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "is_admin", "admin_role", "password_changed", "disabled_at", "deleted_at", "created_at", "updated_at"}).
		AddRow(userID, "test@example.com", "Test User", "hash", true, false, nil, true, nil, nil, time.Now(), time.Now())

	userMock.ExpectQuery(`SELECT (.+) FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(userRows)

	orgMock.ExpectQuery(`SELECT (.+) FROM org_memberships`).
		WithArgs(userID).
		WillReturnError(errSimulated)

	handler.ViewAccount(rr, req, nil)

	// Org failure must not redirect — page should still render
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("expected 200 OK despite org error, got %d", status)
	}
}

func TestUpdateProfile_Success(t *testing.T) {
	handler, mock, _ := setupAccountMockedHandler(t)

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
	handler, mock, _ := setupAccountMockedHandler(t)

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

	rows := sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "is_admin", "admin_role", "password_changed", "disabled_at", "deleted_at", "created_at", "updated_at"}).
		AddRow(userID, "test@example.com", "Test User", string(hash), true, false, nil, true, nil, nil, time.Now(), time.Now())

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
