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
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/config"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	redisStore "github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
	"golang.org/x/crypto/bcrypt"
)

// setupMockedHandler returns an IdentityHandler with mocked postgres and redis stores,
// along with the mocks to allow assertions.
func setupMockedHandler(t *testing.T) (*IdentityHandler, sqlmock.Sqlmock, *miniredis.Miniredis) {
	// 1. Mock Database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	userStore := postgres.NewUserStore(db)

	// 2. Mock Redis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub redis connection", err)
	}
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	sessionStore := redisStore.NewSessionStore(rdb)

	// 3. Mock Config
	cfg := &config.Config{
		AppURL: "http://localhost:8080",
	}

	// 4. Create Handler (Mailer is nil to bypass sending)
	handler := NewIdentityHandler(cfg, userStore, sessionStore, nil)

	return handler, mock, mr
}

func TestRegisterFunc_Success(t *testing.T) {
	handler, mock, mr := setupMockedHandler(t)
	defer mr.Close()

	formData := url.Values{}
	formData.Set("email", "test@example.com")
	formData.Set("password", "StrongPassw0rd!")
	formData.Set("name", "Test User")

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	newID := uuid.New()
	rows := sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "created_at", "updated_at"}).
		AddRow(newID, "test@example.com", "Test User", "hashed_password_stub", false, time.Now(), time.Now())

	mock.ExpectQuery(`INSERT INTO users`).
		WithArgs("test@example.com", "Test User", sqlmock.AnyArg()).
		WillReturnRows(rows)

	handler.RegisterFunc(rr, req, nil)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}

	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
	}
}

func TestRegisterFunc_MissingFields(t *testing.T) {
	handler, _, mr := setupMockedHandler(t)
	defer mr.Close()

	formData := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.RegisterFunc(rr, req, nil)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}
}

func TestRegisterFunc_InvalidPassword(t *testing.T) {
	handler, _, mr := setupMockedHandler(t)
	defer mr.Close()

	formData := url.Values{}
	formData.Set("email", "test@example.com")
	formData.Set("password", "short")
	formData.Set("name", "Test User")

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.RegisterFunc(rr, req, nil)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}
}

func TestLoginFunc_Success(t *testing.T) {
	handler, mock, mr := setupMockedHandler(t)
	defer mr.Close()

	formData := url.Values{}
	formData.Set("email", "login@example.com")
	formData.Set("password", "ValidPass123!")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	hash, _ := bcrypt.GenerateFromPassword([]byte("ValidPass123!"), bcrypt.DefaultCost)

	userID := uuid.New()
	rows := sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "created_at", "updated_at"}).
		AddRow(userID, "login@example.com", "Test User", string(hash), true, time.Now(), time.Now())

	mock.ExpectQuery(`SELECT (.+) FROM users WHERE email = \$1`).
		WithArgs("login@example.com").
		WillReturnRows(rows)

	handler.LoginFunc(rr, req, nil)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}

	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
	}

	// Verify session was created
	cookies := rr.Result().Cookies()
	var authCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "auth_session" {
			authCookie = cookie
			break
		}
	}
	if authCookie == nil {
		t.Error("expected auth_session cookie to be set")
	}
}

func TestVerifyEmailFunc_Success(t *testing.T) {
	handler, mock, mr := setupMockedHandler(t)
	defer mr.Close()

	userID := uuid.New()

	// Pre-populate OTP in Redis
	handler.sessionStore.CreateOTP(context.Background(), userID, "123456")

	formData := url.Values{}
	formData.Set("user_id", userID.String())
	formData.Set("otp", "123456")

	req := httptest.NewRequest(http.MethodPost, "/verify-email", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	// Use regex matching for the query string since there are updates and arguments
	mock.ExpectExec(`UPDATE users SET is_verified = TRUE(.+)WHERE id = \$1`).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	handler.VerifyEmailFunc(rr, req, nil)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}

	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
	}
}

func TestLogoutFunc_Success(t *testing.T) {
	handler, _, mr := setupMockedHandler(t)
	defer mr.Close()

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	// Add mock session cookie
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: "fake-session-id"})
	rr := httptest.NewRecorder()

	handler.LogoutFunc(rr, req, nil)

	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
	}

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Value != "" {
		t.Errorf("expected auth_session cookie to be cleared")
	}
}

func TestForgotPasswordFunc_Success(t *testing.T) {
	handler, mock, mr := setupMockedHandler(t)
	defer mr.Close()

	userID := uuid.New()
	rows := sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "created_at", "updated_at"}).
		AddRow(userID, "forgot@example.com", "Test User", "hash", true, time.Now(), time.Now())

	mock.ExpectQuery(`SELECT (.+) FROM users WHERE email = \$1`).
		WithArgs("forgot@example.com").
		WillReturnRows(rows)

	formData := url.Values{}
	formData.Set("email", "forgot@example.com")
	req := httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ForgotPasswordFunc(rr, req, nil)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestResetPasswordFunc_Success(t *testing.T) {
	handler, mock, mr := setupMockedHandler(t)
	defer mr.Close()

	userID := uuid.New()
	token := "mock-reset-token"

	// Manually inject reset token into miniredis
	mr.Set("reset_token:"+token, userID.String())

	formData := url.Values{}
	formData.Set("token", token)
	formData.Set("password", "NewStrongP@ss1")

	req := httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mock.ExpectExec(`UPDATE users SET password_hash = \$1(.+)WHERE id = \$2`).
		WithArgs(sqlmock.AnyArg(), userID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	handler.ResetPasswordFunc(rr, req, nil)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}
