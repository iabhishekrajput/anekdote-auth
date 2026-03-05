package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func setupTestDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock db: %v", err)
	}
	return db, mock
}

func TestClientStore_GetByID_Success(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	store := NewClientStore(db)

	mock.ExpectQuery(`SELECT secret, domain, public FROM oauth2_clients WHERE id = \$1`).
		WithArgs("client-123").
		WillReturnRows(sqlmock.NewRows([]string{"secret", "domain", "public"}).AddRow("secret-abc", "http://localhost", true))

	client, err := store.GetByID(context.Background(), "client-123")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if client.GetID() != "client-123" {
		t.Errorf("expected client-123, got %s", client.GetID())
	}
	if client.GetSecret() != "secret-abc" {
		t.Errorf("expected secret-abc, got %s", client.GetSecret())
	}
	if client.GetDomain() != "http://localhost" {
		t.Errorf("expected http://localhost, got %s", client.GetDomain())
	}
	if client.IsPublic() == false {
		t.Errorf("expected true, got %t", client.IsPublic())
	}
}

func TestClientStore_GetByID_NotFound(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	store := NewClientStore(db)

	mock.ExpectQuery(`SELECT secret, domain, public FROM oauth2_clients WHERE id = \$1`).
		WithArgs("client-missing").
		WillReturnError(sql.ErrNoRows)

	client, err := store.GetByID(context.Background(), "client-missing")
	if err != nil {
		t.Errorf("expected nil error for not found client (oauth2 specific), got %v", err)
	}
	if client != nil {
		t.Errorf("expected nil client")
	}
}

func TestUserStore_GetByEmail(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	store := NewUserStore(db)

	userID := uuid.New()
	mock.ExpectQuery(`SELECT (.+) FROM users WHERE email = \$1`).
		WithArgs("test@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "created_at", "updated_at"}).
			AddRow(userID, "test@example.com", "Test Name", "hash", true, time.Now(), time.Now()))

	user, err := store.GetByEmail("test@example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user.Email != "test@example.com" {
		t.Errorf("expected test@example.com, got %s", user.Email)
	}
}

func TestUserStore_Create(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	store := NewUserStore(db)
	newID := uuid.New()

	mock.ExpectQuery(`INSERT INTO users`).
		WithArgs("new@example.com", "New User", "hashedpass").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "created_at", "updated_at"}).
			AddRow(newID, "new@example.com", "New User", "hashedpass", false, time.Now(), time.Now()))

	user, err := store.Create("new@example.com", "New User", "hashedpass")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user.ID != newID {
		t.Errorf("expected UUID %s, got %s", newID, user.ID)
	}
}

func TestUserStore_Updates(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	store := NewUserStore(db)
	userID := uuid.New()

	// UpdateName
	mock.ExpectExec(`UPDATE users SET name = \$1(.+)`).
		WithArgs("Brand New", userID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := store.UpdateName(userID, "Brand New")
	if err != nil {
		t.Errorf("UpdateName failed: %v", err)
	}

	// UpdatePassword
	mock.ExpectExec(`UPDATE users SET password_hash = \$1(.+)`).
		WithArgs("newhash", userID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = store.UpdatePassword(userID, "newhash")
	if err != nil {
		t.Errorf("UpdatePassword failed: %v", err)
	}

	// UpdateVerified
	mock.ExpectExec(`UPDATE users SET is_verified = TRUE(.+)`).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = store.UpdateVerified(userID)
	if err != nil {
		t.Errorf("UpdateVerified failed: %v", err)
	}
}
