package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
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

	hash, _ := bcrypt.GenerateFromPassword([]byte("secret-abc"), bcrypt.MinCost)

	mock.ExpectQuery(`SELECT secret, domain, public, org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs("client-123").
		WillReturnRows(sqlmock.NewRows([]string{"secret", "domain", "public", "org_id"}).AddRow(string(hash), "http://localhost", true, nil))

	client, err := store.GetByID(context.Background(), "client-123")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if client.GetID() != "client-123" {
		t.Errorf("expected client-123, got %s", client.GetID())
	}
	// Secrets are stored as bcrypt hashes; GetSecret() always returns "".
	// Verify via the ClientPasswordVerifier interface instead.
	cpv, ok := client.(oauth2.ClientPasswordVerifier)
	if !ok {
		t.Fatal("expected client to implement ClientPasswordVerifier")
	}
	if !cpv.VerifyPassword("secret-abc") {
		t.Error("expected VerifyPassword to succeed for correct secret")
	}
	if cpv.VerifyPassword("wrong-secret") {
		t.Error("expected VerifyPassword to fail for wrong secret")
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

	mock.ExpectQuery(`SELECT secret, domain, public, org_id FROM oauth2_clients WHERE id = \$1`).
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
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "is_admin", "disabled_at", "created_at", "updated_at"}).
			AddRow(userID, "test@example.com", "Test Name", "hash", true, false, nil, time.Now(), time.Now()))

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

func TestUserStore_SetDisabled(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	store := NewUserStore(db)
	userID := uuid.New()

	// Disable: SQL uses NOW() directly, only id is a parameter.
	mock.ExpectExec(`UPDATE users SET disabled_at = NOW\(\)(.+)WHERE id = \$1`).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.SetDisabled(context.Background(), userID, true); err != nil {
		t.Errorf("SetDisabled(true) failed: %v", err)
	}

	// Enable: disabled_at is set to NULL, only id is a parameter.
	mock.ExpectExec(`UPDATE users SET disabled_at = NULL(.+)WHERE id = \$1`).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.SetDisabled(context.Background(), userID, false); err != nil {
		t.Errorf("SetDisabled(false) failed: %v", err)
	}
}

// --- ClientStore new methods ---

func TestClientStore_ListOrgClients_Empty(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	orgID := uuid.New()
	store := NewClientStore(db)

	mock.ExpectQuery(`SELECT id, name, domain, public, created_at FROM oauth2_clients WHERE org_id = \$1`).
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "domain", "public", "created_at"}))

	clients, err := store.ListOrgClients(context.Background(), orgID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(clients) != 0 {
		t.Errorf("expected 0 clients, got %d", len(clients))
	}
}

func TestClientStore_ListOrgClients_WithRows(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	orgID := uuid.New()
	store := NewClientStore(db)
	now := time.Now()

	mock.ExpectQuery(`SELECT id, name, domain, public, created_at FROM oauth2_clients WHERE org_id = \$1`).
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "domain", "public", "created_at"}).
			AddRow("client-1", "My App", "https://example.com/cb", false, now).
			AddRow("client-2", "SPA", "https://spa.example.com/cb", true, now))

	clients, err := store.ListOrgClients(context.Background(), orgID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(clients))
	}
	if clients[0].ID != "client-1" || clients[0].Name != "My App" {
		t.Errorf("unexpected first client: %+v", clients[0])
	}
	if clients[1].Public != true {
		t.Error("expected second client to be public")
	}
}

func TestClientStore_CreateOrgClient_Confidential(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	orgID := uuid.New()
	store := NewClientStore(db)

	mock.ExpectExec(`INSERT INTO oauth2_clients`).
		WithArgs(sqlmock.AnyArg(), "My App", sqlmock.AnyArg(), "https://example.com/cb", false, orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	clientID, plainSecret, err := store.CreateOrgClient(context.Background(), orgID, "My App", "https://example.com/cb", false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if clientID == "" {
		t.Error("expected non-empty clientID")
	}
	if !strings.HasPrefix(plainSecret, "key_") {
		t.Errorf("expected secret to start with 'key_', got %q", plainSecret)
	}
}

func TestClientStore_CreateOrgClient_Public(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	orgID := uuid.New()
	store := NewClientStore(db)

	mock.ExpectExec(`INSERT INTO oauth2_clients`).
		WithArgs(sqlmock.AnyArg(), "SPA", "", "https://spa.example.com/cb", true, orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	clientID, plainSecret, err := store.CreateOrgClient(context.Background(), orgID, "SPA", "https://spa.example.com/cb", true)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if clientID == "" {
		t.Error("expected non-empty clientID")
	}
	if plainSecret != "" {
		t.Errorf("expected empty secret for public client, got %q", plainSecret)
	}
}

func TestClientStore_DeleteOrgClient_Success(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	orgID := uuid.New()
	store := NewClientStore(db)

	mock.ExpectExec(`DELETE FROM oauth2_clients WHERE id = \$1 AND org_id = \$2`).
		WithArgs("client-123", orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.DeleteOrgClient(context.Background(), "client-123", orgID); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClientStore_DeleteOrgClient_CrossOrg(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	orgID := uuid.New()
	store := NewClientStore(db)

	mock.ExpectExec(`DELETE FROM oauth2_clients WHERE id = \$1 AND org_id = \$2`).
		WithArgs("client-123", orgID).
		WillReturnResult(sqlmock.NewResult(0, 0)) // 0 rows → cross-org attempt

	err := store.DeleteOrgClient(context.Background(), "client-123", orgID)
	if !errors.Is(err, ErrClientNotFound) {
		t.Errorf("expected ErrClientNotFound, got %v", err)
	}
}

func TestClientStore_RotateOrgClientSecret_Success(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	orgID := uuid.New()
	store := NewClientStore(db)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT public FROM oauth2_clients WHERE id = \$1 AND org_id = \$2 FOR UPDATE`).
		WithArgs("client-123", orgID).
		WillReturnRows(sqlmock.NewRows([]string{"public"}).AddRow(false))
	mock.ExpectExec(`UPDATE oauth2_clients SET secret = \$1 WHERE id = \$2 AND org_id = \$3`).
		WithArgs(sqlmock.AnyArg(), "client-123", orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	newSecret, err := store.RotateOrgClientSecret(context.Background(), "client-123", orgID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(newSecret, "key_") {
		t.Errorf("expected secret to start with 'key_', got %q", newSecret)
	}
}

func TestClientStore_RotateOrgClientSecret_ClientNotFound(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	orgID := uuid.New()
	store := NewClientStore(db)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT public FROM oauth2_clients WHERE id = \$1 AND org_id = \$2 FOR UPDATE`).
		WithArgs("client-missing", orgID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, err := store.RotateOrgClientSecret(context.Background(), "client-missing", orgID)
	if !errors.Is(err, ErrClientNotFound) {
		t.Errorf("expected ErrClientNotFound, got %v", err)
	}
}

func TestClientStore_RotateOrgClientSecret_PublicClient(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	orgID := uuid.New()
	store := NewClientStore(db)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT public FROM oauth2_clients WHERE id = \$1 AND org_id = \$2 FOR UPDATE`).
		WithArgs("client-pub", orgID).
		WillReturnRows(sqlmock.NewRows([]string{"public"}).AddRow(true))
	mock.ExpectRollback()

	_, err := store.RotateOrgClientSecret(context.Background(), "client-pub", orgID)
	if err == nil {
		t.Error("expected error for public client rotation")
	}
}
