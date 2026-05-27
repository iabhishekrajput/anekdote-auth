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

	mock.ExpectQuery(`SELECT name, secret, domain, public, org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs("client-123").
		WillReturnRows(sqlmock.NewRows([]string{"name", "secret", "domain", "public", "org_id"}).AddRow("Test Client", string(hash), "http://localhost", true, nil))

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

	mock.ExpectQuery(`SELECT name, secret, domain, public, org_id FROM oauth2_clients WHERE id = \$1`).
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
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "username", "password_hash", "is_verified", "is_admin", "admin_role", "password_changed", "disabled_at", "deleted_at", "created_at", "updated_at"}).
			AddRow(userID, "test@example.com", "Test Name", nil, "hash", true, false, nil, true, nil, nil, time.Now(), time.Now()))

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
	newID := "usr_01jpqrst_test_new_user_id_"

	mock.ExpectQuery(`INSERT INTO users`).
		WithArgs(sqlmock.AnyArg(), "new@example.com", "New User", sqlmock.AnyArg(), "hashedpass").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "username", "password_hash", "is_verified", "created_at", "updated_at"}).
			AddRow(newID, "new@example.com", "New User", nil, "hashedpass", false, time.Now(), time.Now()))

	user, err := store.Create("new@example.com", "New User", "", "hashedpass")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user.ID == "" {
		t.Errorf("expected non-empty user ID, got %s", newID)
	}
}

func TestUserStore_Updates(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	store := NewUserStore(db)
	userID := "usr_test_update_id"

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
	userID := "usr_test_disable_id"

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

	mock.ExpectQuery(`SELECT (.+) FROM oauth2_clients`).
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "domain", "public", "created_at", "is_global", "is_owner"}))

	clients, err := store.ListOrgClients(context.Background(), orgID.String())
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

	mock.ExpectQuery(`SELECT (.+) FROM oauth2_clients`).
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "domain", "public", "created_at", "is_global", "is_owner"}).
			AddRow("client-1", "My App", "https://example.com/cb", false, now, false, true).
			AddRow("client-2", "SPA", "https://spa.example.com/cb", true, now, false, true))

	clients, err := store.ListOrgClients(context.Background(), orgID.String())
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

	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO oauth2_clients`).
		WithArgs(sqlmock.AnyArg(), "My App", sqlmock.AnyArg(), "https://example.com/cb", false, sqlmock.AnyArg(), orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`INSERT INTO client_org_grants`).
		WithArgs(sqlmock.AnyArg(), orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	clientID, plainSecret, err := store.CreateOrgClient(context.Background(), orgID.String(), "My App", "https://example.com/cb", false, false)
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

	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO oauth2_clients`).
		WithArgs(sqlmock.AnyArg(), "SPA", "", "https://spa.example.com/cb", true, sqlmock.AnyArg(), orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`INSERT INTO client_org_grants`).
		WithArgs(sqlmock.AnyArg(), orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	clientID, plainSecret, err := store.CreateOrgClient(context.Background(), orgID.String(), "SPA", "https://spa.example.com/cb", true, false)
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

	if err := store.DeleteOrgClient(context.Background(), "client-123", orgID.String()); err != nil {
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
		WillReturnResult(sqlmock.NewResult(0, 0)) // 0 rows → not a direct-org client
	// IsGlobalClient check: client exists but is single-org (org_id IS NOT NULL)
	mock.ExpectQuery(`SELECT \(org_id IS NULL\) FROM oauth2_clients WHERE id = \$1`).
		WithArgs("client-123").
		WillReturnRows(sqlmock.NewRows([]string{"is_global"}).AddRow(false))

	err := store.DeleteOrgClient(context.Background(), "client-123", orgID.String())
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
	mock.ExpectQuery(`SELECT public FROM oauth2_clients`).
		WithArgs("client-123", orgID).
		WillReturnRows(sqlmock.NewRows([]string{"public"}).AddRow(false))
	mock.ExpectExec(`UPDATE oauth2_clients SET secret`).
		WithArgs(sqlmock.AnyArg(), "client-123", orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	newSecret, err := store.RotateOrgClientSecret(context.Background(), "client-123", orgID.String())
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
	mock.ExpectQuery(`SELECT public FROM oauth2_clients`).
		WithArgs("client-missing", orgID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, err := store.RotateOrgClientSecret(context.Background(), "client-missing", orgID.String())
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

	_, err := store.RotateOrgClientSecret(context.Background(), "client-pub", orgID.String())
	if err == nil {
		t.Error("expected error for public client rotation")
	}
}

// --- Grant request store methods ---

func TestClientStore_CreateGrantRequest_Success(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	store := NewClientStore(db)
	clientID := uuid.New().String()
	requesterOrgID := uuid.New()
	ownerOrgID := uuid.New()
	requestedBy := uuid.New()
	requestID := uuid.New()
	now := time.Now()

	mock.ExpectQuery(`INSERT INTO client_access_requests`).
		WithArgs(clientID, requesterOrgID, ownerOrgID, requestedBy).
		WillReturnRows(sqlmock.NewRows([]string{"id", "client_id", "requester_org_id", "owner_org_id", "requested_by", "status", "requested_at"}).
			AddRow(requestID, clientID, requesterOrgID, ownerOrgID, requestedBy, "pending", now))

	gr, err := store.CreateGrantRequest(context.Background(), clientID, requesterOrgID.String(), ownerOrgID.String(), requestedBy.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gr == nil {
		t.Fatal("expected non-nil GrantRequest")
	}
	if gr.ClientID != clientID {
		t.Errorf("expected clientID %s, got %s", clientID, gr.ClientID)
	}
	if gr.Status != "pending" {
		t.Errorf("expected status 'pending', got %s", gr.Status)
	}
}

func TestClientStore_CreateGrantRequest_Duplicate(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	store := NewClientStore(db)
	clientID := uuid.New().String()
	requesterOrgID := uuid.New()
	ownerOrgID := uuid.New()
	requestedBy := uuid.New()

	// ON CONFLICT DO NOTHING means RETURNING returns no rows → sql.ErrNoRows
	mock.ExpectQuery(`INSERT INTO client_access_requests`).
		WithArgs(clientID, requesterOrgID, ownerOrgID, requestedBy).
		WillReturnRows(sqlmock.NewRows([]string{"id", "client_id", "requester_org_id", "owner_org_id", "requested_by", "status", "requested_at"}))

	gr, err := store.CreateGrantRequest(context.Background(), clientID, requesterOrgID.String(), ownerOrgID.String(), requestedBy.String())
	if err != nil {
		t.Fatalf("expected nil error for duplicate, got %v", err)
	}
	if gr != nil {
		t.Error("expected nil GrantRequest for duplicate (ON CONFLICT DO NOTHING)")
	}
}

func TestClientStore_ApproveGrantRequest_Success(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	store := NewClientStore(db)
	requestID := uuid.New()
	clientID := uuid.New().String()
	ownerOrgID := uuid.New()
	resolvedBy := uuid.New()
	requesterOrgID := uuid.New()
	now := time.Now()
	requestedBy := uuid.New()

	mock.ExpectBegin()
	mock.ExpectQuery(`UPDATE client_access_requests`).
		WithArgs(requestID, clientID, ownerOrgID, resolvedBy).
		WillReturnRows(sqlmock.NewRows([]string{"id", "client_id", "requester_org_id", "owner_org_id", "requested_by", "status", "requested_at"}).
			AddRow(requestID, clientID, requesterOrgID, ownerOrgID, requestedBy, "approved", now))
	mock.ExpectExec(`INSERT INTO client_org_grants`).
		WithArgs(clientID, requesterOrgID, resolvedBy).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	gr, err := store.ApproveGrantRequest(context.Background(), requestID.String(), clientID, ownerOrgID.String(), resolvedBy.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gr == nil {
		t.Fatal("expected non-nil GrantRequest")
	}
	if gr.Status != "approved" {
		t.Errorf("expected status 'approved', got %s", gr.Status)
	}
}

func TestClientStore_ApproveGrantRequest_NotPending(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	store := NewClientStore(db)
	requestID := uuid.New()
	clientID := uuid.New().String()
	ownerOrgID := uuid.New()
	resolvedBy := uuid.New()

	mock.ExpectBegin()
	// UPDATE matched 0 rows (already resolved) → RETURNING returns no rows → sql.ErrNoRows
	mock.ExpectQuery(`UPDATE client_access_requests`).
		WithArgs(requestID, clientID, ownerOrgID, resolvedBy).
		WillReturnRows(sqlmock.NewRows([]string{"id", "client_id", "requester_org_id", "owner_org_id", "requested_by", "status", "requested_at"}))
	mock.ExpectRollback()

	_, err := store.ApproveGrantRequest(context.Background(), requestID.String(), clientID, ownerOrgID.String(), resolvedBy.String())
	if !errors.Is(err, ErrGrantRequestNotPending) {
		t.Errorf("expected ErrGrantRequestNotPending, got %v", err)
	}
}

func TestClientStore_DenyGrantRequest_Success(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	store := NewClientStore(db)
	requestID := uuid.New()
	clientID := uuid.New().String()
	ownerOrgID := uuid.New()
	resolvedBy := uuid.New()
	requesterOrgID := uuid.New()
	now := time.Now()
	requestedBy := uuid.New()

	mock.ExpectQuery(`UPDATE client_access_requests`).
		WithArgs(requestID, clientID, ownerOrgID, resolvedBy).
		WillReturnRows(sqlmock.NewRows([]string{"id", "client_id", "requester_org_id", "owner_org_id", "requested_by", "status", "requested_at"}).
			AddRow(requestID, clientID, requesterOrgID, ownerOrgID, requestedBy, "denied", now))

	gr, err := store.DenyGrantRequest(context.Background(), requestID.String(), clientID, ownerOrgID.String(), resolvedBy.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gr == nil || gr.Status != "denied" {
		t.Errorf("expected status 'denied', got %v", gr)
	}
}

func TestClientStore_DenyGrantRequest_NotPending(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	store := NewClientStore(db)
	requestID := uuid.New()
	clientID := uuid.New().String()
	ownerOrgID := uuid.New()
	resolvedBy := uuid.New()

	mock.ExpectQuery(`UPDATE client_access_requests`).
		WithArgs(requestID, clientID, ownerOrgID, resolvedBy).
		WillReturnRows(sqlmock.NewRows([]string{"id", "client_id", "requester_org_id", "owner_org_id", "requested_by", "status", "requested_at"}))

	_, err := store.DenyGrantRequest(context.Background(), requestID.String(), clientID, ownerOrgID.String(), resolvedBy.String())
	if !errors.Is(err, ErrGrantRequestNotPending) {
		t.Errorf("expected ErrGrantRequestNotPending, got %v", err)
	}
}

func TestClientStore_ListDiscoverableClients_FirstPage(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	store := NewClientStore(db)
	excludeOrgID := uuid.New()
	ownerOrgID := uuid.New()
	clientID := uuid.New().String()
	now := time.Now()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM oauth2_clients`).
		WithArgs(excludeOrgID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	mock.ExpectQuery(`SELECT c\.id, c\.name`).
		WithArgs(excludeOrgID, 2). // limit=1 → limit+1=2
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "domain", "public", "owner_org_id", "display_name", "slug", "created_at"}).
			AddRow(clientID, "Global App", "https://app.example.com/cb", false, ownerOrgID, "Owner Corp", "owner-corp", now))

	clients, nextCursor, total, err := store.ListDiscoverableClients(context.Background(), excludeOrgID.String(), 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("expected total=1, got %d", total)
	}
	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(clients))
	}
	if clients[0].ID != clientID {
		t.Errorf("expected clientID %s, got %s", clientID, clients[0].ID)
	}
	if nextCursor != "" {
		t.Errorf("expected empty nextCursor for single page, got %s", nextCursor)
	}
}

// ── normalizeDestinations (pure function) ─────────────────────────────────

func TestNormalizeDestinations(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"", "token"},
		{"token", "token"},
		{"access_token", "access_token"},
		{"id_token", "id_token"},
		{"id_token,access_token", "access_token,id_token"},    // sorts alphabetically
		{"access_token,id_token", "access_token,id_token"},    // already sorted
		{"userinfo,id_token,access_token", "access_token,id_token,userinfo"},
		{" access_token , id_token ", "access_token,id_token"}, // trimmed
	}
	for _, c := range cases {
		got := normalizeDestinations(c.input)
		if got != c.want {
			t.Errorf("normalizeDestinations(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// ── scopeMatches (pure function) ──────────────────────────────────────────

func TestScopeMatches(t *testing.T) {
	cases := []struct {
		scopeGate, grantedScope string
		want                    bool
	}{
		{"", "openid profile email", true},      // empty gate always passes
		{"", "", true},                           // empty gate, empty scope
		{"email", "openid email profile", true},  // word boundary match
		{"email", "openid email_extra", false},   // no substring match across word boundary
		{"profile", "openid profile", true},
		{"custom", "openid", false},              // not present
		{"custom", "openid custom profile", true},
	}
	for _, c := range cases {
		got := scopeMatches(c.scopeGate, c.grantedScope)
		if got != c.want {
			t.Errorf("scopeMatches(%q, %q) = %v, want %v", c.scopeGate, c.grantedScope, got, c.want)
		}
	}
}

// ── destMatches (pure function) ───────────────────────────────────────────

func TestDestMatches(t *testing.T) {
	cases := []struct {
		rowDests, destination string
		want                  bool
	}{
		{"token", "access_token", true},   // "token" alias covers access_token
		{"token", "id_token", true},       // "token" alias covers id_token
		{"token", "userinfo", false},      // "token" does NOT cover userinfo
		{"access_token", "access_token", true},
		{"access_token", "id_token", false},
		{"id_token", "id_token", true},
		{"id_token", "access_token", false},
		{"userinfo", "userinfo", true},
		{"userinfo", "access_token", false},
		{"access_token,id_token", "access_token", true},
		{"access_token,id_token", "id_token", true},
		{"access_token,id_token", "userinfo", false},
		{"access_token,id_token,userinfo", "userinfo", true},
	}
	for _, c := range cases {
		got := destMatches(c.rowDests, c.destination)
		if got != c.want {
			t.Errorf("destMatches(%q, %q) = %v, want %v", c.rowDests, c.destination, got, c.want)
		}
	}
}

// ── GetCustomClaims with scope+destination filtering (sqlmock) ───────────

func TestGetCustomClaims_ScopeAndDestFilter(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()
	store := NewClientStore(db)

	rows := sqlmock.NewRows([]string{"key", "value_type", "value", "scope_gate", "destinations"}).
		AddRow("https://example.com/tier", "string", "enterprise", "", "token").           // no gate, "token" → matches any access/id
		AddRow("https://example.com/secret", "string", "hidden", "custom_scope", "token"). // gate not in scope → filtered
		AddRow("https://example.com/count", "number", "42", "", "id_token").               // dest id_token but query is access_token → filtered
		AddRow("https://example.com/flag", "boolean", "true", "", "access_token")          // matches access_token

	mock.ExpectQuery(`SELECT key, value_type, value`).
		WithArgs("client-1").
		WillReturnRows(rows)

	claims, err := store.GetCustomClaims(context.Background(), "client-1", "openid profile", "access_token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// tier: matches (no gate, token→access_token ok)
	if v, ok := claims["https://example.com/tier"]; !ok || v != "enterprise" {
		t.Errorf("expected tier=enterprise, got %v", claims)
	}
	// secret: filtered out (gate=custom_scope not in "openid profile")
	if _, ok := claims["https://example.com/secret"]; ok {
		t.Error("secret should be filtered (scope gate not met)")
	}
	// count: filtered out (dest=id_token but request is access_token)
	if _, ok := claims["https://example.com/count"]; ok {
		t.Error("count should be filtered (dest=id_token not access_token)")
	}
	// flag: matches (dest=access_token)
	if v, ok := claims["https://example.com/flag"]; !ok || v != true {
		t.Errorf("expected flag=true, got %v", claims)
	}
}

func TestGetCustomClaims_UserInfoDestination(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()
	store := NewClientStore(db)

	rows := sqlmock.NewRows([]string{"key", "value_type", "value", "scope_gate", "destinations"}).
		AddRow("https://example.com/ui_only", "string", "ui-val", "", "userinfo").
		AddRow("https://example.com/token_only", "string", "tok-val", "", "access_token")

	mock.ExpectQuery(`SELECT key, value_type, value`).
		WithArgs("client-1").
		WillReturnRows(rows)

	claims, err := store.GetCustomClaims(context.Background(), "client-1", "openid", "userinfo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := claims["https://example.com/ui_only"]; !ok {
		t.Error("ui_only should be present for userinfo destination")
	}
	if _, ok := claims["https://example.com/token_only"]; ok {
		t.Error("token_only should be filtered out for userinfo destination")
	}
}

// ── GetClientOrgID (sqlmock) ──────────────────────────────────────────────

func TestGetClientOrgID_Found(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()
	store := NewClientStore(db)

	orgID := "org-xyz"
	mock.ExpectQuery(`SELECT org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs("client-1").
		WillReturnRows(sqlmock.NewRows([]string{"org_id"}).AddRow(&orgID))

	result, err := store.GetClientOrgID(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || *result != "org-xyz" {
		t.Errorf("expected org_id=org-xyz, got %v", result)
	}
}

func TestGetClientOrgID_NullOrgID(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()
	store := NewClientStore(db)

	mock.ExpectQuery(`SELECT org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs("client-public").
		WillReturnRows(sqlmock.NewRows([]string{"org_id"}).AddRow(nil))

	result, err := store.GetClientOrgID(context.Background(), "client-public")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil org_id for public client, got %v", result)
	}
}

func TestGetClientOrgID_NotFound(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()
	store := NewClientStore(db)

	mock.ExpectQuery(`SELECT org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs("missing-client").
		WillReturnError(sql.ErrNoRows)

	result, err := store.GetClientOrgID(context.Background(), "missing-client")
	if err != nil {
		t.Fatalf("expected nil error for not found, got %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for not found, got %v", result)
	}
}
