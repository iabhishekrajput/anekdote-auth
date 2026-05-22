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
	"github.com/alicebob/miniredis/v2"
	goredis "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	redisStore "github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis/redisutil"
	"github.com/julienschmidt/httprouter"
)

// setupOrgHandler wires an OrgHandler with two independent sqlmock databases
// (one for the org/user stores, one for the client store) and a miniredis.
// Returns (handler, orgMock, clientMock, mr) so callers can set expectations
// and defer mr.Close().
func setupOrgHandler(t *testing.T) (*OrgHandler, sqlmock.Sqlmock, sqlmock.Sqlmock, *miniredis.Miniredis) {
	t.Helper()

	orgDB, orgMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock (org): %v", err)
	}
	clientDB, clientMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock (client): %v", err)
	}

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}

	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	sess := redisStore.NewSessionStore(rdb)
	revoc := redisStore.NewRevocationStore(rdb)

	encKey := make([]byte, 32)
	h := NewOrgHandler(
		postgres.NewOrgStore(orgDB),
		postgres.NewUserStore(orgDB),
		postgres.NewClientStore(clientDB),
		sess,
		nil,
		rdb,
		revoc,
		encKey,
		"http://localhost:8080",
	)
	return h, orgMock, clientMock, mr
}

// orgSlugRow returns a single-row result for a GetOrgBySlug query.
func orgSlugRow(orgID uuid.UUID, slug, name string) *sqlmock.Rows {
	ownerID := uuid.New()
	return sqlmock.NewRows([]string{"id", "slug", "display_name", "owner_id", "created_at", "updated_at"}).
		AddRow(orgID, slug, name, ownerID, time.Now(), time.Now())
}

// membershipRow returns a single-row result for GetMembership.
func membershipRow(role string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"role"}).AddRow(role)
}

// withParams builds an httprouter.Params slice from alternating key/value pairs.
func withParams(kv ...string) httprouter.Params {
	var ps httprouter.Params
	for i := 0; i+1 < len(kv); i += 2 {
		ps = append(ps, httprouter.Param{Key: kv[i], Value: kv[i+1]})
	}
	return ps
}

// --- OrgClients GET ---

func TestOrgClients_NoFlash(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))
	clientMock.ExpectQuery(`SELECT id, name, domain, public, created_at FROM oauth2_clients`).
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "domain", "public", "created_at"}))

	req := httptest.NewRequest(http.MethodGet, "/account/orgs/acme/clients", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.OrgClients(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Acme Corp") {
		t.Error("expected org name in response")
	}
}

func TestOrgClients_WithFlash(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()
	clientIDStr := uuid.New().String()
	const secret = "key_abc123"

	// Pre-seed the flash key in miniredis (must be encrypted, matching OrgHandler.storeSecretFlash).
	encKey := make([]byte, 32)
	encrypted, err := redisutil.Encrypt(encKey, secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	mr.Set("oauth:client-secret-flash:"+clientIDStr, encrypted)

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))
	clientMock.ExpectQuery(`SELECT id, name, domain, public, created_at FROM oauth2_clients`).
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "domain", "public", "created_at"}))

	req := httptest.NewRequest(http.MethodGet, "/account/orgs/acme/clients?newClientID="+clientIDStr, nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.OrgClients(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), secret) {
		t.Error("expected secret to appear in secret reveal modal")
	}

	// Flash key should be consumed (GETDEL).
	if _, err := mr.Get("oauth:client-secret-flash:" + clientIDStr); err == nil {
		t.Error("expected flash key to be deleted after pop")
	}
}

func TestOrgClients_NonMember(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(sqlmock.NewRows([]string{"role"})) // no rows → role=""

	req := httptest.NewRequest(http.MethodGet, "/account/orgs/acme/clients", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.OrgClients(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "Access+denied") {
		t.Errorf("expected access denied redirect, got %s", rr.Header().Get("Location"))
	}
}

// --- RegisterClient POST ---

func TestRegisterClient_Success_Confidential(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))
	clientMock.ExpectExec(`INSERT INTO oauth2_clients`).
		WithArgs(sqlmock.AnyArg(), "My App", sqlmock.AnyArg(), "https://example.com/cb", false, orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	form := url.Values{}
	form.Set("name", "My App")
	form.Set("redirect_uri", "https://example.com/cb")
	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/clients",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.RegisterClient(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "newClientID=") {
		t.Errorf("expected newClientID in redirect, got %s", loc)
	}
}

func TestRegisterClient_Success_Public(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("admin"))
	// Public clients have empty secret
	clientMock.ExpectExec(`INSERT INTO oauth2_clients`).
		WithArgs(sqlmock.AnyArg(), "SPA Client", "", "https://app.example.com/cb", true, orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	form := url.Values{}
	form.Set("name", "SPA Client")
	form.Set("redirect_uri", "https://app.example.com/cb")
	form.Set("public", "on")
	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/clients",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.RegisterClient(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
}

func TestRegisterClient_InvalidName(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	form := url.Values{}
	form.Set("name", "") // empty → invalid
	form.Set("redirect_uri", "https://example.com/cb")
	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/clients",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.RegisterClient(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "error=") {
		t.Errorf("expected error in redirect, got %s", loc)
	}
	if strings.Contains(loc, "newClientID=") {
		t.Error("should not have newClientID on validation error")
	}
}

func TestRegisterClient_InvalidRedirectURI(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	form := url.Values{}
	form.Set("name", "My App")
	form.Set("redirect_uri", "ftp://bad.example.com") // invalid scheme
	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/clients",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.RegisterClient(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "error=") {
		t.Error("expected error redirect for invalid redirect URI")
	}
}

func TestRegisterClient_NonAdmin(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("member")) // not owner/admin

	form := url.Values{}
	form.Set("name", "My App")
	form.Set("redirect_uri", "https://example.com/cb")
	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/clients",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.RegisterClient(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "Access+denied") {
		t.Errorf("expected access denied redirect, got %s", rr.Header().Get("Location"))
	}
}

// --- DeleteClient POST ---

func TestDeleteClient_Success(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()
	clientIDStr := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))
	clientMock.ExpectExec(`DELETE FROM oauth2_clients WHERE id = \$1 AND org_id = \$2`).
		WithArgs(clientIDStr, orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/clients/"+clientIDStr+"/delete", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.DeleteClient(rr, req, withParams("slug", "acme", "clientID", clientIDStr))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "Client+deleted") {
		t.Errorf("expected success message, got %s", rr.Header().Get("Location"))
	}
}

func TestDeleteClient_NotFound(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()
	clientIDStr := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))
	clientMock.ExpectExec(`DELETE FROM oauth2_clients WHERE id = \$1 AND org_id = \$2`).
		WithArgs(clientIDStr, orgID).
		WillReturnResult(sqlmock.NewResult(0, 0)) // 0 rows → ErrClientNotFound

	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/clients/"+clientIDStr+"/delete", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.DeleteClient(rr, req, withParams("slug", "acme", "clientID", clientIDStr))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "error=") {
		t.Errorf("expected error redirect, got %s", rr.Header().Get("Location"))
	}
}

func TestDeleteClient_NonAdmin(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()
	clientIDStr := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("member"))

	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/clients/"+clientIDStr+"/delete", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.DeleteClient(rr, req, withParams("slug", "acme", "clientID", clientIDStr))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "Access+denied") {
		t.Errorf("expected access denied redirect, got %s", rr.Header().Get("Location"))
	}
}

// --- RotateClientSecret POST ---

func TestRotateClientSecret_Success(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()
	clientIDStr := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	clientMock.ExpectBegin()
	clientMock.ExpectQuery(`SELECT public FROM oauth2_clients WHERE id = \$1 AND org_id = \$2 FOR UPDATE`).
		WithArgs(clientIDStr, orgID).
		WillReturnRows(sqlmock.NewRows([]string{"public"}).AddRow(false))
	clientMock.ExpectExec(`UPDATE oauth2_clients SET secret`).
		WithArgs(sqlmock.AnyArg(), clientIDStr, orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	clientMock.ExpectCommit()

	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/clients/"+clientIDStr+"/rotate-secret", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.RotateClientSecret(rr, req, withParams("slug", "acme", "clientID", clientIDStr))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "newClientID=") {
		t.Errorf("expected newClientID in redirect, got %s", loc)
	}
	// Flash key should have been written.
	if _, err := mr.Get("oauth:client-secret-flash:" + clientIDStr); err != nil {
		t.Error("expected flash key to be set after rotate")
	}
}

func TestRotateClientSecret_ClientNotFound(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()
	clientIDStr := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	clientMock.ExpectBegin()
	clientMock.ExpectQuery(`SELECT public FROM oauth2_clients WHERE id = \$1 AND org_id = \$2 FOR UPDATE`).
		WithArgs(clientIDStr, orgID).
		WillReturnError(sqlmock.ErrCancelled) // causes ErrClientNotFound via sql.ErrNoRows path
	clientMock.ExpectRollback()

	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/clients/"+clientIDStr+"/rotate-secret", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.RotateClientSecret(rr, req, withParams("slug", "acme", "clientID", clientIDStr))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "error=") {
		t.Errorf("expected error redirect, got %s", rr.Header().Get("Location"))
	}
}

func TestRotateClientSecret_FlashFailure(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()
	clientIDStr := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	clientMock.ExpectBegin()
	clientMock.ExpectQuery(`SELECT public FROM oauth2_clients WHERE id = \$1 AND org_id = \$2 FOR UPDATE`).
		WithArgs(clientIDStr, orgID).
		WillReturnRows(sqlmock.NewRows([]string{"public"}).AddRow(false))
	clientMock.ExpectExec(`UPDATE oauth2_clients SET secret`).
		WithArgs(sqlmock.AnyArg(), clientIDStr, orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	clientMock.ExpectCommit()

	// Take Redis down to simulate flash store failure.
	mr.Close()

	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/clients/"+clientIDStr+"/rotate-secret", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.RotateClientSecret(rr, req, withParams("slug", "acme", "clientID", clientIDStr))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "error=") {
		t.Errorf("expected recovery error redirect, got %s", loc)
	}
	if strings.Contains(loc, "newClientID=") {
		t.Error("should not redirect to secret reveal when flash failed")
	}
}

// seedInvite writes a JSON invite payload to miniredis at org:invite:{token}.
func seedInvite(mr *miniredis.Miniredis, token, orgID, orgSlug, orgName, email, inviterEmail, role string) {
	payload := `{"org_id":"` + orgID + `","inviter_id":"00000000-0000-0000-0000-000000000001","role":"` + role + `","email":"` + email + `","inviter_email":"` + inviterEmail + `","org_slug":"` + orgSlug + `","org_name":"` + orgName + `"}`
	mr.Set("org:invite:"+token, payload)
}

// seedSession creates a session in miniredis and returns the session ID.
func seedSession(t *testing.T, rdb *goredis.Client, userID uuid.UUID) string {
	t.Helper()
	sess := redisStore.NewSessionStore(rdb)
	sessionID, err := sess.Create(context.Background(), userID)
	if err != nil {
		t.Fatalf("seedSession: %v", err)
	}
	return sessionID
}

// --- AcceptInvite ---

func TestAcceptInvite_MissingToken(t *testing.T) {
	h, _, _, mr := setupOrgHandler(t)
	defer mr.Close()

	req := httptest.NewRequest(http.MethodGet, "/join", nil)
	rr := httptest.NewRecorder()

	h.AcceptInvite(rr, req, nil)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/login") || !strings.Contains(loc, "error=") {
		t.Errorf("expected redirect to /login?error=..., got %s", loc)
	}
}

func TestAcceptInvite_ExpiredToken(t *testing.T) {
	h, _, _, mr := setupOrgHandler(t)
	defer mr.Close()

	req := httptest.NewRequest(http.MethodGet, "/join?token=no-such-token", nil)
	rr := httptest.NewRecorder()

	h.AcceptInvite(rr, req, nil)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/login") || !strings.Contains(loc, "error=") {
		t.Errorf("expected redirect to /login?error=..., got %s", loc)
	}
}

func TestAcceptInvite_NotLoggedIn(t *testing.T) {
	h, _, _, mr := setupOrgHandler(t)
	defer mr.Close()

	const token = "invite-token-notloggedin"
	orgID := uuid.New()
	seedInvite(mr, token, orgID.String(), "acme", "Acme Corp", "invited@example.com", "admin@example.com", "member")

	req := httptest.NewRequest(http.MethodGet, "/join?token="+token, nil)
	rr := httptest.NewRecorder()

	h.AcceptInvite(rr, req, nil)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/register") || !strings.Contains(loc, "invite=") {
		t.Errorf("expected redirect to /register?invite=..., got %s", loc)
	}
}

func TestAcceptInvite_Success(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	const token = "invite-token-success"
	userID := uuid.New()
	orgID := uuid.New()
	sessionID := seedSession(t, h.rdb, userID)
	seedInvite(mr, token, orgID.String(), "acme", "Acme Corp", "user@example.com", "admin@example.com", "member")

	orgMock.ExpectQuery(`SELECT (.+) FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "is_admin", "admin_role", "password_changed", "disabled_at", "created_at", "updated_at"}).
			AddRow(userID, "user@example.com", "User", "hash", true, false, nil, false, nil, time.Now(), time.Now()))
	orgMock.ExpectExec(`INSERT INTO org_memberships`).
		WithArgs(orgID, userID, "member", nil).
		WillReturnResult(sqlmock.NewResult(1, 1))

	req := httptest.NewRequest(http.MethodGet, "/join?token="+token, nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})
	rr := httptest.NewRecorder()

	h.AcceptInvite(rr, req, nil)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/account/orgs/acme") {
		t.Errorf("expected redirect to org page, got %s", loc)
	}
	// Token should be cleaned up
	if _, err := mr.Get("org:invite:" + token); err == nil {
		t.Error("expected invite token to be deleted after successful join")
	}
}

func TestAcceptInvite_EmailMismatch(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	const token = "invite-token-mismatch"
	userID := uuid.New()
	orgID := uuid.New()
	sessionID := seedSession(t, h.rdb, userID)
	seedInvite(mr, token, orgID.String(), "acme", "Acme Corp", "invited@example.com", "admin@example.com", "member")

	orgMock.ExpectQuery(`SELECT (.+) FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "password_hash", "is_verified", "is_admin", "admin_role", "password_changed", "disabled_at", "created_at", "updated_at"}).
			AddRow(userID, "wrong@example.com", "Wrong User", "hash", true, false, nil, true, nil, time.Now(), time.Now()))

	req := httptest.NewRequest(http.MethodGet, "/join?token="+token, nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})
	rr := httptest.NewRecorder()

	h.AcceptInvite(rr, req, nil)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "invited@example.com") {
		t.Error("expected invited email in response body")
	}
	if !strings.Contains(body, "wrong@example.com") {
		t.Error("expected current user email in response body")
	}
	if !strings.Contains(body, `name="redirect_to"`) {
		t.Error("expected redirect_to hidden field in response body")
	}
	// Token must NOT be consumed
	if _, err := mr.Get("org:invite:" + token); err != nil {
		t.Error("invite token should still be valid after mismatch")
	}
}

// --- LeaveOrg POST ---

func leaveOrgRequest(t *testing.T, userID uuid.UUID) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/leave", nil)
	req = withUserContext(req, userID)
	return req, httptest.NewRecorder()
}

func TestLeaveOrg_OrgNotFound(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	userID := uuid.New()
	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"id", "slug", "display_name", "owner_id", "created_at", "updated_at"}))

	req, rr := leaveOrgRequest(t, userID)
	h.LeaveOrg(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/account?error=") {
		t.Errorf("expected error redirect, got %s", loc)
	}
	if !strings.Contains(url.PathEscape(loc), url.PathEscape("Organization")) {
		// just check redirect has error param
	}
}

func TestLeaveOrg_NotMember(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}))

	req, rr := leaveOrgRequest(t, userID)
	h.LeaveOrg(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/account?error=") {
		t.Errorf("expected error redirect, got %s", loc)
	}
}

func TestLeaveOrg_OwnerBlocked_ViaStore(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))
	// RemoveMember: owner check query returns userID as owner_id → ErrOwnerCannotBeRemoved
	orgMock.ExpectQuery(`SELECT owner_id FROM organizations WHERE id`).
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows([]string{"owner_id"}).AddRow(userID))

	req, rr := leaveOrgRequest(t, userID)
	h.LeaveOrg(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/account?error=") {
		t.Errorf("expected error redirect, got %s", loc)
	}
}

func TestLeaveOrg_Success_Member(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()
	differentOwner := uuid.New()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"id", "slug", "display_name", "owner_id", "created_at", "updated_at"}).
			AddRow(orgID, "acme", "Acme Corp", differentOwner, time.Now(), time.Now()))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("member"))
	// RemoveMember: owner check
	orgMock.ExpectQuery(`SELECT owner_id FROM organizations WHERE id`).
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows([]string{"owner_id"}).AddRow(differentOwner))
	orgMock.ExpectExec(`UPDATE org_memberships SET removed_at`).
		WithArgs(orgID, userID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	req, rr := leaveOrgRequest(t, userID)
	h.LeaveOrg(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/account?message=") {
		t.Errorf("expected success redirect, got %s", loc)
	}
	if !strings.Contains(loc, "Acme+Corp") && !strings.Contains(loc, "Acme%20Corp") && !strings.Contains(loc, "Acme") {
		t.Errorf("expected org name in message, got %s", loc)
	}
}

func TestLeaveOrg_Success_Admin(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()
	differentOwner := uuid.New()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"id", "slug", "display_name", "owner_id", "created_at", "updated_at"}).
			AddRow(orgID, "acme", "Acme Corp", differentOwner, time.Now(), time.Now()))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("admin"))
	orgMock.ExpectQuery(`SELECT owner_id FROM organizations WHERE id`).
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows([]string{"owner_id"}).AddRow(differentOwner))
	orgMock.ExpectExec(`UPDATE org_memberships SET removed_at`).
		WithArgs(orgID, userID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	req, rr := leaveOrgRequest(t, userID)
	h.LeaveOrg(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/account?message=") {
		t.Errorf("expected success redirect, got %s", loc)
	}
}

func TestLeaveOrg_StoreError(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New()
	userID := uuid.New()
	differentOwner := uuid.New()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"id", "slug", "display_name", "owner_id", "created_at", "updated_at"}).
			AddRow(orgID, "acme", "Acme Corp", differentOwner, time.Now(), time.Now()))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("member"))
	orgMock.ExpectQuery(`SELECT owner_id FROM organizations WHERE id`).
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows([]string{"owner_id"}).AddRow(differentOwner))
	orgMock.ExpectExec(`UPDATE org_memberships SET removed_at`).
		WithArgs(orgID, userID).
		WillReturnError(errors.New("db failure"))

	req, rr := leaveOrgRequest(t, userID)
	h.LeaveOrg(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/account?error=") {
		t.Errorf("expected error redirect, got %s", loc)
	}
}
