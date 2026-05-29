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
		nil, // auditStore: nil is safe — handler guards with != nil check
		encKey,
		"http://localhost:8080",
	)
	return h, orgMock, clientMock, mr
}

// orgSlugRow returns a single-row result for a GetOrgBySlug query.
func orgSlugRow(orgID string, slug, name string) *sqlmock.Rows {
	ownerID := uuid.New().String()
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

	orgID := uuid.New().String()
	userID := uuid.New().String()

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

	orgID := uuid.New().String()
	userID := uuid.New().String()
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

	orgID := uuid.New().String()
	userID := uuid.New().String()

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

	orgID := uuid.New().String()
	userID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))
	clientMock.ExpectBegin()
	clientMock.ExpectExec(`INSERT INTO oauth2_clients`).
		WithArgs(sqlmock.AnyArg(), "My App", sqlmock.AnyArg(), "https://example.com/cb", false, sqlmock.AnyArg(), orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	clientMock.ExpectExec(`INSERT INTO client_org_grants`).
		WithArgs(sqlmock.AnyArg(), orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	clientMock.ExpectCommit()

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

	orgID := uuid.New().String()
	userID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("admin"))
	// Public clients have empty secret
	clientMock.ExpectBegin()
	clientMock.ExpectExec(`INSERT INTO oauth2_clients`).
		WithArgs(sqlmock.AnyArg(), "SPA Client", "", "https://app.example.com/cb", true, sqlmock.AnyArg(), orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	clientMock.ExpectExec(`INSERT INTO client_org_grants`).
		WithArgs(sqlmock.AnyArg(), orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	clientMock.ExpectCommit()

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

func TestRegisterClient_Success_ServiceAccount(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))
	clientMock.ExpectBegin()
	clientMock.ExpectExec(`INSERT INTO oauth2_clients`).
		WithArgs(sqlmock.AnyArg(), "CI Deploy Bot", sqlmock.AnyArg(), serviceAccountRedirectURI, false, sqlmock.AnyArg(), orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	clientMock.ExpectExec(`INSERT INTO client_org_grants`).
		WithArgs(sqlmock.AnyArg(), orgID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	clientMock.ExpectCommit()

	form := url.Values{}
	form.Set("name", "CI Deploy Bot")
	form.Set("service_account", "on")
	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/clients",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.RegisterClient(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "newClientID=") {
		t.Errorf("expected newClientID in redirect, got %s", loc)
	}
}

func TestRegisterClient_InvalidName(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()

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

	orgID := uuid.New().String()
	userID := uuid.New().String()

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

	orgID := uuid.New().String()
	userID := uuid.New().String()

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

	orgID := uuid.New().String()
	userID := uuid.New().String()
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

	orgID := uuid.New().String()
	userID := uuid.New().String()
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

	orgID := uuid.New().String()
	userID := uuid.New().String()
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

	orgID := uuid.New().String()
	userID := uuid.New().String()
	clientIDStr := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	clientMock.ExpectBegin()
	clientMock.ExpectQuery(`SELECT public FROM oauth2_clients`).
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

	orgID := uuid.New().String()
	userID := uuid.New().String()
	clientIDStr := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	clientMock.ExpectBegin()
	clientMock.ExpectQuery(`SELECT public FROM oauth2_clients`).
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

	orgID := uuid.New().String()
	userID := uuid.New().String()
	clientIDStr := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	clientMock.ExpectBegin()
	clientMock.ExpectQuery(`SELECT public FROM oauth2_clients`).
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
func seedSession(t *testing.T, rdb *goredis.Client, userID string) string {
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
	orgID := uuid.New().String()
	seedInvite(mr, token, orgID, "acme", "Acme Corp", "invited@example.com", "admin@example.com", "member")

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
	userID := uuid.New().String()
	orgID := uuid.New().String()
	sessionID := seedSession(t, h.rdb, userID)
	seedInvite(mr, token, orgID, "acme", "Acme Corp", "user@example.com", "admin@example.com", "member")

	orgMock.ExpectQuery(`SELECT (.+) FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "username", "password_hash", "is_verified", "is_admin", "admin_role", "password_changed", "disabled_at", "deleted_at", "created_at", "updated_at"}).
			AddRow(userID, "user@example.com", "User", nil, "hash", true, false, nil, false, nil, nil, time.Now(), time.Now()))
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
	userID := uuid.New().String()
	orgID := uuid.New().String()
	sessionID := seedSession(t, h.rdb, userID)
	seedInvite(mr, token, orgID, "acme", "Acme Corp", "invited@example.com", "admin@example.com", "member")

	orgMock.ExpectQuery(`SELECT (.+) FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "username", "password_hash", "is_verified", "is_admin", "admin_role", "password_changed", "disabled_at", "deleted_at", "created_at", "updated_at"}).
			AddRow(userID, "wrong@example.com", "Wrong User", nil, "hash", true, false, nil, true, nil, nil, time.Now(), time.Now()))

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

func leaveOrgRequest(t *testing.T, userID string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/leave", nil)
	req = withUserContext(req, userID)
	return req, httptest.NewRecorder()
}

func TestLeaveOrg_OrgNotFound(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	userID := uuid.New().String()
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

	orgID := uuid.New().String()
	userID := uuid.New().String()

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

	orgID := uuid.New().String()
	userID := uuid.New().String()

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

	orgID := uuid.New().String()
	userID := uuid.New().String()
	differentOwner := uuid.New().String()

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

	orgID := uuid.New().String()
	userID := uuid.New().String()
	differentOwner := uuid.New().String()

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

	orgID := uuid.New().String()
	userID := uuid.New().String()
	differentOwner := uuid.New().String()

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

// --- TransferOwnershipAndLeave POST ---

func transferOwnershipRequest(t *testing.T, userID string, newOwnerID string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	form := url.Values{}
	form.Set("new_owner_id", newOwnerID)
	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/transfer-ownership",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUserContext(req, userID)
	return req, httptest.NewRecorder()
}

func TestTransferOwnership_OrgNotFound(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	userID := uuid.New().String()
	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"id", "slug", "display_name", "owner_id", "created_at", "updated_at"}))

	req, rr := transferOwnershipRequest(t, userID, uuid.New().String())
	h.TransferOwnershipAndLeave(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "/account/orgs?error=") {
		t.Errorf("expected org-list error redirect, got %s", rr.Header().Get("Location"))
	}
}

func TestTransferOwnership_NotMember(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(sqlmock.NewRows([]string{"role"})) // no rows → role=""

	req, rr := transferOwnershipRequest(t, userID, uuid.New().String())
	h.TransferOwnershipAndLeave(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/account/orgs/acme?error=") {
		t.Errorf("expected org detail error redirect, got %s", loc)
	}
}

func TestTransferOwnership_NotOwner(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("admin"))

	req, rr := transferOwnershipRequest(t, userID, uuid.New().String())
	h.TransferOwnershipAndLeave(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/account/orgs/acme?error=") || !strings.Contains(loc, "Access+denied") {
		t.Errorf("expected access denied redirect, got %s", loc)
	}
}

func TestTransferOwnership_SelfTransfer(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	req, rr := transferOwnershipRequest(t, userID, userID)
	h.TransferOwnershipAndLeave(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/account/orgs/acme?error=") || !strings.Contains(loc, "yourself") {
		t.Errorf("expected self-transfer error redirect, got %s", loc)
	}
}

func TestTransferOwnership_TargetNotMember(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()
	newOwnerID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))
	// TransferOwnershipAndLeave TX: BEGIN → SELECT FOR UPDATE (no rows) → ROLLBACK
	orgMock.ExpectBegin()
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, newOwnerID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}))
	orgMock.ExpectRollback()

	req, rr := transferOwnershipRequest(t, userID, newOwnerID)
	h.TransferOwnershipAndLeave(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/account/orgs/acme?error=") || !strings.Contains(loc, "not+a+member") {
		t.Errorf("expected target-not-member error redirect, got %s", loc)
	}
}

func TestTransferOwnership_StoreError(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()
	newOwnerID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))
	orgMock.ExpectBegin()
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, newOwnerID).
		WillReturnError(errors.New("db failure"))
	orgMock.ExpectRollback()

	req, rr := transferOwnershipRequest(t, userID, newOwnerID)
	h.TransferOwnershipAndLeave(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/account/orgs/acme?error=") {
		t.Errorf("expected error redirect, got %s", loc)
	}
}

func TestTransferOwnership_Success(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()
	newOwnerID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	// TransferOwnershipAndLeave TX
	orgMock.ExpectBegin()
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, newOwnerID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("admin"))
	orgMock.ExpectExec(`UPDATE organizations SET owner_id`).
		WithArgs(newOwnerID, orgID, userID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	orgMock.ExpectExec(`UPDATE org_memberships SET role = 'owner'`).
		WithArgs(orgID, newOwnerID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	orgMock.ExpectExec(`UPDATE org_memberships SET removed_at`).
		WithArgs(orgID, userID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	orgMock.ExpectCommit()

	req, rr := transferOwnershipRequest(t, userID, newOwnerID)
	h.TransferOwnershipAndLeave(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/account?message=") {
		t.Errorf("expected success redirect to /account, got %s", loc)
	}
	if !strings.Contains(loc, "Acme") {
		t.Errorf("expected org name in success message, got %s", loc)
	}
}

// --- SendInvite ---

func sendInviteRequest(t *testing.T, userID string, email, role string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	form := url.Values{}
	form.Set("email", email)
	form.Set("role", role)
	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/invites",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUserContext(req, userID)
	return req, httptest.NewRecorder()
}

func userEmailRow(id string, email string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "email", "name", "username", "password_hash", "is_verified", "is_admin", "admin_role", "password_changed", "disabled_at", "deleted_at", "created_at", "updated_at"}).
		AddRow(id, email, "User", nil, "hash", true, false, nil, false, nil, nil, time.Now(), time.Now())
}

func TestSendInvite_ExistingActiveMember(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	actorID := uuid.New().String()
	targetID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, actorID).
		WillReturnRows(membershipRow("admin"))
	orgMock.ExpectQuery(`SELECT (.+) FROM users WHERE email = \$1`).
		WithArgs("alice@example.com").
		WillReturnRows(userEmailRow(targetID, "alice@example.com"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, targetID).
		WillReturnRows(membershipRow("member"))

	req, rr := sendInviteRequest(t, actorID, "alice@example.com", "admin")
	h.SendInvite(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "already+a+member") && !strings.Contains(loc, "already%20a%20member") {
		t.Errorf("expected 'already a member' error in redirect, got %s", loc)
	}
	if keys := mr.Keys(); len(keys) > 0 {
		t.Errorf("expected no Redis keys created, got %v", keys)
	}
}

func TestSendInvite_AlreadyPendingInvite(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	actorID := uuid.New().String()

	const existingToken = "existing-pending-token"
	seedInvite(mr, existingToken, orgID, "acme", "Acme Corp", "bob@example.com", "admin@example.com", "member")
	h.rdb.SAdd(context.Background(), "org:invites:"+orgID, existingToken)

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, actorID).
		WillReturnRows(membershipRow("admin"))
	orgMock.ExpectQuery(`SELECT (.+) FROM users WHERE email = \$1`).
		WithArgs("bob@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "username", "password_hash", "is_verified", "is_admin", "admin_role", "password_changed", "disabled_at", "deleted_at", "created_at", "updated_at"}))

	req, rr := sendInviteRequest(t, actorID, "bob@example.com", "viewer")
	h.SendInvite(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "already+pending") && !strings.Contains(loc, "already%20pending") {
		t.Errorf("expected 'already pending' error in redirect, got %s", loc)
	}
	if _, err := mr.Get("org:invite:" + existingToken); err != nil {
		t.Error("original invite token should still exist in Redis")
	}
}

func TestSendInvite_GetByEmailError(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	actorID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, actorID).
		WillReturnRows(membershipRow("admin"))
	orgMock.ExpectQuery(`SELECT (.+) FROM users WHERE email = \$1`).
		WithArgs("error@example.com").
		WillReturnError(errors.New("connection refused"))

	req, rr := sendInviteRequest(t, actorID, "error@example.com", "member")
	h.SendInvite(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "Server+error") && !strings.Contains(loc, "Server%20error") {
		t.Errorf("expected 'Server error' in redirect, got %s", loc)
	}
	if keys := mr.Keys(); len(keys) > 0 {
		t.Errorf("expected no Redis keys created, got %v", keys)
	}
}

func TestSendInvite_EmailNormalization(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	actorID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, actorID).
		WillReturnRows(membershipRow("admin"))
	orgMock.ExpectQuery(`SELECT (.+) FROM users WHERE email = \$1`).
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "username", "password_hash", "is_verified", "is_admin", "admin_role", "password_changed", "disabled_at", "deleted_at", "created_at", "updated_at"}))
	orgMock.ExpectQuery(`SELECT (.+) FROM users WHERE id = \$1`).
		WithArgs(actorID).
		WillReturnRows(userEmailRow(actorID, "admin@example.com"))

	req, rr := sendInviteRequest(t, actorID, "  Alice@Example.com  ", "member")
	h.SendInvite(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "Invite+sent") && !strings.Contains(loc, "Invite%20sent") {
		t.Errorf("expected success redirect, got %s", loc)
	}
	members, err := mr.SMembers("org:invites:" + orgID)
	if err != nil || len(members) == 0 {
		t.Fatal("expected invite token in Redis SET")
	}
	raw, err := mr.Get("org:invite:" + members[0])
	if err != nil {
		t.Fatalf("expected invite payload in Redis: %v", err)
	}
	if !strings.Contains(raw, `"alice@example.com"`) {
		t.Errorf("expected normalized lowercase email in invite payload, got %s", raw)
	}
}

func TestSendInvite_NewUnregisteredUser(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	actorID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, actorID).
		WillReturnRows(membershipRow("admin"))
	orgMock.ExpectQuery(`SELECT (.+) FROM users WHERE email = \$1`).
		WithArgs("new@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "username", "password_hash", "is_verified", "is_admin", "admin_role", "password_changed", "disabled_at", "deleted_at", "created_at", "updated_at"}))
	orgMock.ExpectQuery(`SELECT (.+) FROM users WHERE id = \$1`).
		WithArgs(actorID).
		WillReturnRows(userEmailRow(actorID, "admin@example.com"))

	req, rr := sendInviteRequest(t, actorID, "new@example.com", "member")
	h.SendInvite(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "Invite+sent") && !strings.Contains(loc, "Invite%20sent") {
		t.Errorf("expected success redirect, got %s", loc)
	}
	members, err := mr.SMembers("org:invites:" + orgID)
	if err != nil || len(members) == 0 {
		t.Fatal("expected invite token in org:invites SET")
	}
	if _, err := mr.Get("org:invite:" + members[0]); err != nil {
		t.Errorf("expected org:invite payload in Redis: %v", err)
	}
}

// --- GrantClientAccess ---

func TestGrantClientAccess_SingleOrg_DirectGrant(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()
	clientIDStr := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	// IsGlobalClient: org_id IS NOT NULL → not global
	clientMock.ExpectQuery(`SELECT \(org_id IS NULL\) FROM oauth2_clients WHERE id = \$1`).
		WithArgs(clientIDStr).
		WillReturnRows(sqlmock.NewRows([]string{"is_global"}).AddRow(false))

	// GrantOrgAccess: INSERT INTO client_org_grants
	clientMock.ExpectExec(`INSERT INTO client_org_grants`).
		WithArgs(clientIDStr, orgID, userID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	form := url.Values{}
	form.Set("client_id", clientIDStr)
	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/grants",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.GrantClientAccess(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "granted") && !strings.Contains(loc, "message=") {
		t.Errorf("expected success message redirect, got %s", loc)
	}
}

func TestGrantClientAccess_MultiOrg_CreatesRequest(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()
	clientIDStr := uuid.New().String()
	ownerOrgID := uuid.New().String()
	requestID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	// IsGlobalClient: org_id IS NULL → global
	clientMock.ExpectQuery(`SELECT \(org_id IS NULL\) FROM oauth2_clients WHERE id = \$1`).
		WithArgs(clientIDStr).
		WillReturnRows(sqlmock.NewRows([]string{"is_global"}).AddRow(true))

	// GetClientOwnerOrgID
	clientMock.ExpectQuery(`SELECT owner_org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs(clientIDStr).
		WillReturnRows(sqlmock.NewRows([]string{"owner_org_id"}).AddRow(ownerOrgID))

	// CreateGrantRequest
	clientMock.ExpectQuery(`INSERT INTO client_access_requests`).
		WithArgs(sqlmock.AnyArg(), clientIDStr, orgID, ownerOrgID, userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "client_id", "requester_org_id", "owner_org_id", "requested_by", "status", "requested_at"}).
			AddRow(requestID, clientIDStr, orgID, ownerOrgID, userID, "pending", time.Now()))

	form := url.Values{}
	form.Set("client_id", clientIDStr)
	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/grants",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.GrantClientAccess(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "message=") {
		t.Errorf("expected success message redirect, got %s", loc)
	}
	if strings.Contains(loc, "error=") {
		t.Errorf("expected no error in redirect, got %s", loc)
	}
}

func TestGrantClientAccess_NotOwner(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()
	clientIDStr := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("admin")) // admin, not owner

	form := url.Values{}
	form.Set("client_id", clientIDStr)
	req := httptest.NewRequest(http.MethodPost, "/account/orgs/acme/grants",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.GrantClientAccess(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

// --- ApproveGrantRequest ---

func TestApproveGrantRequest_Success(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()
	clientIDStr := uuid.New().String()
	requestID := uuid.New().String()
	requesterOrgID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	// GetClientOwnerOrgID — must match this org
	clientMock.ExpectQuery(`SELECT owner_org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs(clientIDStr).
		WillReturnRows(sqlmock.NewRows([]string{"owner_org_id"}).AddRow(orgID))

	// ApproveGrantRequest TX
	clientMock.ExpectBegin()
	clientMock.ExpectQuery(`UPDATE client_access_requests`).
		WithArgs(requestID, clientIDStr, orgID, userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "client_id", "requester_org_id", "owner_org_id", "requested_by", "status", "requested_at"}).
			AddRow(requestID, clientIDStr, requesterOrgID, orgID, userID, "approved", time.Now()))
	clientMock.ExpectExec(`INSERT INTO client_org_grants`).
		WithArgs(clientIDStr, requesterOrgID, userID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	clientMock.ExpectCommit()

	req := httptest.NewRequest(http.MethodPost,
		"/account/orgs/acme/clients/"+clientIDStr+"/requests/"+requestID+"/approve", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.ApproveGrantRequest(rr, req, withParams("slug", "acme", "clientID", clientIDStr, "requestID", requestID))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "message=") || strings.Contains(loc, "error=") {
		t.Errorf("expected success message redirect, got %s", loc)
	}
}

func TestApproveGrantRequest_NotOwner(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()
	clientIDStr := uuid.New().String()
	requestID := uuid.New().String()
	otherOrgID := uuid.New().String() // client owned by a different org

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	// GetClientOwnerOrgID — returns a different org → forbidden
	clientMock.ExpectQuery(`SELECT owner_org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs(clientIDStr).
		WillReturnRows(sqlmock.NewRows([]string{"owner_org_id"}).AddRow(otherOrgID))

	req := httptest.NewRequest(http.MethodPost,
		"/account/orgs/acme/clients/"+clientIDStr+"/requests/"+requestID+"/approve", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.ApproveGrantRequest(rr, req, withParams("slug", "acme", "clientID", clientIDStr, "requestID", requestID))

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

// --- DenyGrantRequest ---

func TestDenyGrantRequest_Success(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()
	clientIDStr := uuid.New().String()
	requestID := uuid.New().String()
	requesterOrgID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	clientMock.ExpectQuery(`SELECT owner_org_id FROM oauth2_clients WHERE id = \$1`).
		WithArgs(clientIDStr).
		WillReturnRows(sqlmock.NewRows([]string{"owner_org_id"}).AddRow(orgID))

	// DenyGrantRequest — single UPDATE (no TX)
	clientMock.ExpectQuery(`UPDATE client_access_requests`).
		WithArgs(requestID, clientIDStr, orgID, userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "client_id", "requester_org_id", "owner_org_id", "requested_by", "status", "requested_at"}).
			AddRow(requestID, clientIDStr, requesterOrgID, orgID, userID, "denied", time.Now()))

	req := httptest.NewRequest(http.MethodPost,
		"/account/orgs/acme/clients/"+clientIDStr+"/requests/"+requestID+"/deny", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.DenyGrantRequest(rr, req, withParams("slug", "acme", "clientID", clientIDStr, "requestID", requestID))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "message=") || strings.Contains(loc, "error=") {
		t.Errorf("expected success message redirect, got %s", loc)
	}
}

// --- ExploreApps ---

func TestExploreApps_Success(t *testing.T) {
	h, orgMock, clientMock, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()
	ownerOrgID := uuid.New().String()
	clientIDStr := uuid.New().String()
	now := time.Now()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(membershipRow("owner"))

	// ListDiscoverableClients: COUNT then SELECT
	clientMock.ExpectQuery(`SELECT COUNT\(\*\) FROM oauth2_clients`).
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	clientMock.ExpectQuery(`SELECT c\.id, c\.name`).
		WithArgs(orgID, 21). // pageSize=20 → limit+1=21
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "domain", "public", "owner_org_id", "display_name", "slug", "created_at"}).
			AddRow(clientIDStr, "Global App", "https://app.example.com/cb", false, ownerOrgID, "Owner Corp", "owner-corp", now))

	req := httptest.NewRequest(http.MethodGet, "/account/orgs/acme/explore", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.ExploreApps(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Global App") {
		t.Error("expected client name in response body")
	}
}

func TestExploreApps_NonMember(t *testing.T) {
	h, orgMock, _, mr := setupOrgHandler(t)
	defer mr.Close()

	orgID := uuid.New().String()
	userID := uuid.New().String()

	orgMock.ExpectQuery(`SELECT (.+) FROM organizations WHERE slug`).
		WithArgs("acme").
		WillReturnRows(orgSlugRow(orgID, "acme", "Acme Corp"))
	orgMock.ExpectQuery(`SELECT role FROM org_memberships`).
		WithArgs(orgID, userID).
		WillReturnRows(sqlmock.NewRows([]string{"role"})) // no membership

	req := httptest.NewRequest(http.MethodGet, "/account/orgs/acme/explore", nil)
	req = withUserContext(req, userID)
	rr := httptest.NewRecorder()

	h.ExploreApps(rr, req, withParams("slug", "acme"))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "Access+denied") {
		t.Errorf("expected access denied redirect, got %s", rr.Header().Get("Location"))
	}
}
