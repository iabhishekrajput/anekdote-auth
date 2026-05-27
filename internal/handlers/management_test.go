package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/julienschmidt/httprouter"
)

const testMgmtAud = "https://localhost:8080/api/v1/"

// --- test doubles -----------------------------------------------------------

type mockRevStore struct {
	revoked bool
	err     error
}

func (m *mockRevStore) IsRevoked(_ context.Context, _ string) (bool, error) {
	return m.revoked, m.err
}

type mockMgmtClientStore struct {
	orgID  *string
	claims []postgres.ClaimDefinition
	saved  []postgres.ClaimDefinition
	err    error
}

func (m *mockMgmtClientStore) GetClientOrgID(_ context.Context, _ string) (*string, error) {
	return m.orgID, m.err
}

func (m *mockMgmtClientStore) ListCustomClaims(_ context.Context, _ string) ([]postgres.ClaimDefinition, error) {
	return m.claims, m.err
}

func (m *mockMgmtClientStore) SetCustomClaimsAdmin(_ context.Context, _ string, defs []postgres.ClaimDefinition) error {
	m.saved = defs
	return m.err
}

// --- helpers ----------------------------------------------------------------

func newTestKeyStore(t *testing.T) *crypto.KeyStore {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return &crypto.KeyStore{PrivateKey: pk, PublicKey: &pk.PublicKey, KeyID: "test-kid"}
}

func signMgmtToken(t *testing.T, ks *crypto.KeyStore, orgID, scope, aud string, exp time.Duration) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":    "https://localhost:8080",
		"sub":    "",
		"aud":    aud,
		"exp":    time.Now().Add(exp).Unix(),
		"iat":    time.Now().Unix(),
		"jti":    uuid.New().String(),
		"scope":  scope,
		"org_id": orgID,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = ks.KeyID
	s, err := tok.SignedString(ks.PrivateKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

func newTestMgmtHandler(ks *crypto.KeyStore, rev ManagementRevStore, cs ManagementClientStore) *ManagementHandler {
	return NewManagementHandler(ks, rev, cs, testMgmtAud)
}

// --- tests ------------------------------------------------------------------

func TestManagement_GetClaims_OK(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	clientID := "client-123"
	store := &mockMgmtClientStore{
		orgID: &orgID,
		claims: []postgres.ClaimDefinition{
			{Key: "https://example.com/tier", ValueType: "string", Value: "enterprise", Destinations: "token"},
		},
	}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "read:client_claims", testMgmtAud, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/"+clientID+"/claims", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", clientID))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse body: %v", err)
	}
	claimsArr, ok := body["claims"].([]any)
	if !ok || len(claimsArr) != 1 {
		t.Fatalf("expected 1 claim in response, got %v", body)
	}
}

func TestManagement_GetClaims_WrongOrg(t *testing.T) {
	ks := newTestKeyStore(t)
	clientOrgID := "org-other"
	store := &mockMgmtClientStore{orgID: &clientOrgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, "org-caller", "read:client_claims", testMgmtAud, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for wrong org, got %d", rr.Code)
	}
}

func TestManagement_GetClaims_WrongAudience(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "read:client_claims", "https://other.example.com/api/", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong audience, got %d", rr.Code)
	}
}

func TestManagement_GetClaims_ExpiredJWT(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "read:client_claims", testMgmtAud, -time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired JWT, got %d", rr.Code)
	}
}

func TestManagement_GetClaims_MissingScope(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "openid profile", testMgmtAud, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing scope, got %d", rr.Code)
	}
}

func TestManagement_GetClaims_RevokedToken(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{revoked: true}, store)

	token := signMgmtToken(t, ks, orgID, "read:client_claims", testMgmtAud, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked token, got %d", rr.Code)
	}
}

func TestManagement_PutClaims_OK(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	clientID := "client-123"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	body := `{"claims":[{"key":"https://example.com/tier","type":"string","value":"enterprise"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/"+clientID+"/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", clientID))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(store.saved) != 1 || store.saved[0].Key != "https://example.com/tier" {
		t.Errorf("expected saved claim key https://example.com/tier, got %v", store.saved)
	}
}

func TestManagement_PutClaims_ReservedKey(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	body := `{"claims":[{"key":"sub","type":"string","value":"evil"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for reserved key 'sub', got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_PutClaims_MissingNamespace(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	body := `{"claims":[{"key":"tier","type":"string","value":"enterprise"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for un-namespaced key 'tier', got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_PutClaims_ScopeGate(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	body := `{"claims":[{"key":"https://example.com/tier","type":"string","value":"enterprise","scope_gate":"custom_scope","destinations":"id_token"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with scope_gate, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(store.saved) != 1 || store.saved[0].ScopeGate != "custom_scope" || store.saved[0].Destinations != "id_token" {
		t.Errorf("expected scope_gate=custom_scope and destinations=id_token, got %+v", store.saved)
	}
}

func TestManagement_NoAuthHeader(t *testing.T) {
	ks := newTestKeyStore(t)
	h := newTestMgmtHandler(ks, &mockRevStore{}, &mockMgmtClientStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing auth header, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestManagement_ErrorFormat(t *testing.T) {
	ks := newTestKeyStore(t)
	h := newTestMgmtHandler(ks, &mockRevStore{}, &mockMgmtClientStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not valid JSON: %v", err)
	}
	if _, ok := body["error"]; !ok {
		t.Errorf("expected 'error' key in error response, got %v", body)
	}
}

// httprouterParams constructs a minimal httprouter.Params from k/v pairs.
func httprouterParams(kvs ...string) httprouter.Params {
	if len(kvs)%2 != 0 {
		panic(fmt.Sprintf("httprouterParams: odd number of args: %v", kvs))
	}
	ps := make(httprouter.Params, 0, len(kvs)/2)
	for i := 0; i < len(kvs); i += 2 {
		ps = append(ps, httprouter.Param{Key: kvs[i], Value: kvs[i+1]})
	}
	return ps
}
