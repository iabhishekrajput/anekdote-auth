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

func TestManagement_PutClaims_InvalidJSON(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader("{not valid json"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for invalid JSON, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_PutClaims_TooManyClaims(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)

	// Build 21 valid claims (max is 20)
	claimsJSON := `{"claims":[`
	for i := 0; i < 21; i++ {
		if i > 0 {
			claimsJSON += ","
		}
		claimsJSON += fmt.Sprintf(`{"key":"https://example.com/claim%d","type":"string","value":"v"}`, i)
	}
	claimsJSON += `]}`

	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(claimsJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for too many claims, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_PutClaims_InvalidType(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	body := `{"claims":[{"key":"https://example.com/tier","type":"array","value":"[1,2,3]"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for invalid type, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_PutClaims_InvalidNumber(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	body := `{"claims":[{"key":"https://example.com/tier","type":"number","value":"notanumber"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for invalid number, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_PutClaims_NonFiniteNumber(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	body := `{"claims":[{"key":"https://example.com/tier","type":"number","value":"NaN"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for NaN number, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_PutClaims_InvalidBoolean(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	body := `{"claims":[{"key":"https://example.com/tier","type":"boolean","value":"yes"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for invalid boolean, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_PutClaims_ValidBoolean(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	body := `{"claims":[{"key":"https://example.com/active","type":"boolean","value":"true"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid boolean, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(store.saved) != 1 || store.saved[0].ValueType != "boolean" || store.saved[0].Value != "true" {
		t.Errorf("expected saved boolean claim, got %+v", store.saved)
	}
}

func TestManagement_PutClaims_ValidNumber(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	body := `{"claims":[{"key":"https://example.com/count","type":"number","value":"42"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid number, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(store.saved) != 1 || store.saved[0].ValueType != "number" {
		t.Errorf("expected saved number claim, got %+v", store.saved)
	}
}

func TestManagement_PutClaims_InvalidDestinations(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	body := `{"claims":[{"key":"https://example.com/tier","type":"string","value":"v","destinations":"nowhere"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for invalid destinations, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_PutClaims_MultiDestinations(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	// access_token,id_token should be valid (sorted form)
	body := `{"claims":[{"key":"https://example.com/tier","type":"string","value":"v","destinations":"id_token,access_token"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for multi-destination, got %d: %s", rr.Code, rr.Body.String())
	}
	// Destinations should be sorted canonically
	if len(store.saved) != 1 || store.saved[0].Destinations != "access_token,id_token" {
		t.Errorf("expected canonical sorted destinations, got %+v", store.saved)
	}
}

func TestManagement_PutClaims_KeyTooLong(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	// Build a key that's 101 characters after "https://example.com/"
	longKey := "https://example.com/" + strings.Repeat("a", 82) // 20+81=101 total
	body := `{"claims":[{"key":"` + longKey + `","type":"string","value":"v"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for key too long, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_PutClaims_StoreError(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID, err: fmt.Errorf("db unavailable")}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	// First call (GetClientOrgID) will fail — triggers 404 not found path
	body := `{"claims":[{"key":"https://example.com/tier","type":"string","value":"v"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	// Returns 403 (not 404) to prevent client ID enumeration.
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 when store.GetClientOrgID errors (anti-enumeration), got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_PutClaims_SetClaimsAdminError(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	// OrgID lookup succeeds but SetCustomClaimsAdmin fails
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	// We need a store that succeeds on GetClientOrgID but fails on SetCustomClaimsAdmin.
	// Use a dedicated mock.
	failingStore := &failingSetStore{orgID: &orgID}
	h2 := newTestMgmtHandler(ks, &mockRevStore{}, failingStore)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	body := `{"claims":[{"key":"https://example.com/tier","type":"string","value":"v"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h2.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when SetCustomClaimsAdmin errors, got %d: %s", rr.Code, rr.Body.String())
	}
	_ = h // suppress unused
}

type failingSetStore struct {
	orgID *string
}

func (f *failingSetStore) GetClientOrgID(_ context.Context, _ string) (*string, error) {
	return f.orgID, nil
}
func (f *failingSetStore) ListCustomClaims(_ context.Context, _ string) ([]postgres.ClaimDefinition, error) {
	return nil, nil
}
func (f *failingSetStore) SetCustomClaimsAdmin(_ context.Context, _ string, _ []postgres.ClaimDefinition) error {
	return fmt.Errorf("db write error")
}

func TestManagement_GetClaims_ClientNotFound(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	// orgID is returned but clientOrgID is nil (no org binding)
	store := &mockMgmtClientStore{orgID: nil} // GetClientOrgID returns nil, nil → "client not found"
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "read:client_claims", testMgmtAud, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	// Returns 403 (not 404) to prevent client ID enumeration.
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for client not found (anti-enumeration), got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_GetClaims_NoOrgIDInToken(t *testing.T) {
	ks := newTestKeyStore(t)
	store := &mockMgmtClientStore{}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	// Token with empty org_id — checkOwnership returns errOwnershipDenied with empty tokenOrgID
	token := signMgmtToken(t, ks, "", "read:client_claims", testMgmtAud, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 when token has no org_id, got %d: %s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	json.NewDecoder(rr.Body).Decode(&body)
	if body["error"] != "management API requires a service account token with org_id claim" {
		t.Errorf("unexpected error message: %v", body)
	}
}

func TestManagement_GetClaims_StoreError(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID, err: fmt.Errorf("db error")}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "read:client_claims", testMgmtAud, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	// Returns 403 (not 404) to prevent client ID enumeration.
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 when GetClientOrgID errors (anti-enumeration), got %d: %s", rr.Code, rr.Body.String())
	}
}

type listFailStore struct {
	orgID *string
}

func (f *listFailStore) GetClientOrgID(_ context.Context, _ string) (*string, error) {
	return f.orgID, nil
}
func (f *listFailStore) ListCustomClaims(_ context.Context, _ string) ([]postgres.ClaimDefinition, error) {
	return nil, fmt.Errorf("list db error")
}
func (f *listFailStore) SetCustomClaimsAdmin(_ context.Context, _ string, _ []postgres.ClaimDefinition) error {
	return nil
}

func TestManagement_GetClaims_ListStoreError(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &listFailStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "read:client_claims", testMgmtAud, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ListCustomClaims errors, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_GetClaims_RevocationStoreError(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	// rev store errors → fail closed → 401
	h := newTestMgmtHandler(ks, &mockRevStore{err: fmt.Errorf("redis down")}, store)

	token := signMgmtToken(t, ks, orgID, "read:client_claims", testMgmtAud, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (fail closed) when revocation store errors, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_BearerPrefixOnly(t *testing.T) {
	ks := newTestKeyStore(t)
	h := newTestMgmtHandler(ks, &mockRevStore{}, &mockMgmtClientStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	req.Header.Set("Authorization", "Bearer ")
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for 'Bearer ' with no token, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_NonBearerScheme(t *testing.T) {
	ks := newTestKeyStore(t)
	h := newTestMgmtHandler(ks, &mockRevStore{}, &mockMgmtClientStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for Basic auth scheme, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_PutClaims_WrongScope(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	// Token has read scope but PUT requires update scope
	token := signMgmtToken(t, ks, orgID, "read:client_claims", testMgmtAud, time.Hour)
	body := `{"claims":[]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong scope on PUT, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_WWWAuthenticate_On401(t *testing.T) {
	ks := newTestKeyStore(t)
	h := newTestMgmtHandler(ks, &mockRevStore{}, &mockMgmtClientStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/c1/claims", nil)
	rr := httptest.NewRecorder()

	h.GetClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	// RFC 6750: 401 must carry WWW-Authenticate with error code.
	wwwAuth := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "Bearer") || !strings.Contains(wwwAuth, "error=") {
		t.Errorf("expected RFC 6750 WWW-Authenticate with error=, got %q", wwwAuth)
	}
}

func TestManagement_PutClaims_EmptyClaimsArray(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	store := &mockMgmtClientStore{orgID: &orgID}
	h := newTestMgmtHandler(ks, &mockRevStore{}, store)

	token := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)
	body := `{"claims":[]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/c1/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.PutClientClaims(rr, req, httprouterParams("id", "c1"))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty claims (replace-all with zero), got %d: %s", rr.Code, rr.Body.String())
	}
	var respBody map[string]any
	json.NewDecoder(rr.Body).Decode(&respBody)
	if v, _ := respBody["count"].(float64); v != 0 {
		t.Errorf("expected count=0, got %v", respBody["count"])
	}
}

func TestManagement_ScopeHasWord(t *testing.T) {
	cases := []struct {
		scope, target string
		want          bool
	}{
		{"read:client_claims update:client_claims", "read:client_claims", true},
		{"read:client_claims", "read", false},
		{"", "read:client_claims", false},
		{"read:client_claims", "", false},
		{"openid profile email", "email", true},
		{"openid profile email_extra", "email", false},
		{"openid email_extra", "email", false},
	}
	for _, c := range cases {
		got := scopeHasWord(c.scope, c.target)
		if got != c.want {
			t.Errorf("scopeHasWord(%q, %q) = %v, want %v", c.scope, c.target, got, c.want)
		}
	}
}

// TestManagement_GetClaims_DuplicateClaimKey verifies that PUT with duplicate keys returns 422.
func TestManagement_PutClaims_DuplicateKey(t *testing.T) {
	ks := newTestKeyStore(t)
	orgID := "org-abc"
	clientID := "cli_test"
	h := newTestMgmtHandler(ks, &mockRevStore{}, &mockMgmtClientStore{orgID: &orgID})
	tok := signMgmtToken(t, ks, orgID, "update:client_claims", testMgmtAud, time.Hour)

	body := `{"claims":[{"key":"https://example.com/role","type":"string","value":"a"},{"key":"https://example.com/role","type":"string","value":"b"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/clients/"+clientID+"/claims", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PutClientClaims(rr, req, httprouterParams("id", clientID))

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("duplicate key: expected 422, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestManagement_NormalizeDestinationsHandler(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"token", "token"},
		{"access_token", "access_token"},
		{"id_token,access_token", "access_token,id_token"},
		{"access_token,id_token", "access_token,id_token"},
		{"userinfo,id_token,access_token", "access_token,id_token,userinfo"},
		{"  access_token , id_token  ", "access_token,id_token"},
		{"", ""},
	}
	for _, c := range cases {
		got := normalizeDestinationsHandler(c.input)
		if got != c.want {
			t.Errorf("normalizeDestinationsHandler(%q) = %q, want %q", c.input, got, c.want)
		}
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
