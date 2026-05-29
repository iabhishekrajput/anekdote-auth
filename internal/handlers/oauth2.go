package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	oautherrors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/golang-jwt/jwt/v5"
	"github.com/iabhishekrajput/anekdote-auth/internal/auth"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/iabhishekrajput/anekdote-auth/internal/models"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
	"github.com/iabhishekrajput/anekdote-auth/web/ui"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/nosurf"
)

// authCodeTTL mirrors the OAuth2 server's authorization code expiry (server.go).
// The nonce is keyed by auth code and must not outlive it.
const authCodeTTL = 10 * time.Minute

// oauth2OrgStore extends OrgMembershipReader with org name lookup for the access-denied page.
type oauth2OrgStore interface {
	auth.OrgMembershipReader
	GetOrgByID(ctx context.Context, id string) (*models.Org, error)
}

// oauth2ClientGrantStore fetches multi-org grants for a client.
type oauth2ClientGrantStore interface {
	ListUserEligibleOrgsForClient(ctx context.Context, clientID string, userID string) ([]*postgres.ClientGrantItem, error)
}

// IDTokenGenerator generates OIDC ID tokens for successful authorization_code exchanges.
// Implemented by *auth.JWTGenerator.
type IDTokenGenerator interface {
	GenerateIDToken(ctx context.Context, sub, aud, scope, accessToken string, expiry time.Duration, nonce string) (string, error)
}

// OAuth2RevocationStore handles JWT revocation.
type OAuth2RevocationStore interface {
	RevokeJTI(ctx context.Context, jti string, duration time.Duration) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// OAuth2NonceStore handles OIDC nonce binding.
type OAuth2NonceStore interface {
	StoreNonce(ctx context.Context, code, nonce string, ttl time.Duration) error
	ConsumeNonce(ctx context.Context, code string) (string, error)
}

type OAuth2Handler struct {
	server       *server.Server
	sessionStore *redis.SessionStore
	revocStore   OAuth2RevocationStore
	nonceStore   OAuth2NonceStore
	keyStore     *crypto.KeyStore
	orgStore     oauth2OrgStore         // optional; enables org membership check and friendly denial page at /authorize
	grantStore   oauth2ClientGrantStore // optional; enables multi-org client grants
	idTokenGen   IDTokenGenerator       // optional; enables id_token in /token response when openid scope granted
}

func NewOAuth2Handler(srv *server.Server, sess *redis.SessionStore, rev OAuth2RevocationStore, keys *crypto.KeyStore, orgStore oauth2OrgStore, grantStore oauth2ClientGrantStore, idTokenGen IDTokenGenerator) *OAuth2Handler {
	h := &OAuth2Handler{
		server:       srv,
		sessionStore: sess,
		revocStore:   rev,
		keyStore:     keys,
		orgStore:     orgStore,
		grantStore:   grantStore,
		idTokenGen:   idTokenGen,
	}
	if ns, ok := rev.(OAuth2NonceStore); ok {
		h.nonceStore = ns
	}

	h.server.SetUserAuthorizationHandler(h.userAuthorizeHandler)
	return h
}

func (h *OAuth2Handler) WithNonceStore(store OAuth2NonceStore) *OAuth2Handler {
	h.nonceStore = store
	return h
}

// responseCapture buffers the status code and body from go-oauth2 so we can
// inject id_token before the response reaches the client.
type responseCapture struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	if rc.statusCode == 0 {
		rc.statusCode = http.StatusOK
	}
	return rc.body.Write(b)
}

func (rc *responseCapture) flush() {
	if rc.statusCode != 0 {
		// Remove Content-Length so net/http recomputes it after body modification.
		rc.ResponseWriter.Header().Del("Content-Length")
		rc.ResponseWriter.WriteHeader(rc.statusCode)
	}
	rc.ResponseWriter.Write(rc.body.Bytes()) //nolint:errcheck
}

// authCodeCapture buffers the authorize response so we can persist the OIDC nonce
// before the redirect reaches the client, eliminating any store-before-redirect race.
type authCodeCapture struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
	code       string
}

func (ac *authCodeCapture) WriteHeader(status int) {
	ac.statusCode = status
	if status == http.StatusFound {
		loc := ac.ResponseWriter.Header().Get("Location")
		if u, err := url.Parse(loc); err == nil {
			ac.code = u.Query().Get("code")
		}
	}
}

func (ac *authCodeCapture) Write(b []byte) (int, error) {
	if ac.statusCode == 0 {
		ac.statusCode = http.StatusOK
	}
	return ac.body.Write(b)
}

func (ac *authCodeCapture) flush() {
	if ac.statusCode != 0 {
		ac.ResponseWriter.Header().Del("Content-Length")
		ac.ResponseWriter.WriteHeader(ac.statusCode)
	}
	ac.ResponseWriter.Write(ac.body.Bytes()) //nolint:errcheck
}

// Authorize handles the initial redirect from the client
func (h *OAuth2Handler) Authorize(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// 1. Check if the user is logged in
	userID, err := h.sessionStore.GetUserFromSession(r)
	if err != nil || userID == "" {
		// Store the current URL to redirect back after login
		loginURL := "/login?req=" + url.QueryEscape(r.URL.String())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// 2. Parse the request form so go-oauth2 can process both URL query params and POST values
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	nonce := r.FormValue("nonce")
	ac := &authCodeCapture{ResponseWriter: w}
	err = h.server.HandleAuthorizeRequest(ac, r)
	if err != nil {
		slog.Error("Authorize Request Error", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Store nonce BEFORE flushing the redirect. This eliminates the race where a fast
	// client exchanges the code before the nonce is persisted.
	if nonce != "" && ac.code != "" && h.nonceStore != nil {
		if storeErr := h.nonceStore.StoreNonce(r.Context(), ac.code, nonce, authCodeTTL); storeErr != nil {
			slog.Error("authorize: failed to store nonce; aborting redirect", "error", storeErr)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
	}
	ac.flush()
}

func (h *OAuth2Handler) userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	// 1. Double check user is logged in
	uid, err := h.sessionStore.GetUserFromSession(r)
	if err != nil || uid == "" {
		http.Redirect(w, r, "/login?req="+url.QueryEscape(r.URL.String()), http.StatusFound)
		return "", nil // returning empty userID stops go-oauth2 processing
	}

	clientID := r.FormValue("client_id")
	if clientID == "" {
		clientID = "Unknown Application"
	}

	// 2. Handle Consent Form Submission (POST with accept/reject).
	if r.Method == http.MethodPost {
		if r.FormValue("accept") != "true" {
			return "", oautherrors.ErrAccessDenied
		}
		// If a specific org was selected from the picker, encode it in the returned userID.
		// The JWT generator will split on "|" and validate membership at token time.
		if selectedOrg := r.FormValue("selected_org_id"); selectedOrg != "" {
			return uid + "|" + selectedOrg, nil
		}
		return uid, nil
	}

	// 3. Fetch client once — used for org gate, domain display, and name on consent screen.
	type clientInfoIface interface {
		GetDomain() string
		GetName() string
	}
	var fetchedClient clientInfoIface
	if clientID != "Unknown Application" {
		if c, cErr := h.server.Manager.GetClient(r.Context(), clientID); cErr == nil && c != nil {
			if ci, ok := c.(clientInfoIface); ok {
				fetchedClient = ci
			}
		}
	}

	// Resolve display name early so access-denied pages can use it.
	clientName := clientID
	if fetchedClient != nil {
		if n := fetchedClient.GetName(); n != "" {
			clientName = n
		}
	}

	// 4. Determine eligible orgs:
	//    - Legacy single-org client (OrgID set): use existing single-org membership check.
	//    - Multi-org client (OrgID nil, grantStore set): query client_org_grants.
	returnURL := r.URL.Query().Get("redirect_uri")
	var eligibleOrgs []ui.OrgOption
	var singleOrgID *string // set when exactly 1 org matches

	if h.orgStore != nil && fetchedClient != nil {
		if oci, ok := fetchedClient.(*postgres.OrgClientInfo); ok {
			if oci.OrgID != nil {
				// Legacy path: single-org client.
				role, memberErr := h.orgStore.GetMembership(r.Context(), *oci.OrgID, uid)
				if memberErr != nil || role == "" {
					orgName := ""
					if org, lookupErr := h.orgStore.GetOrgByID(r.Context(), *oci.OrgID); lookupErr == nil && org != nil {
						orgName = org.DisplayName
					}
					_ = ui.OAuthAccessDeniedPage(clientName, orgName, returnURL).Render(r.Context(), w)
					return "", nil
				}
				// Single-org: proceed without picker, encode the org.
				singleOrgID = oci.OrgID
			} else if h.grantStore != nil {
				// Multi-org path: find all orgs this client is granted to that the user belongs to.
				grants, grantErr := h.grantStore.ListUserEligibleOrgsForClient(r.Context(), clientID, uid)
				if grantErr != nil {
					slog.Error("authorize: failed to list eligible orgs", "client_id", clientID, "error", grantErr)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return "", nil
				}
				if len(grants) == 0 {
					_ = ui.OAuthAccessDeniedNoGrant(clientName, returnURL).Render(r.Context(), w)
					return "", nil
				}
				if len(grants) == 1 {
					orgID := grants[0].OrgID
					singleOrgID = &orgID
				} else {
					for _, g := range grants {
						eligibleOrgs = append(eligibleOrgs, ui.OrgOption{
							ID:   g.OrgID,
							Name: g.OrgName,
							Slug: g.OrgSlug,
						})
					}
				}
			}
		}
	}

	// If exactly one org matched (legacy or single-grant), no picker needed.
	// Encode the org so the JWT generator uses it; no user interaction required.
	if singleOrgID != nil && len(eligibleOrgs) == 0 {
		// We need to show consent but auto-select the org. Pass it as a hidden field.
		eligibleOrgs = nil // no picker shown; selectedOrgID will be set as hidden
	}

	// Parse requested scopes
	var requestedScopes []string
	if scope := r.FormValue("scope"); scope != "" {
		requestedScopes = strings.Split(scope, " ")
	} else {
		requestedScopes = []string{"openid", "profile"}
	}

	// Extract domain from the registered client for the trust badge.
	clientDomain := ""
	if fetchedClient != nil {
		if rawDomain := fetchedClient.GetDomain(); rawDomain != "" {
			if parsed, err := url.Parse(rawDomain); err == nil {
				clientDomain = parsed.Host
			}
		}
	}

	selectedOrgID := ""
	if singleOrgID != nil {
		selectedOrgID = *singleOrgID
	}

	csrfToken := nosurf.Token(r)
	ui.ConsentPage(clientName, clientDomain, requestedScopes, csrfToken, "", "", "", eligibleOrgs, selectedOrgID).Render(r.Context(), w)

	// Return empty userID to halt go-oauth2 — we rendered the page ourselves.
	return "", nil
}

// Token handles the exchange of an Authorization Code (or Refresh Token) for an Access JWT.
// When the openid scope is granted and an IDTokenGenerator is configured, an id_token is
// injected into the response JSON.
func (h *OAuth2Handler) Token(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// Capture the authorization code before HandleTokenRequest consumes the body.
	// r.FormValue parses and caches the form; subsequent calls by go-oauth2 reuse the cache.
	code := r.FormValue("code")
	rc := &responseCapture{ResponseWriter: w}
	err := h.server.HandleTokenRequest(rc, r)
	if err != nil {
		slog.Error("Token Request Error", "error", err)
	}
	if rc.statusCode == http.StatusOK && h.idTokenGen != nil {
		if err := h.tryInjectIDToken(r.Context(), rc, code); err != nil {
			slog.Error("id_token injection failed; returning server error", "error", err)
			rc.statusCode = http.StatusInternalServerError
			rc.body.Reset()
			rc.body.Write([]byte(`{"error":"server_error","error_description":"internal server error"}`)) //nolint:errcheck
		}
	}
	rc.flush()
}

// tryInjectIDToken parses the buffered token response and injects an id_token when the
// openid scope is present and the token has a user subject (not client_credentials).
// code is the authorization code from the request; used to retrieve a stored nonce.
// Returns an error if nonce retrieval fails (fail-closed: a Redis error on the nonce
// store aborts id_token generation rather than silently omitting the nonce).
func (h *OAuth2Handler) tryInjectIDToken(ctx context.Context, rc *responseCapture, code string) error {
	var resp map[string]interface{}
	if err := json.Unmarshal(rc.body.Bytes(), &resp); err != nil {
		return nil
	}
	scope, _ := resp["scope"].(string)
	scopeSet := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		scopeSet[s] = true
	}
	if !scopeSet["openid"] {
		return nil
	}
	accessToken, _ := resp["access_token"].(string)
	if accessToken == "" {
		return nil
	}
	// ParseUnverified to extract sub/aud/exp from our own just-issued token without re-verifying.
	parser := jwt.NewParser()
	parsed, _, parseErr := parser.ParseUnverified(accessToken, jwt.MapClaims{})
	if parseErr != nil {
		return nil
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}
	sub, _ := claims["sub"].(string)
	aud, _ := claims["aud"].(string)
	if sub == "" || sub == aud {
		return nil // client_credentials token — no user to describe
	}

	var expiry time.Duration
	if exp, ok := claims["exp"].(float64); ok {
		if remaining := time.Until(time.Unix(int64(exp), 0)); remaining > 0 {
			expiry = remaining
		}
	}
	if expiry <= 0 {
		expiry = time.Hour
	}

	var nonce string
	if code != "" && h.nonceStore != nil {
		n, err := h.nonceStore.ConsumeNonce(ctx, code)
		if err != nil {
			return fmt.Errorf("nonce retrieval failed: %w", err)
		}
		nonce = n
	}

	idToken, err := h.idTokenGen.GenerateIDToken(ctx, sub, aud, scope, accessToken, expiry, nonce)
	if err != nil {
		slog.Warn("id_token generation failed; omitting from response", "error", err)
		return nil
	}
	resp["id_token"] = idToken

	newBody, err := json.Marshal(resp)
	if err != nil {
		return nil
	}
	rc.body.Reset()
	rc.body.Write(newBody) //nolint:errcheck
	return nil
}

// Revoke handles invalidating a specific JWT by its JTI blocklist, or deleting a refresh token
func (h *OAuth2Handler) Revoke(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	tokenStr := r.FormValue("token")
	if tokenStr == "" {
		http.Error(w, "missing token parameter", http.StatusBadRequest)
		return
	}

	tokenTypeHint := r.FormValue("token_type_hint")

	// RFC 7009: The server responds with HTTP 200 OK regardless of whether the token
	// was valid/found or not, to prevent leaking information. Only 500s or 400s on bad requests.

	// Try JWT parsing first (Access Tokens) unless explicitly hinted heavily otherwise
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		return h.keyStore.PublicKey, nil
	}, jwt.WithoutClaimsValidation(), jwt.WithValidMethods([]string{"RS256"}))
	if err == nil && token.Valid {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if jti, ok := claims["jti"].(string); ok && jti != "" {
				// Blocklist the JTI in Redis
				_ = h.revocStore.RevokeJTI(r.Context(), jti, 10*time.Hour)
				w.WriteHeader(http.StatusOK)
				return
			}
		}
	}

	// If parsing as JWT failed, or it lacked a JTI, it's likely a Refresh Token (which our generator makes as UUIDs).
	// Or maybe the token type hint specifically suggests it.
	if tokenTypeHint == "refresh_token" || err != nil {
		_ = h.server.Manager.RemoveRefreshToken(r.Context(), tokenStr)
	} else {
		// Just to be safe, try removing it as both if neither hint nor JWT structural match worked.
		_ = h.server.Manager.RemoveAccessToken(r.Context(), tokenStr)
		_ = h.server.Manager.RemoveRefreshToken(r.Context(), tokenStr)
	}

	w.WriteHeader(http.StatusOK)
}
