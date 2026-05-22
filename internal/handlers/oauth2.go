package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	oautherrors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/auth"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/iabhishekrajput/anekdote-auth/internal/models"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
	"github.com/iabhishekrajput/anekdote-auth/web/ui"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/nosurf"
)

// oauth2OrgStore extends OrgMembershipReader with org name lookup for the access-denied page.
type oauth2OrgStore interface {
	auth.OrgMembershipReader
	GetOrgByID(ctx context.Context, id uuid.UUID) (*models.Org, error)
}

// IDTokenGenerator generates OIDC ID tokens for successful authorization_code exchanges.
// Implemented by *auth.JWTGenerator.
type IDTokenGenerator interface {
	GenerateIDToken(ctx context.Context, sub, aud, scope, accessToken string, expiry time.Duration) (string, error)
}

type OAuth2Handler struct {
	server       *server.Server
	sessionStore *redis.SessionStore
	revocStore   *redis.RevocationStore
	keyStore     *crypto.KeyStore
	orgStore     oauth2OrgStore  // optional; enables org membership check and friendly denial page at /authorize
	idTokenGen   IDTokenGenerator // optional; enables id_token in /token response when openid scope granted
}

func NewOAuth2Handler(srv *server.Server, sess *redis.SessionStore, rev *redis.RevocationStore, keys *crypto.KeyStore, orgStore oauth2OrgStore, idTokenGen IDTokenGenerator) *OAuth2Handler {
	h := &OAuth2Handler{
		server:       srv,
		sessionStore: sess,
		revocStore:   rev,
		keyStore:     keys,
		orgStore:     orgStore,
		idTokenGen:   idTokenGen,
	}

	h.server.SetUserAuthorizationHandler(h.userAuthorizeHandler)
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

// Authorize handles the initial redirect from the client
func (h *OAuth2Handler) Authorize(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// 1. Check if the user is logged in
	userID, err := h.sessionStore.GetUserFromSession(r)
	if err != nil || userID.String() == "00000000-0000-0000-0000-000000000000" {
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

	err = h.server.HandleAuthorizeRequest(w, r)
	if err != nil {
		slog.Error("Authorize Request Error", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (h *OAuth2Handler) userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	// 1. Double check user is logged in
	uid, err := h.sessionStore.GetUserFromSession(r)
	if err != nil || uid.String() == "00000000-0000-0000-0000-000000000000" {
		http.Redirect(w, r, "/login?req="+url.QueryEscape(r.URL.String()), http.StatusFound)
		return "", nil // returning empty userID stops go-oauth2 processing
	}

	// 2. Handle Consent Form Submission
	if r.Method == http.MethodPost {
		if r.FormValue("accept") == "true" {
			return uid.String(), nil
		}
		return "", oautherrors.ErrAccessDenied
	}

	clientID := r.FormValue("client_id")
	if clientID == "" {
		clientID = "Unknown Application"
	}

	// 3. Fetch client once — used for both org membership gate and domain display.
	type clientInfoIface interface{ GetDomain() string }
	var fetchedClient clientInfoIface
	if clientID != "Unknown Application" {
		if c, cErr := h.server.Manager.GetClient(r.Context(), clientID); cErr == nil && c != nil {
			fetchedClient = c
		}
	}

	// 4. For org-scoped clients: verify membership BEFORE rendering consent.
	if h.orgStore != nil && fetchedClient != nil {
		if oci, ok := fetchedClient.(*postgres.OrgClientInfo); ok && oci.OrgID != nil {
			userUUID, parseErr := uuid.Parse(uid.String())
			if parseErr != nil {
				slog.Error("authorize: session user ID is not a valid UUID", "uid", uid.String())
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return "", nil
			}
			role, memberErr := h.orgStore.GetMembership(r.Context(), *oci.OrgID, userUUID)
			if memberErr != nil || role == "" {
				orgName := ""
				if org, lookupErr := h.orgStore.GetOrgByID(r.Context(), *oci.OrgID); lookupErr == nil && org != nil {
					orgName = org.DisplayName
				}
				returnURL := r.URL.Query().Get("redirect_uri")
				_ = ui.OAuthAccessDeniedPage(clientID, orgName, returnURL).Render(r.Context(), w)
				return "", nil
			}
		}
	}

	// Parse requested scopes
	var requestedScopes []string
	if scope := r.FormValue("scope"); scope != "" {
		requestedScopes = strings.Split(scope, " ")
	} else {
		requestedScopes = []string{"openid", "profile"}
	}

	// Extract domain from registered redirect URI for trust badge display
	clientDomain := ""
	if fetchedClient != nil {
		if rawDomain := fetchedClient.GetDomain(); rawDomain != "" {
			if parsed, err := url.Parse(rawDomain); err == nil {
				clientDomain = parsed.Host
			}
		}
	}

	csrfToken := nosurf.Token(r)

	ui.ConsentPage(clientID, clientDomain, requestedScopes, csrfToken, "", "", "").Render(r.Context(), w)

	// Since we rendered the HTML response, we return empty userID and NO error
	// to tell go-oauth2 to halt and not overwrite the response.
	return "", nil
}

// Token handles the exchange of an Authorization Code (or Refresh Token) for an Access JWT.
// When the openid scope is granted and an IDTokenGenerator is configured, an id_token is
// injected into the response JSON.
func (h *OAuth2Handler) Token(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	rc := &responseCapture{ResponseWriter: w}
	err := h.server.HandleTokenRequest(rc, r)
	if err != nil {
		slog.Error("Token Request Error", "error", err)
	}
	if rc.statusCode == http.StatusOK && h.idTokenGen != nil {
		h.tryInjectIDToken(r.Context(), rc)
	}
	rc.flush()
}

// tryInjectIDToken parses the buffered token response and injects an id_token when the
// openid scope is present and the token has a user subject (not client_credentials).
func (h *OAuth2Handler) tryInjectIDToken(ctx context.Context, rc *responseCapture) {
	var resp map[string]interface{}
	if err := json.Unmarshal(rc.body.Bytes(), &resp); err != nil {
		return
	}
	scope, _ := resp["scope"].(string)
	scopeSet := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		scopeSet[s] = true
	}
	if !scopeSet["openid"] {
		return
	}
	accessToken, _ := resp["access_token"].(string)
	if accessToken == "" {
		return
	}
	// ParseUnverified to extract sub/aud/exp from our own just-issued token without re-verifying.
	parser := jwt.NewParser()
	parsed, _, parseErr := parser.ParseUnverified(accessToken, jwt.MapClaims{})
	if parseErr != nil {
		return
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return // client_credentials token — no user to describe
	}
	aud, _ := claims["aud"].(string)

	var expiry time.Duration
	if exp, ok := claims["exp"].(float64); ok {
		if remaining := time.Until(time.Unix(int64(exp), 0)); remaining > 0 {
			expiry = remaining
		}
	}
	if expiry <= 0 {
		expiry = time.Hour
	}

	idToken, err := h.idTokenGen.GenerateIDToken(ctx, sub, aud, scope, accessToken, expiry)
	if err != nil {
		slog.Warn("id_token generation failed; omitting from response", "error", err)
		return
	}
	resp["id_token"] = idToken

	newBody, err := json.Marshal(resp)
	if err != nil {
		return
	}
	rc.body.Reset()
	rc.body.Write(newBody) //nolint:errcheck
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
