package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	goredis "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/mailer"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
	"github.com/iabhishekrajput/anekdote-auth/internal/types"
	"github.com/iabhishekrajput/anekdote-auth/web/ui"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/nosurf"
)

const clientSecretFlashTTL = 60 * time.Second

var (
	slugRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

	reservedSlugs = map[string]bool{
		"accept": true, "admin": true, "api": true, "account": true,
		"login": true, "register": true, "token": true, "revoke": true,
		"authorize": true, "static": true, "clients": true, "members": true,
	}

	inviteKeyTTL = 24 * time.Hour
)

type invitePayload struct {
	OrgID        string `json:"org_id"`
	InviterID    string `json:"inviter_id"`
	Role         string `json:"role"`
	Email        string `json:"email"`
	InviterEmail string `json:"inviter_email"`
	OrgSlug      string `json:"org_slug"`
	OrgName      string `json:"org_name"`
}

type OrgHandler struct {
	orgStore     *postgres.OrgStore
	userStore    *postgres.UserStore
	clientStore  *postgres.ClientStore
	sessionStore *redis.SessionStore
	revocStore   *redis.RevocationStore
	mailer       *mailer.Mailer
	rdb          *goredis.Client
	appURL       string
}

func NewOrgHandler(
	orgStore *postgres.OrgStore,
	userStore *postgres.UserStore,
	clientStore *postgres.ClientStore,
	sessionStore *redis.SessionStore,
	mailSvc *mailer.Mailer,
	rdb *goredis.Client,
	revocStore *redis.RevocationStore,
	appURL string,
) *OrgHandler {
	return &OrgHandler{
		orgStore:     orgStore,
		userStore:    userStore,
		clientStore:  clientStore,
		sessionStore: sessionStore,
		revocStore:   revocStore,
		mailer:       mailSvc,
		rdb:          rdb,
		appURL:       appURL,
	}
}

// ListOrgs handles GET /account/orgs
func (h *OrgHandler) ListOrgs(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)

	orgs, err := h.orgStore.ListOrgsForUserFull(r.Context(), userID)
	if err != nil {
		http.Redirect(w, r, "/account?error="+url.QueryEscape("Failed to load organizations"), http.StatusFound)
		return
	}

	isAdmin, _ := r.Context().Value(types.IsAdminContextKey).(bool)
	csrfToken := nosurf.Token(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.OrgListPage(csrfToken, orgs, nil, isAdmin, r.URL.Query().Get("error"), r.URL.Query().Get("message")).Render(r.Context(), w)
}

// CreateOrg handles POST /account/orgs
func (h *OrgHandler) CreateOrg(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)

	slug := r.FormValue("slug")
	displayName := r.FormValue("display_name")

	if !slugRegex.MatchString(slug) {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Invalid slug: must be 3-63 lowercase letters, numbers, or hyphens"), http.StatusFound)
		return
	}
	if reservedSlugs[slug] {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Slug '"+slug+"' is reserved"), http.StatusFound)
		return
	}
	if displayName == "" {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Display name is required"), http.StatusFound)
		return
	}

	tx, err := h.orgStore.BeginTx(r.Context())
	if err != nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Server error"), http.StatusFound)
		return
	}
	defer tx.Rollback()

	org, err := h.orgStore.CreateOrgWithOwner(r.Context(), tx, slug, displayName, userID)
	if err != nil {
		msg := "Failed to create organization"
		if isUniqueViolation(err) {
			msg = "Slug '" + slug + "' is already taken"
		}
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Server error"), http.StatusFound)
		return
	}

	http.Redirect(w, r, "/account/orgs/"+org.Slug+"?message="+url.QueryEscape("Organization created"), http.StatusFound)
}

// AcceptInvite handles GET /account/orgs/accept?token=<T> (no RequireAuth)
func (h *OrgHandler) AcceptInvite(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Invalid invite link"), http.StatusFound)
		return
	}

	// Read invite from Redis
	raw, err := h.rdb.Get(r.Context(), "org:invite:"+token).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			http.Redirect(w, r, "/login?error="+url.QueryEscape("Invite link has expired or is invalid"), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Server error"), http.StatusFound)
		return
	}

	var inv invitePayload
	if err := json.Unmarshal([]byte(raw), &inv); err != nil {
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Invalid invite"), http.StatusFound)
		return
	}

	// Check if user is authenticated
	sessionUserID, sessionErr := h.sessionStore.GetUserFromSession(r)
	if sessionErr != nil || sessionUserID == uuid.Nil {
		// Not logged in — redirect to register with invite param preserved
		http.Redirect(w, r, "/register?invite="+url.QueryEscape(token), http.StatusFound)
		return
	}

	// Authenticated: verify the logged-in user's email matches the invite target
	currentUser, err := h.userStore.GetByID(sessionUserID)
	if err != nil || currentUser == nil {
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Session error"), http.StatusFound)
		return
	}
	if !strings.EqualFold(currentUser.Email, inv.Email) {
		logoutRedirect := "/login?req=" + url.QueryEscape("/join?token="+token)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		invIsAdmin, _ := r.Context().Value(types.IsAdminContextKey).(bool)
		_ = ui.InviteEmailMismatch(inv.Email, currentUser.Email, logoutRedirect, nosurf.Token(r), invIsAdmin).Render(r.Context(), w)
		return
	}

	orgID, err := uuid.Parse(inv.OrgID)
	if err != nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Invalid invite"), http.StatusFound)
		return
	}

	if err := h.orgStore.AddMember(r.Context(), orgID, sessionUserID, inv.Role, nil); err != nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Failed to join organization"), http.StatusFound)
		return
	}

	// Cleanup Redis
	h.rdb.Del(r.Context(), "org:invite:"+token)
	h.rdb.SRem(r.Context(), "org:invites:"+inv.OrgID, token)

	http.Redirect(w, r, "/account/orgs/"+inv.OrgSlug+"?message="+url.QueryEscape("You joined "+inv.OrgName), http.StatusFound)
}

// OrgDetail handles GET /account/orgs/:slug
func (h *OrgHandler) OrgDetail(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}

	role, err := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if err != nil || role == "" {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	members, err := h.orgStore.ListMembers(r.Context(), org.ID)
	if err != nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Failed to load members"), http.StatusFound)
		return
	}

	pending := h.loadPendingInvites(r.Context(), org.ID.String())
	isOwnerOrAdmin := role == "owner" || role == "admin"
	isAdmin, _ := r.Context().Value(types.IsAdminContextKey).(bool)
	csrfToken := nosurf.Token(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.OrgDetailPage(csrfToken, org, members, pending, userID.String(), isOwnerOrAdmin, isAdmin,
		r.URL.Query().Get("error"), r.URL.Query().Get("message")).Render(r.Context(), w)
}

// SendInvite handles POST /account/orgs/:slug/invites
func (h *OrgHandler) SendInvite(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	redirectBase := "/account/orgs/" + slug

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}

	role, _ := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if role != "owner" && role != "admin" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	email := r.FormValue("email")
	inviteRole := r.FormValue("role")
	if email == "" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Email is required"), http.StatusFound)
		return
	}
	if inviteRole != "member" && inviteRole != "admin" {
		inviteRole = "member"
	}

	inviter, _ := h.userStore.GetByID(userID)
	inviterEmail := "a member"
	if inviter != nil {
		inviterEmail = inviter.Email
	}

	token := uuid.New().String()
	inv := invitePayload{
		OrgID:        org.ID.String(),
		InviterID:    userID.String(),
		Role:         inviteRole,
		Email:        email,
		InviterEmail: inviterEmail,
		OrgSlug:      org.Slug,
		OrgName:      org.DisplayName,
	}
	data, _ := json.Marshal(inv)

	pipe := h.rdb.Pipeline()
	pipe.Set(r.Context(), "org:invite:"+token, string(data), inviteKeyTTL)
	pipe.SAdd(r.Context(), "org:invites:"+org.ID.String(), token)
	if _, err := pipe.Exec(r.Context()); err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Failed to create invite"), http.StatusFound)
		return
	}

	acceptURL := h.appURL + "/join?token=" + token
	if h.mailer != nil {
		if err := h.mailer.SendOrgInvite(r.Context(), email, org.DisplayName, inviterEmail, acceptURL); err != nil {
			h.rdb.Del(r.Context(), "org:invite:"+token)
			h.rdb.SRem(r.Context(), "org:invites:"+org.ID.String(), token)
			http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Failed to send invite email"), http.StatusFound)
			return
		}
	}

	http.Redirect(w, r, redirectBase+"?message="+url.QueryEscape("Invite sent to "+email), http.StatusFound)
}

// RevokeInvite handles POST /account/orgs/:slug/invites/:token/revoke
func (h *OrgHandler) RevokeInvite(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	token := ps.ByName("token")
	redirectBase := "/account/orgs/" + slug

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}

	role, _ := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if role != "owner" && role != "admin" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	h.rdb.Del(r.Context(), "org:invite:"+token)
	h.rdb.SRem(r.Context(), "org:invites:"+org.ID.String(), token)

	http.Redirect(w, r, redirectBase+"?message="+url.QueryEscape("Invite revoked"), http.StatusFound)
}

// ChangeMemberRole handles POST /account/orgs/:slug/members/:userID/role
func (h *OrgHandler) ChangeMemberRole(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	actorID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	targetIDStr := ps.ByName("userID")
	redirectBase := "/account/orgs/" + slug

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}

	actorRole, _ := h.orgStore.GetMembership(r.Context(), org.ID, actorID)
	if actorRole != "owner" && actorRole != "admin" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	targetID, err := uuid.Parse(targetIDStr)
	if err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Invalid user ID"), http.StatusFound)
		return
	}

	newRole := r.FormValue("role")
	if err := h.orgStore.UpdateMemberRole(r.Context(), org.ID, targetID, newRole); err != nil {
		if errors.Is(err, postgres.ErrInvalidRole) {
			http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Cannot set role to 'owner' via this form"), http.StatusFound)
			return
		}
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Failed to update role"), http.StatusFound)
		return
	}

	http.Redirect(w, r, redirectBase+"?message="+url.QueryEscape("Role updated"), http.StatusFound)
}

// RemoveMember handles POST /account/orgs/:slug/members/:userID/remove
func (h *OrgHandler) RemoveMember(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	actorID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	targetIDStr := ps.ByName("userID")
	redirectBase := "/account/orgs/" + slug

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}

	actorRole, _ := h.orgStore.GetMembership(r.Context(), org.ID, actorID)
	if actorRole != "owner" && actorRole != "admin" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	targetID, err := uuid.Parse(targetIDStr)
	if err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Invalid user ID"), http.StatusFound)
		return
	}

	if err := h.orgStore.RemoveMember(r.Context(), org.ID, targetID); err != nil {
		if errors.Is(err, postgres.ErrOwnerCannotBeRemoved) {
			http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Cannot remove the org owner"), http.StatusFound)
			return
		}
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Failed to remove member"), http.StatusFound)
		return
	}

	http.Redirect(w, r, redirectBase+"?message="+url.QueryEscape("Member removed"), http.StatusFound)
}

// storeSecretFlash saves a one-time secret in Redis for the POST→GET secret reveal flow.
func (h *OrgHandler) storeSecretFlash(ctx context.Context, clientID, secret string) error {
	return h.rdb.Set(ctx, "oauth:client-secret-flash:"+clientID, secret, clientSecretFlashTTL).Err()
}

// popSecretFlash atomically reads and deletes the flash secret (requires Redis >= 6.2.0).
func (h *OrgHandler) popSecretFlash(ctx context.Context, clientID string) string {
	val, err := h.rdb.GetDel(ctx, "oauth:client-secret-flash:"+clientID).Result()
	if err != nil {
		return ""
	}
	return val
}

// OrgClients handles GET /account/orgs/:slug/clients
func (h *OrgHandler) OrgClients(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}

	role, err := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if err != nil || role == "" {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	newClientID := r.URL.Query().Get("newClientID")
	newSecret := ""
	if newClientID != "" {
		newSecret = h.popSecretFlash(r.Context(), newClientID)
	}

	clients, _ := h.clientStore.ListOrgClients(r.Context(), org.ID)
	isOwnerOrAdmin := role == "owner" || role == "admin"
	isAdmin, _ := r.Context().Value(types.IsAdminContextKey).(bool)
	csrfToken := nosurf.Token(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.OrgClientsPage(csrfToken, org, isOwnerOrAdmin, isAdmin, clients, newClientID, newSecret,
		r.URL.Query().Get("error"), r.URL.Query().Get("message")).Render(r.Context(), w)
}

// RegisterClient handles POST /account/orgs/:slug/clients
func (h *OrgHandler) RegisterClient(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	redirectBase := "/account/orgs/" + slug + "/clients"

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}
	role, _ := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if role != "owner" && role != "admin" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	name := r.FormValue("name")
	redirectURI := r.FormValue("redirect_uri")
	isPublic := r.FormValue("public") == "on"

	if len(name) == 0 || len(name) > 255 {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Client name must be 1–255 characters"), http.StatusFound)
		return
	}
	if err := validateRedirectURI(redirectURI); err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}

	clientID, plainSecret, err := h.clientStore.CreateOrgClient(r.Context(), org.ID, name, redirectURI, isPublic)
	if err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Failed to register client"), http.StatusFound)
		return
	}

	if plainSecret != "" {
		if err := h.storeSecretFlash(r.Context(), clientID, plainSecret); err != nil {
			http.Redirect(w, r, redirectBase+"?newClientID="+url.QueryEscape(clientID)+"&error="+url.QueryEscape("Client created but secret could not be saved. Click Rotate Secret to reveal a new one."), http.StatusFound)
			return
		}
	}

	http.Redirect(w, r, redirectBase+"?newClientID="+url.QueryEscape(clientID), http.StatusFound)
}

// DeleteClient handles POST /account/orgs/:slug/clients/:clientID/delete
func (h *OrgHandler) DeleteClient(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	clientID := ps.ByName("clientID")
	redirectBase := "/account/orgs/" + slug + "/clients"

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}
	role, _ := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if role != "owner" && role != "admin" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	if err := h.clientStore.DeleteOrgClient(r.Context(), clientID, org.ID); err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Client not found"), http.StatusFound)
		return
	}

	// Best-effort: revoke all outstanding tokens issued to this client.
	// Errors are non-fatal — the client row is already deleted and tokens
	// will expire naturally within their TTL (~1 hour).
	if h.revocStore != nil {
		indexKey := "oauth:client-tokens:" + clientID
		if jtis, err := h.rdb.SMembers(r.Context(), indexKey).Result(); err == nil && len(jtis) > 0 {
			for _, jti := range jtis {
				h.revocStore.RevokeJTI(r.Context(), jti, time.Hour)
			}
			h.rdb.Del(r.Context(), indexKey)
		}
	}

	http.Redirect(w, r, redirectBase+"?message="+url.QueryEscape("Client deleted"), http.StatusFound)
}

// RotateClientSecret handles POST /account/orgs/:slug/clients/:clientID/rotate-secret
func (h *OrgHandler) RotateClientSecret(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	clientID := ps.ByName("clientID")
	redirectBase := "/account/orgs/" + slug + "/clients"

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}
	role, _ := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if role != "owner" && role != "admin" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	newSecret, err := h.clientStore.RotateOrgClientSecret(r.Context(), clientID, org.ID)
	if err != nil {
		msg := "Failed to rotate secret"
		if errors.Is(err, postgres.ErrClientNotFound) {
			msg = "Client not found"
		}
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}

	if err := h.storeSecretFlash(r.Context(), clientID, newSecret); err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Secret rotated but could not be displayed. Try rotating again."), http.StatusFound)
		return
	}

	http.Redirect(w, r, redirectBase+"?newClientID="+url.QueryEscape(clientID), http.StatusFound)
}

// loadPendingInvites reads org:invites:{orgID} SET and fetches each invite payload,
// lazily pruning stale tokens.
func (h *OrgHandler) loadPendingInvites(ctx context.Context, orgID string) []ui.OrgPendingMember {
	tokens, err := h.rdb.SMembers(ctx, "org:invites:"+orgID).Result()
	if err != nil {
		return nil
	}

	var pending []ui.OrgPendingMember
	for _, token := range tokens {
		raw, err := h.rdb.Get(ctx, "org:invite:"+token).Result()
		if err != nil {
			h.rdb.SRem(ctx, "org:invites:"+orgID, token)
			continue
		}
		var inv invitePayload
		if err := json.Unmarshal([]byte(raw), &inv); err != nil {
			h.rdb.SRem(ctx, "org:invites:"+orgID, token)
			continue
		}
		pending = append(pending, ui.OrgPendingMember{
			Email: inv.Email,
			Role:  inv.Role,
			Token: token,
		})
	}
	return pending
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "duplicate key") || strings.Contains(msg, "unique constraint")
}

func validateRedirectURI(rawURI string) error {
	if rawURI == "" {
		return errors.New("redirect URI is required")
	}
	u, err := url.Parse(rawURI)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("redirect URI must start with http:// or https://")
	}
	if strings.Contains(rawURI, "*") {
		return errors.New("redirect URI must not contain wildcards")
	}
	return nil
}
