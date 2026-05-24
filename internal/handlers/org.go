package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	goredis "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/mailer"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis/redisutil"
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
	auditStore   *postgres.AuditStore
	mailer       *mailer.Mailer
	rdb          *goredis.Client
	encKey       []byte // AES-256 key for client secret flash encryption
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
	auditStore *postgres.AuditStore,
	encKey []byte,
	appURL string,
) *OrgHandler {
	return &OrgHandler{
		orgStore:     orgStore,
		userStore:    userStore,
		clientStore:  clientStore,
		sessionStore: sessionStore,
		revocStore:   revocStore,
		auditStore:   auditStore,
		mailer:       mailSvc,
		rdb:          rdb,
		encKey:       encKey,
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
	if err != nil || role == "" || role == "member" {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	members, err := h.orgStore.ListMembers(r.Context(), org.ID)
	if err != nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Failed to load members"), http.StatusFound)
		return
	}

	pending := h.loadPendingInvites(r.Context(), org.ID.String())
	canEdit := role == "owner" || role == "admin"
	isOwner := role == "owner"

	var grantedClients []*postgres.OrgGrantItem
	if isOwner {
		grantedClients, _ = h.clientStore.ListOrgGrantedClients(r.Context(), org.ID)
	}

	// Outgoing pending grant requests this org has made (org B's view of its own requests).
	outgoingRequests, _ := h.clientStore.ListGrantRequestsForOrg(r.Context(), org.ID)

	isAdmin, _ := r.Context().Value(types.IsAdminContextKey).(bool)
	csrfToken := nosurf.Token(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.OrgDetailPage(csrfToken, org, members, pending, userID.String(), canEdit, isOwner, isAdmin,
		grantedClients, outgoingRequests, r.URL.Query().Get("error"), r.URL.Query().Get("message")).Render(r.Context(), w)
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

	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	inviteRole := r.FormValue("role")
	if email == "" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Email is required"), http.StatusFound)
		return
	}
	if inviteRole != "member" && inviteRole != "viewer" && inviteRole != "admin" {
		inviteRole = "member"
	}

	targetUser, err := h.userStore.GetByEmail(email)
	if err != nil && !errors.Is(err, postgres.ErrUserNotFound) {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Server error, please try again"), http.StatusFound)
		return
	}
	if targetUser != nil {
		memberRole, _ := h.orgStore.GetMembership(r.Context(), org.ID, targetUser.ID)
		if memberRole != "" {
			http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("user is already a member of this organization"), http.StatusFound)
			return
		}
	}

	for _, p := range h.loadPendingInvites(r.Context(), org.ID.String()) {
		if p.Email == email {
			http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("an invitation is already pending for this email"), http.StatusFound)
			return
		}
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

	msg := "Role updated"
	if target, err := h.userStore.GetByID(targetID); err == nil {
		msg = "Changed " + target.Email + " to " + newRole
	}
	http.Redirect(w, r, redirectBase+"?message="+url.QueryEscape(msg), http.StatusFound)
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

// storeSecretFlash encrypts secret with AES-256-GCM and stores it in Redis.
// The plaintext never appears in Redis — only ciphertext with a 60-second TTL.
func (h *OrgHandler) storeSecretFlash(ctx context.Context, clientID, secret string) error {
	ct, err := redisutil.Encrypt(h.encKey, secret)
	if err != nil {
		return err
	}
	return h.rdb.Set(ctx, "oauth:client-secret-flash:"+clientID, ct, clientSecretFlashTTL).Err()
}

// popSecretFlash atomically reads, deletes, and decrypts the flash secret.
func (h *OrgHandler) popSecretFlash(ctx context.Context, clientID string) string {
	ct, err := h.rdb.GetDel(ctx, "oauth:client-secret-flash:"+clientID).Result()
	if err != nil {
		return ""
	}
	plain, err := redisutil.Decrypt(h.encKey, ct)
	if err != nil {
		slog.Warn("org: failed to decrypt client secret flash", "client_id", clientID, "err", err)
		return ""
	}
	return plain
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
	if err != nil || role == "" || role == "member" {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	newClientID := r.URL.Query().Get("newClientID")
	newSecret := ""
	if newClientID != "" {
		newSecret = h.popSecretFlash(r.Context(), newClientID)
	}

	clients, _ := h.clientStore.ListOrgClients(r.Context(), org.ID)

	// For multi-org clients owned by this org, batch-load pending requests and connected orgs.
	for _, c := range clients {
		if c.IsGlobal && c.IsOwner {
			c.PendingRequests, _ = h.clientStore.ListGrantRequestsForClient(r.Context(), c.ID)
			c.ConnectedOrgs, _ = h.clientStore.ListOrgsGrantedClient(r.Context(), c.ID)
		}
	}

	canEdit := role == "owner" || role == "admin"
	isAdmin, _ := r.Context().Value(types.IsAdminContextKey).(bool)
	csrfToken := nosurf.Token(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.OrgClientsPage(csrfToken, org, canEdit, isAdmin, clients, newClientID, newSecret,
		r.URL.Query().Get("error"), r.URL.Query().Get("message")).Render(r.Context(), w)
}

// ExploreApps handles GET /account/orgs/:slug/explore
func (h *OrgHandler) ExploreApps(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}

	role, err := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if err != nil || role == "" || role == "member" {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	clients, err := h.clientStore.ListDiscoverableClients(r.Context(), org.ID)
	if err != nil {
		slog.Error("ExploreApps: failed to list clients", "error", err)
		http.Redirect(w, r, "/account/orgs/"+org.Slug+"?error="+url.QueryEscape("Failed to load apps"), http.StatusFound)
		return
	}

	canEdit := role == "owner" || role == "admin"
	isOwner := role == "owner"
	isAdmin, _ := r.Context().Value(types.IsAdminContextKey).(bool)
	csrfToken := nosurf.Token(r)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.OrgExploreAppsPage(csrfToken, org, clients, canEdit, isOwner, isAdmin,
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
	isMultiOrg := r.FormValue("multi_org") == "on"

	if len(name) == 0 || len(name) > 255 {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Client name must be 1–255 characters"), http.StatusFound)
		return
	}
	if err := validateRedirectURI(redirectURI); err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}

	clientID, plainSecret, err := h.clientStore.CreateOrgClient(r.Context(), org.ID, name, redirectURI, isPublic, isMultiOrg)
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
		if errors.Is(err, postgres.ErrGlobalClientUsesGrant) {
			// Multi-org client: remove this org's grant instead of deleting the client row.
			if rErr := h.clientStore.RevokeOrgAccess(r.Context(), clientID, org.ID); rErr != nil {
				http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Failed to remove client"), http.StatusFound)
				return
			}
			// Best-effort token revocation for this org's grants.
			if h.rdb != nil && h.revocStore != nil {
				indexKey := "oauth:user-org-tokens:*:" + org.ID.String()
				if keys, kErr := h.rdb.Keys(r.Context(), indexKey).Result(); kErr == nil {
					for _, key := range keys {
						if jtis, err := h.rdb.SMembers(r.Context(), key).Result(); err == nil {
							for _, jti := range jtis {
								h.revocStore.RevokeJTI(r.Context(), jti, time.Hour)
							}
						}
					}
				}
			}
			http.Redirect(w, r, redirectBase+"?message="+url.QueryEscape("Removed from this org"), http.StatusFound)
			return
		}
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

	// Notify owner org's admins that the secret was rotated.
	if h.mailer != nil {
		orgDisplayName := org.DisplayName
		go func() {
			emails, err := h.userStore.ListOrgAdmins(context.Background(), org.ID)
			if err != nil || len(emails) == 0 {
				return
			}
			clientName, _ := h.clientStore.GetClientName(context.Background(), clientID)
			if clientName == "" {
				clientName = clientID
			}
			if err := h.mailer.SendSecretRotated(context.Background(), emails, clientName, orgDisplayName); err != nil {
				slog.Error("secret rotated email failed", "client", clientID, "err", err)
			}
		}()
	}

	http.Redirect(w, r, redirectBase+"?newClientID="+url.QueryEscape(clientID), http.StatusFound)
}

// TransferOwnershipAndLeave handles POST /account/orgs/:slug/transfer-ownership
func (h *OrgHandler) TransferOwnershipAndLeave(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	redirectBase := "/account/orgs/" + slug

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}

	role, err := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if err != nil || role != "owner" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	newOwnerIDStr := r.FormValue("new_owner_id")
	newOwnerID, err := uuid.Parse(newOwnerIDStr)
	if err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Invalid user ID"), http.StatusFound)
		return
	}

	if newOwnerID == userID {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Cannot transfer to yourself"), http.StatusFound)
		return
	}

	if err := h.orgStore.TransferOwnershipAndLeave(r.Context(), org.ID, userID, newOwnerID); err != nil {
		if errors.Is(err, postgres.ErrTransferTargetNotMember) {
			http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("User is not a member of this org"), http.StatusFound)
			return
		}
		slog.Error("transfer ownership failed", "org", slug, "err", err)
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Failed to transfer ownership"), http.StatusFound)
		return
	}

	// Best-effort: revoke org-scoped tokens for the departing owner.
	if h.revocStore != nil && h.rdb != nil {
		indexKey := "oauth:user-org-tokens:" + userID.String() + ":" + org.ID.String()
		if jtis, err := h.rdb.SMembers(r.Context(), indexKey).Result(); err == nil && len(jtis) > 0 {
			for _, jti := range jtis {
				h.revocStore.RevokeJTI(r.Context(), jti, time.Hour)
			}
			h.rdb.Del(r.Context(), indexKey)
		}
	}

	// Audit log.
	if h.auditStore != nil {
		_ = h.auditStore.Log(r.Context(), userID, postgres.AuditActionTransferOrgOwnership,
			"org", org.ID.String(), r.RemoteAddr, r.UserAgent())
	}

	// Best-effort: notify new owner by email in a goroutine so email failure
	// does not block or reverse the already-committed transfer.
	if h.mailer != nil {
		newOwner, err := h.userStore.GetByID(newOwnerID)
		if err == nil && newOwner != nil {
			go func() {
				if err := h.mailer.SendOwnershipTransfer(context.Background(), newOwner.Email, org.DisplayName, org.Slug, h.appURL); err != nil {
					slog.Error("failed to send ownership transfer email", "to", newOwner.Email, "org", slug, "err", err)
				}
			}()
		}
	}

	http.Redirect(w, r, "/account?message="+url.QueryEscape("Ownership of "+org.DisplayName+" transferred. You've been removed from the org."), http.StatusFound)
}

// LeaveOrg handles POST /account/orgs/:slug/leave
func (h *OrgHandler) LeaveOrg(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/account?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}

	role, err := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if err != nil {
		http.Redirect(w, r, "/account?error="+url.QueryEscape("Failed to verify membership"), http.StatusFound)
		return
	}
	if role == "" {
		http.Redirect(w, r, "/account?error="+url.QueryEscape("You are not a member of this organization"), http.StatusFound)
		return
	}

	if err := h.orgStore.RemoveMember(r.Context(), org.ID, userID); err != nil {
		if errors.Is(err, postgres.ErrOwnerCannotBeRemoved) {
			http.Redirect(w, r, "/account?error="+url.QueryEscape("Transfer ownership before leaving the organization"), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/account?error="+url.QueryEscape("Failed to leave organization"), http.StatusFound)
		return
	}

	// Best-effort: revoke all org-scoped tokens issued to this user for this org.
	if h.revocStore != nil && h.rdb != nil {
		indexKey := "oauth:user-org-tokens:" + userID.String() + ":" + org.ID.String()
		if jtis, err := h.rdb.SMembers(r.Context(), indexKey).Result(); err == nil && len(jtis) > 0 {
			for _, jti := range jtis {
				h.revocStore.RevokeJTI(r.Context(), jti, time.Hour)
			}
			h.rdb.Del(r.Context(), indexKey)
		}
	}

	http.Redirect(w, r, "/account?message="+url.QueryEscape("You've left "+org.DisplayName+"."), http.StatusFound)
}

// DeleteOrg handles POST /account/orgs/:slug/delete — owner-only org deletion.
func (h *OrgHandler) DeleteOrg(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}

	role, err := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if err != nil || role != "owner" {
		http.Redirect(w, r, "/account/orgs/"+slug+"?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	// Require the slug to be typed as confirmation.
	if r.FormValue("confirm_slug") != slug {
		http.Redirect(w, r, "/account/orgs/"+slug+"?error="+url.QueryEscape("Confirmation slug did not match"), http.StatusFound)
		return
	}

	orgID := org.ID
	orgName := org.DisplayName

	if err := h.orgStore.DeleteOrg(r.Context(), orgID); err != nil {
		http.Redirect(w, r, "/account/orgs/"+slug+"?error="+url.QueryEscape("Failed to delete organization"), http.StatusFound)
		return
	}

	// Clean up pending invites from Redis.
	h.cleanupOrgInvites(r.Context(), orgID.String())

	if h.auditStore != nil {
		go func() {
			_ = h.auditStore.Log(context.Background(), userID, postgres.AuditActionDeleteOrg,
				"org", orgID.String(), "", "owner")
		}()
	}

	_ = orgName
	http.Redirect(w, r, "/account/orgs?message="+url.QueryEscape("Organization deleted"), http.StatusFound)
}

// cleanupOrgInvites removes all pending Redis invite keys for an org.
func (h *OrgHandler) cleanupOrgInvites(ctx context.Context, orgID string) {
	tokens, err := h.rdb.SMembers(ctx, "org:invites:"+orgID).Result()
	if err != nil {
		return
	}
	for _, token := range tokens {
		h.rdb.Del(ctx, "org:invite:"+token)
	}
	h.rdb.Del(ctx, "org:invites:"+orgID)
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
	sort.Slice(pending, func(i, j int) bool { return pending[i].Email < pending[j].Email })
	return pending
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "duplicate key") || strings.Contains(msg, "unique constraint")
}

// GrantClientAccess handles POST /account/orgs/:slug/grants.
// For single-org clients it grants access directly (legacy path).
// For multi-org clients it creates a pending access request and emails the owner org.
func (h *OrgHandler) GrantClientAccess(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	redirectBase := "/account/orgs/" + slug

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/account/orgs", http.StatusFound)
		return
	}
	role, _ := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if role != "owner" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	clientID := strings.TrimSpace(r.FormValue("client_id"))
	if clientID == "" {
		http.Redirect(w, r, redirectBase+"?error=Client+ID+is+required", http.StatusFound)
		return
	}

	isGlobal, err := h.clientStore.IsGlobalClient(r.Context(), clientID)
	if errors.Is(err, postgres.ErrClientNotFound) {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Client not found"), http.StatusFound)
		return
	}
	if err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Server error"), http.StatusFound)
		return
	}

	if !isGlobal {
		// Single-org client: direct grant (legacy path).
		if err := h.clientStore.GrantOrgAccess(r.Context(), clientID, org.ID, userID); err != nil {
			http.Redirect(w, r, redirectBase+"?error=Failed+to+grant+access", http.StatusFound)
			return
		}
		if h.auditStore != nil {
			_ = h.auditStore.Log(context.Background(), userID, postgres.AuditActionGrantOrgClient,
				"client", clientID, r.RemoteAddr, r.UserAgent())
		}
		http.Redirect(w, r, redirectBase+"?message="+url.QueryEscape("Client access granted"), http.StatusFound)
		return
	}

	// Multi-org client: create a pending access request.
	ownerOrgID, err := h.clientStore.GetClientOwnerOrgID(r.Context(), clientID)
	if err != nil || ownerOrgID == nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Client has no owner org"), http.StatusFound)
		return
	}

	gr, err := h.clientStore.CreateGrantRequest(r.Context(), clientID, org.ID, *ownerOrgID, userID)
	if err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Failed to create access request"), http.StatusFound)
		return
	}
	if gr == nil {
		// ON CONFLICT DO NOTHING fired — a pending request already exists.
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("A pending request already exists for this client"), http.StatusFound)
		return
	}

	// Send email to owner org's admins/owners.
	if h.mailer != nil {
		ownerOrg, oErr := h.orgStore.GetOrgByID(r.Context(), *ownerOrgID)
		if oErr == nil && ownerOrg != nil {
			members, mErr := h.orgStore.ListMembers(r.Context(), *ownerOrgID)
			if mErr == nil {
				var adminEmails []string
				for _, m := range members {
					if m.Role == "owner" || m.Role == "admin" {
						adminEmails = append(adminEmails, m.UserEmail)
					}
				}
				if len(adminEmails) > 0 {
					approveURL := h.appURL + "/account/orgs/" + ownerOrg.Slug + "/clients/" + clientID + "/requests/" + gr.ID.String() + "/approve"
					denyURL := h.appURL + "/account/orgs/" + ownerOrg.Slug + "/clients/" + clientID + "/requests/" + gr.ID.String() + "/deny"
					go func() {
						if eErr := h.mailer.SendClientGrantRequest(context.Background(), adminEmails, gr.ClientName, org.DisplayName, approveURL, denyURL); eErr != nil {
							slog.Error("grant request email failed", "client", clientID, "err", eErr)
						}
					}()
				}
			}
		}
	}

	http.Redirect(w, r, redirectBase+"?message="+url.QueryEscape("Access request sent. The client owner will review it."), http.StatusFound)
}

// RevokeClientAccess handles POST /account/orgs/:slug/grants/:clientID/revoke — owner removes a client grant.
func (h *OrgHandler) RevokeClientAccess(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	clientID := ps.ByName("clientID")

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/account/orgs", http.StatusFound)
		return
	}
	role, _ := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if role != "owner" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if err := h.clientStore.RevokeOrgAccess(r.Context(), clientID, org.ID); err != nil {
		http.Redirect(w, r, "/account/orgs/"+slug+"?error=Failed+to+revoke+access", http.StatusFound)
		return
	}

	// Blocklist all outstanding JTIs for users of this org issued for this client's grants.
	if h.rdb != nil && h.revocStore != nil {
		pattern := "oauth:user-org-tokens:*:" + org.ID.String()
		keys, scanErr := h.rdb.Keys(r.Context(), pattern).Result()
		if scanErr == nil {
			for _, key := range keys {
				jtis, err := h.rdb.SMembers(r.Context(), key).Result()
				if err != nil {
					continue
				}
				for _, jti := range jtis {
					_ = h.revocStore.RevokeJTI(r.Context(), jti, 2*time.Hour)
				}
			}
		}
	}

	if h.auditStore != nil {
		_ = h.auditStore.Log(context.Background(), userID, postgres.AuditActionRevokeOrgClient,
			"client", clientID, r.RemoteAddr, r.UserAgent())
	}

	// Notify client owner org's admins that this org removed its own grant.
	if h.mailer != nil {
		orgDisplayName := org.DisplayName
		go func() {
			ownerOrgID, err := h.clientStore.GetClientOwnerOrgID(context.Background(), clientID)
			if err != nil || ownerOrgID == nil {
				return
			}
			emails, err := h.userStore.ListOrgAdmins(context.Background(), *ownerOrgID)
			if err != nil || len(emails) == 0 {
				return
			}
			clientName, _ := h.clientStore.GetClientName(context.Background(), clientID)
			if clientName == "" {
				clientName = clientID
			}
			if err := h.mailer.SendGrantRevoked(context.Background(), emails, clientName, orgDisplayName, false, ""); err != nil {
				slog.Error("grant revoked email failed", "client", clientID, "err", err)
			}
		}()
	}

	http.Redirect(w, r, "/account/orgs/"+slug+"?message="+url.QueryEscape("Client access revoked"), http.StatusFound)
}

// ApproveGrantRequest handles POST /account/orgs/:slug/clients/:clientID/requests/:requestID/approve
func (h *OrgHandler) ApproveGrantRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	clientID := ps.ByName("clientID")
	requestIDStr := ps.ByName("requestID")
	redirectBase := "/account/orgs/" + slug + "/clients"

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}
	role, _ := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if role != "owner" && role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Verify the client is owned by this org (prevents cross-org privilege escalation).
	ownerOrgID, err := h.clientStore.GetClientOwnerOrgID(r.Context(), clientID)
	if err != nil || ownerOrgID == nil || *ownerOrgID != org.ID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Invalid request ID"), http.StatusFound)
		return
	}

	gr, err := h.clientStore.ApproveGrantRequest(r.Context(), requestID, clientID, org.ID, userID)
	if err != nil {
		if errors.Is(err, postgres.ErrGrantRequestNotPending) {
			http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Request already resolved"), http.StatusFound)
			return
		}
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Failed to approve request"), http.StatusFound)
		return
	}

	if h.auditStore != nil {
		_ = h.auditStore.Log(context.Background(), userID, postgres.AuditActionGrantOrgClient,
			"client", clientID, r.RemoteAddr, r.UserAgent())
	}

	// Notify requester org's admins that their request was approved.
	if h.mailer != nil {
		requesterOrgID := gr.RequesterOrgID
		go func() {
			emails, err := h.userStore.ListOrgAdmins(context.Background(), requesterOrgID)
			if err != nil || len(emails) == 0 {
				return
			}
			clientName, _ := h.clientStore.GetClientName(context.Background(), clientID)
			if clientName == "" {
				clientName = clientID
			}
			clientsURL := h.appURL + "/account/orgs"
			if err := h.mailer.SendGrantApproved(context.Background(), emails, clientName, org.DisplayName, clientsURL); err != nil {
				slog.Error("grant approved email failed", "client", clientID, "err", err)
			}
		}()
	}

	http.Redirect(w, r, redirectBase+"?message="+url.QueryEscape("Access request approved"), http.StatusFound)
}

// DenyGrantRequest handles POST /account/orgs/:slug/clients/:clientID/requests/:requestID/deny
func (h *OrgHandler) DenyGrantRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	clientID := ps.ByName("clientID")
	requestIDStr := ps.ByName("requestID")
	redirectBase := "/account/orgs/" + slug + "/clients"

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}
	role, _ := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if role != "owner" && role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Verify the client is owned by this org.
	ownerOrgID, err := h.clientStore.GetClientOwnerOrgID(r.Context(), clientID)
	if err != nil || ownerOrgID == nil || *ownerOrgID != org.ID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Invalid request ID"), http.StatusFound)
		return
	}

	gr, err := h.clientStore.DenyGrantRequest(r.Context(), requestID, clientID, org.ID, userID)
	if err != nil {
		if errors.Is(err, postgres.ErrGrantRequestNotPending) {
			http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Request already resolved"), http.StatusFound)
			return
		}
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Failed to deny request"), http.StatusFound)
		return
	}

	// Notify requester org's admins that their request was denied.
	if h.mailer != nil {
		requesterOrgID := gr.RequesterOrgID
		go func() {
			emails, err := h.userStore.ListOrgAdmins(context.Background(), requesterOrgID)
			if err != nil || len(emails) == 0 {
				return
			}
			clientName, _ := h.clientStore.GetClientName(context.Background(), clientID)
			if clientName == "" {
				clientName = clientID
			}
			if err := h.mailer.SendGrantDenied(context.Background(), emails, clientName, org.DisplayName); err != nil {
				slog.Error("grant denied email failed", "client", clientID, "err", err)
			}
		}()
	}

	http.Redirect(w, r, redirectBase+"?message="+url.QueryEscape("Access request denied"), http.StatusFound)
}

// EditClient handles GET /account/orgs/:slug/clients/:clientID/edit
func (h *OrgHandler) EditClient(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	clientID := ps.ByName("clientID")
	redirectBase := "/account/orgs/" + slug + "/clients"

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}
	role, _ := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if role != "owner" && role != "admin" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	clients, _ := h.clientStore.ListOrgClients(r.Context(), org.ID)
	var client *postgres.OrgClient
	for _, c := range clients {
		if c.ID == clientID && c.IsOwner {
			client = c
			break
		}
	}
	if client == nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Client not found"), http.StatusFound)
		return
	}

	isAdmin, _ := r.Context().Value(types.IsAdminContextKey).(bool)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.OrgClientEditPage(nosurf.Token(r), org, client, true, isAdmin,
		r.URL.Query().Get("error"), r.URL.Query().Get("message")).Render(r.Context(), w)
}

// EditClientPost handles POST /account/orgs/:slug/clients/:clientID/edit
func (h *OrgHandler) EditClientPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	clientID := ps.ByName("clientID")
	redirectBase := "/account/orgs/" + slug + "/clients/" + clientID + "/edit"

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}
	role, _ := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if role != "owner" && role != "admin" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))

	if len(name) == 0 || len(name) > 255 {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Client name must be 1–255 characters"), http.StatusFound)
		return
	}
	if err := validateRedirectURI(redirectURI); err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}

	if err := h.clientStore.UpdateOrgClient(r.Context(), clientID, org.ID, name, redirectURI); err != nil {
		msg := "Failed to update client"
		if errors.Is(err, postgres.ErrClientNotFound) {
			msg = "Client not found"
		}
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}

	http.Redirect(w, r, "/account/orgs/"+slug+"/clients?message="+url.QueryEscape("Client updated"), http.StatusFound)
}

// ClientRequestHistory handles GET /account/orgs/:slug/clients/:clientID/requests
func (h *OrgHandler) ClientRequestHistory(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	slug := ps.ByName("slug")
	clientID := ps.ByName("clientID")
	redirectBase := "/account/orgs/" + slug + "/clients"

	org, err := h.orgStore.GetOrgBySlug(r.Context(), slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/account/orgs?error="+url.QueryEscape("Organization not found"), http.StatusFound)
		return
	}
	role, _ := h.orgStore.GetMembership(r.Context(), org.ID, userID)
	if role != "owner" && role != "admin" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Access denied"), http.StatusFound)
		return
	}

	ownerOrgID, err := h.clientStore.GetClientOwnerOrgID(r.Context(), clientID)
	if err != nil || ownerOrgID == nil || *ownerOrgID != org.ID {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Client not found"), http.StatusFound)
		return
	}

	requests, _ := h.clientStore.ListAllGrantRequestsForClient(r.Context(), clientID)

	clients, _ := h.clientStore.ListOrgClients(r.Context(), org.ID)
	var client *postgres.OrgClient
	for _, c := range clients {
		if c.ID == clientID {
			client = c
			break
		}
	}

	isAdmin, _ := r.Context().Value(types.IsAdminContextKey).(bool)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.OrgClientRequestHistoryPage(nosurf.Token(r), org, client, requests, isAdmin,
		r.URL.Query().Get("error"), r.URL.Query().Get("message")).Render(r.Context(), w)
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
