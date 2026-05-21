package handlers

import (
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
	"github.com/iabhishekrajput/anekdote-auth/internal/types"
	"github.com/iabhishekrajput/anekdote-auth/web/ui"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/nosurf"
)

type AdminHandler struct {
	userStore    *postgres.UserStore
	orgStore     *postgres.OrgStore
	clientStore  *postgres.ClientStore
	sessionStore *redis.SessionStore
}

func NewAdminHandler(uStore *postgres.UserStore, oStore *postgres.OrgStore, cStore *postgres.ClientStore, sStore *redis.SessionStore) *AdminHandler {
	return &AdminHandler{
		userStore:    uStore,
		orgStore:     oStore,
		clientStore:  cStore,
		sessionStore: sStore,
	}
}

func (h *AdminHandler) Dashboard(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	var dbErr bool
	userCount, err := h.userStore.CountAll(ctx)
	if err != nil {
		slog.Error("admin: count users", "err", err)
		dbErr = true
	}
	orgCount, err := h.orgStore.CountAll(ctx)
	if err != nil {
		slog.Error("admin: count orgs", "err", err)
		dbErr = true
	}
	clientCount, err := h.clientStore.CountAll(ctx)
	if err != nil {
		slog.Error("admin: count clients", "err", err)
		dbErr = true
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.AdminDashboard(nosurf.Token(r), userCount, orgCount, clientCount, dbErr).Render(ctx, w)
}

func (h *AdminHandler) UserList(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	page := 1
	if p, _ := strconv.Atoi(r.URL.Query().Get("page")); p > 0 {
		page = p
	}
	const pageSize = 50
	users, _ := h.userStore.ListAll(ctx, pageSize, (page-1)*pageSize)
	total, _ := h.userStore.CountAll(ctx)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.AdminUserList(nosurf.Token(r), users, page, total, pageSize,
		r.URL.Query().Get("error"), r.URL.Query().Get("message")).Render(ctx, w)
}

func (h *AdminHandler) UserDetail(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	id, err := uuid.Parse(ps.ByName("id"))
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	user, err := h.userStore.GetByID(id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	orgs, _ := h.orgStore.ListOrgsForUserFull(ctx, id)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.AdminUserDetail(nosurf.Token(r), user, orgs,
		r.URL.Query().Get("error"), r.URL.Query().Get("message")).Render(ctx, w)
}

func (h *AdminHandler) DisableUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	id, err := uuid.Parse(ps.ByName("id"))
	if err != nil {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("Invalid user ID"), http.StatusFound)
		return
	}
	adminID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	if id == adminID {
		http.Redirect(w, r, "/admin/users/"+id.String()+"?error="+url.QueryEscape("You cannot disable your own account"), http.StatusFound)
		return
	}
	if err := h.userStore.SetDisabled(ctx, id, true); err != nil {
		http.Redirect(w, r, "/admin/users/"+id.String()+"?error="+url.QueryEscape("Failed to disable user"), http.StatusFound)
		return
	}
	_ = h.sessionStore.DeleteAllForUser(ctx, id)
	http.Redirect(w, r, "/admin/users/"+id.String()+"?message="+url.QueryEscape("User disabled and sessions revoked"), http.StatusFound)
}

func (h *AdminHandler) EnableUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	id, err := uuid.Parse(ps.ByName("id"))
	if err != nil {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("Invalid user ID"), http.StatusFound)
		return
	}
	if err := h.userStore.SetDisabled(ctx, id, false); err != nil {
		http.Redirect(w, r, "/admin/users/"+id.String()+"?error="+url.QueryEscape("Failed to enable user"), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/users/"+id.String()+"?message="+url.QueryEscape("User enabled"), http.StatusFound)
}

func (h *AdminHandler) ClientList(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	clients, _ := h.clientStore.ListAll(ctx)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.AdminClientList(nosurf.Token(r), clients,
		r.URL.Query().Get("error"), r.URL.Query().Get("message")).Render(ctx, w)
}

func (h *AdminHandler) DeleteClient(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	clientID := ps.ByName("id")
	if r.FormValue("confirm") != "yes" {
		http.Redirect(w, r, "/admin/clients?error="+url.QueryEscape("Confirmation required"), http.StatusFound)
		return
	}
	if err := h.clientStore.DeleteAny(ctx, clientID); err != nil {
		http.Redirect(w, r, "/admin/clients?error="+url.QueryEscape("Failed to delete client"), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/clients?message="+url.QueryEscape("Client deleted"), http.StatusFound)
}

func (h *AdminHandler) OrgList(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	orgs, _ := h.orgStore.ListAll(ctx)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.AdminOrgList(nosurf.Token(r), orgs,
		r.URL.Query().Get("error"), r.URL.Query().Get("message")).Render(ctx, w)
}

func (h *AdminHandler) OrgDetail(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	slug := ps.ByName("slug")
	org, err := h.orgStore.GetOrgBySlug(ctx, slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/admin/orgs?error="+url.QueryEscape("Org not found"), http.StatusFound)
		return
	}
	members, _ := h.orgStore.ListMembers(ctx, org.ID)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.AdminOrgDetail(nosurf.Token(r), org, members,
		r.URL.Query().Get("error"), r.URL.Query().Get("message")).Render(ctx, w)
}

func (h *AdminHandler) RemoveOrgMember(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	slug := ps.ByName("slug")
	targetUserID, err := uuid.Parse(ps.ByName("user_id"))
	if err != nil {
		http.Redirect(w, r, "/admin/orgs?error="+url.QueryEscape("Invalid user ID"), http.StatusFound)
		return
	}
	adminID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	if targetUserID == adminID {
		http.Redirect(w, r, "/admin/orgs/"+slug+"?error="+url.QueryEscape("You cannot remove yourself via the admin panel"), http.StatusFound)
		return
	}
	org, err := h.orgStore.GetOrgBySlug(ctx, slug)
	if err != nil || org == nil {
		http.Redirect(w, r, "/admin/orgs?error="+url.QueryEscape("Org not found"), http.StatusFound)
		return
	}
	if err := h.orgStore.RemoveMember(ctx, org.ID, targetUserID); err != nil {
		errMsg := "Failed to remove member"
		if strings.Contains(err.Error(), "owner") {
			errMsg = "Cannot remove the org owner; transfer ownership first"
		}
		http.Redirect(w, r, "/admin/orgs/"+slug+"?error="+url.QueryEscape(errMsg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/orgs/"+slug+"?message="+url.QueryEscape("Member removed"), http.StatusFound)
}
