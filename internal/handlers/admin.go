package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

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
	auditStore   *postgres.AuditStore
}

func NewAdminHandler(uStore *postgres.UserStore, oStore *postgres.OrgStore, cStore *postgres.ClientStore, sStore *redis.SessionStore, aStore *postgres.AuditStore) *AdminHandler {
	return &AdminHandler{
		userStore:    uStore,
		orgStore:     oStore,
		clientStore:  cStore,
		sessionStore: sStore,
		auditStore:   aStore,
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
	const pageSize = 50

	cursor, err := postgres.DecodeCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("Invalid pagination cursor"), http.StatusFound)
		return
	}

	users, nextCursor, total, listErr := h.userStore.ListAllCursor(ctx, pageSize, cursor)
	if listErr != nil {
		slog.Error("admin: list users", "err", listErr)
	}
	errMsg := r.URL.Query().Get("error")
	if listErr != nil && errMsg == "" {
		errMsg = "Database error — data may be incomplete"
	}

	cursorParam := r.URL.Query().Get("cursor")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.AdminUserList(nosurf.Token(r), users, total, cursorParam, nextCursor,
		errMsg, r.URL.Query().Get("message")).Render(ctx, w)
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
	adminCount, _ := h.userStore.CountAdmins(ctx)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.AdminUserDetail(nosurf.Token(r), user, orgs, adminCount <= 1,
		r.URL.Query().Get("error"), r.URL.Query().Get("message")).Render(ctx, w)
}

func (h *AdminHandler) DisableUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	id, err := uuid.Parse(ps.ByName("id"))
	if err != nil {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("Invalid user ID"), http.StatusFound)
		return
	}
	adminID, ok := r.Context().Value(types.UserContextKey).(uuid.UUID)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if id == adminID {
		http.Redirect(w, r, "/admin/users/"+id.String()+"?error="+url.QueryEscape("You cannot disable your own account"), http.StatusFound)
		return
	}
	if err := h.userStore.SetDisabled(ctx, id, true); err != nil {
		http.Redirect(w, r, "/admin/users/"+id.String()+"?error="+url.QueryEscape("Failed to disable user"), http.StatusFound)
		return
	}
	_ = h.sessionStore.DeleteAllForUser(ctx, id)
	go func() {
		_ = h.auditStore.Log(context.WithoutCancel(ctx), adminID, postgres.AuditActionDisableUser,
			"user", id.String(), extractIP(r), r.Header.Get("User-Agent"))
	}()
	http.Redirect(w, r, "/admin/users/"+id.String()+"?message="+url.QueryEscape("User disabled and sessions revoked"), http.StatusFound)
}

func (h *AdminHandler) EnableUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	id, err := uuid.Parse(ps.ByName("id"))
	if err != nil {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("Invalid user ID"), http.StatusFound)
		return
	}
	adminID, ok := r.Context().Value(types.UserContextKey).(uuid.UUID)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := h.userStore.SetDisabled(ctx, id, false); err != nil {
		http.Redirect(w, r, "/admin/users/"+id.String()+"?error="+url.QueryEscape("Failed to enable user"), http.StatusFound)
		return
	}
	go func() {
		_ = h.auditStore.Log(context.WithoutCancel(ctx), adminID, postgres.AuditActionEnableUser,
			"user", id.String(), extractIP(r), r.Header.Get("User-Agent"))
	}()
	http.Redirect(w, r, "/admin/users/"+id.String()+"?message="+url.QueryEscape("User enabled"), http.StatusFound)
}

func (h *AdminHandler) PromoteAdmin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	id, err := uuid.Parse(ps.ByName("id"))
	if err != nil {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("Invalid user ID"), http.StatusFound)
		return
	}
	adminID, ok := r.Context().Value(types.UserContextKey).(uuid.UUID)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := h.userStore.SetAdmin(ctx, id, true); err != nil {
		http.Redirect(w, r, "/admin/users/"+id.String()+"?error="+url.QueryEscape("Failed to grant admin access"), http.StatusFound)
		return
	}
	go func() {
		_ = h.auditStore.Log(context.WithoutCancel(ctx), adminID, postgres.AuditActionPromoteAdmin,
			"user", id.String(), extractIP(r), r.Header.Get("User-Agent"))
	}()
	http.Redirect(w, r, "/admin/users/"+id.String()+"?message="+url.QueryEscape("Admin access granted"), http.StatusFound)
}

func (h *AdminHandler) DemoteAdmin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	id, err := uuid.Parse(ps.ByName("id"))
	if err != nil {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("Invalid user ID"), http.StatusFound)
		return
	}
	adminID, ok := r.Context().Value(types.UserContextKey).(uuid.UUID)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := h.userStore.SetAdmin(ctx, id, false); err != nil {
		if errors.Is(err, postgres.ErrLastAdmin) {
			http.Redirect(w, r, "/admin/users/"+id.String()+"?error="+url.QueryEscape("Cannot remove the last admin"), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/admin/users/"+id.String()+"?error="+url.QueryEscape("Failed to remove admin access"), http.StatusFound)
		return
	}
	go func() {
		_ = h.auditStore.Log(context.WithoutCancel(ctx), adminID, postgres.AuditActionDemoteAdmin,
			"user", id.String(), extractIP(r), r.Header.Get("User-Agent"))
	}()
	http.Redirect(w, r, "/admin/users/"+id.String()+"?message="+url.QueryEscape("Admin access removed"), http.StatusFound)
}

// ChangeAdminRole updates a user's admin_role (superadmin / readonly / org_admin).
// Only meaningful when the target user is already an admin (is_admin = true).
func (h *AdminHandler) ChangeAdminRole(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	id, err := uuid.Parse(ps.ByName("id"))
	if err != nil {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("Invalid user ID"), http.StatusFound)
		return
	}
	adminID, ok := r.Context().Value(types.UserContextKey).(uuid.UUID)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	role := r.FormValue("role")
	if err := h.userStore.SetAdminRole(ctx, id, role); err != nil {
		http.Redirect(w, r, "/admin/users/"+id.String()+"?error="+url.QueryEscape("Invalid role: "+err.Error()), http.StatusFound)
		return
	}
	go func() {
		_ = h.auditStore.Log(context.WithoutCancel(ctx), adminID, postgres.AuditActionChangeAdminRole,
			"user", id.String(), extractIP(r), r.Header.Get("User-Agent"))
	}()
	http.Redirect(w, r, "/admin/users/"+id.String()+"?message="+url.QueryEscape("Admin role updated to "+role), http.StatusFound)
}

func (h *AdminHandler) ClientList(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	const pageSize = 50

	cursor, err := postgres.DecodeCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		http.Redirect(w, r, "/admin/clients?error="+url.QueryEscape("Invalid pagination cursor"), http.StatusFound)
		return
	}

	clients, nextCursor, total, listErr := h.clientStore.ListAllCursor(ctx, pageSize, cursor)
	if listErr != nil {
		slog.Error("admin: list clients", "err", listErr)
	}
	errMsg := r.URL.Query().Get("error")
	if listErr != nil && errMsg == "" {
		errMsg = "Database error — data may be incomplete"
	}

	cursorParam := r.URL.Query().Get("cursor")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.AdminClientList(nosurf.Token(r), clients, total, cursorParam, nextCursor,
		errMsg, r.URL.Query().Get("message")).Render(ctx, w)
}

func (h *AdminHandler) DeleteClient(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	clientID := ps.ByName("id")
	adminID, ok := r.Context().Value(types.UserContextKey).(uuid.UUID)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if r.FormValue("confirm") != "yes" {
		http.Redirect(w, r, "/admin/clients?error="+url.QueryEscape("Confirmation required"), http.StatusFound)
		return
	}
	if err := h.clientStore.DeleteAny(ctx, clientID); err != nil {
		http.Redirect(w, r, "/admin/clients?error="+url.QueryEscape("Failed to delete client"), http.StatusFound)
		return
	}
	go func() {
		_ = h.auditStore.Log(context.WithoutCancel(ctx), adminID, postgres.AuditActionDeleteClient,
			"client", clientID, extractIP(r), r.Header.Get("User-Agent"))
	}()
	http.Redirect(w, r, "/admin/clients?message="+url.QueryEscape("Client deleted"), http.StatusFound)
}

func (h *AdminHandler) OrgList(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	const pageSize = 50

	cursor, err := postgres.DecodeCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		http.Redirect(w, r, "/admin/orgs?error="+url.QueryEscape("Invalid pagination cursor"), http.StatusFound)
		return
	}

	orgs, nextCursor, total, listErr := h.orgStore.ListAllCursor(ctx, pageSize, cursor)
	if listErr != nil {
		slog.Error("admin: list orgs", "err", listErr)
	}
	errMsg := r.URL.Query().Get("error")
	if listErr != nil && errMsg == "" {
		errMsg = "Database error — data may be incomplete"
	}

	cursorParam := r.URL.Query().Get("cursor")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.AdminOrgList(nosurf.Token(r), orgs, total, cursorParam, nextCursor,
		errMsg, r.URL.Query().Get("message")).Render(ctx, w)
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
	adminID, ok := r.Context().Value(types.UserContextKey).(uuid.UUID)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
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
		if errors.Is(err, postgres.ErrOwnerCannotBeRemoved) {
			errMsg = "Cannot remove the org owner; transfer ownership first"
		}
		http.Redirect(w, r, "/admin/orgs/"+slug+"?error="+url.QueryEscape(errMsg), http.StatusFound)
		return
	}
	go func() {
		_ = h.auditStore.Log(context.WithoutCancel(ctx), adminID, postgres.AuditActionRemoveOrgMember,
			"org_member", org.ID.String()+"/"+targetUserID.String(), extractIP(r), r.Header.Get("User-Agent"))
	}()
	http.Redirect(w, r, "/admin/orgs/"+slug+"?message="+url.QueryEscape("Member removed"), http.StatusFound)
}

// AuditLog renders the paginated, filtered admin audit log.
func (h *AdminHandler) AuditLog(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	const pageSize = 50

	cursor, err := postgres.DecodeCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		http.Redirect(w, r, "/admin/audit?error="+url.QueryEscape("Invalid pagination cursor"), http.StatusFound)
		return
	}

	filter := parseAuditFilter(r)

	entries, nextCursor, total, listErr := h.auditStore.ListAuditCursor(ctx, pageSize, cursor, filter)
	if listErr != nil {
		slog.Error("admin: list audit log", "err", listErr)
	}
	errMsg := r.URL.Query().Get("error")
	if listErr != nil && errMsg == "" {
		errMsg = "Could not load audit log — data may be incomplete"
	}

	cursorParam := r.URL.Query().Get("cursor")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui.AdminAuditLog(nosurf.Token(r), entries, total, cursorParam, nextCursor, filter,
		errMsg, r.URL.Query().Get("message")).Render(ctx, w)
}

// ExportAuditCSV streams the filtered audit log as a CSV download.
func (h *AdminHandler) ExportAuditCSV(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	filter := parseAuditFilter(r)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="audit-%s.csv"`, time.Now().UTC().Format("20060102-150405")))
	if err := h.auditStore.ExportAuditCSV(r.Context(), filter, w); err != nil {
		slog.Error("admin: export audit CSV", "err", err)
	}
}

// parseAuditFilter reads filter query params from the request.
func parseAuditFilter(r *http.Request) postgres.AuditFilter {
	var f postgres.AuditFilter
	if adminIDStr := r.URL.Query().Get("admin_id"); adminIDStr != "" {
		if id, err := uuid.Parse(adminIDStr); err == nil {
			f.AdminID = &id
		}
	}
	if action := r.URL.Query().Get("action"); action != "" {
		f.Action = action
	}
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		if t, err := time.Parse("2006-01-02", fromStr); err == nil {
			f.From = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		if t, err := time.Parse("2006-01-02", toStr); err == nil {
			// end of the day
			eod := t.Add(24*time.Hour - time.Second)
			f.To = &eod
		}
	}
	return f
}

// extractIP returns the client IP from the request, checking proxy headers first.
func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
