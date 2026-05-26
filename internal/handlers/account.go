package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	goredis "github.com/go-redis/redis/v8"
	"github.com/iabhishekrajput/anekdote-auth/internal/models"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
	"github.com/iabhishekrajput/anekdote-auth/internal/types"
	"github.com/iabhishekrajput/anekdote-auth/web/ui"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/nosurf"
	"golang.org/x/crypto/bcrypt"
)

type AccountHandler struct {
	userStore    *postgres.UserStore
	orgStore     *postgres.OrgStore
	sessionStore *redis.SessionStore
	auditStore   *postgres.AuditStore
	rdb          *goredis.Client
}

func NewAccountHandler(uStore *postgres.UserStore, orgStore *postgres.OrgStore, sessionStore *redis.SessionStore, auditStore *postgres.AuditStore, rdb *goredis.Client) *AccountHandler {
	return &AccountHandler{
		userStore:    uStore,
		orgStore:     orgStore,
		sessionStore: sessionStore,
		auditStore:   auditStore,
		rdb:          rdb,
	}
}

func (h *AccountHandler) render(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}

	if errStr := r.URL.Query().Get("error"); errStr != "" {
		if _, exists := data["Error"]; !exists {
			data["Error"] = errStr
		}
	}
	if msgStr := r.URL.Query().Get("message"); msgStr != "" {
		if _, exists := data["Success"]; !exists {
			data["Success"] = msgStr
		}
	}

	var errorMsg, successMsg string
	if v, ok := data["Error"].(string); ok {
		errorMsg = v
	}
	if v, ok := data["Success"].(string); ok {
		successMsg = v
	}

	csrfToken := nosurf.Token(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	isAdmin, _ := r.Context().Value(types.IsAdminContextKey).(bool)

	switch name {
	case "account.tmpl":
		user, _ := data["User"].(*models.User)
		orgs, _ := data["Orgs"].([]postgres.OrgListItem)
		component := ui.AccountPage(csrfToken, user, isAdmin, orgs, errorMsg, successMsg)
		_ = component.Render(r.Context(), w)
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("template not found"))
	}
}

func (h *AccountHandler) ViewAccount(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(string)

	user, err := h.userStore.GetByID(userID)
	if err != nil {
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Session user not found"), http.StatusFound)
		return
	}

	orgs, _ := h.orgStore.ListOrgsForUserFull(r.Context(), userID)
	if orgs == nil {
		orgs = []postgres.OrgListItem{}
	}

	errMsg := r.URL.Query().Get("error")
	successMsg := r.URL.Query().Get("message")

	h.render(w, r, "account.tmpl", map[string]interface{}{
		"User":    user,
		"Orgs":    orgs,
		"Error":   errMsg,
		"Success": successMsg,
	})
}

func (h *AccountHandler) UpdateProfile(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(string)
	newName := r.FormValue("name")

	if newName == "" {
		http.Redirect(w, r, "/account?error="+url.QueryEscape("Name cannot be empty"), http.StatusFound)
		return
	}

	err := h.userStore.UpdateName(userID, newName)
	if err != nil {
		http.Redirect(w, r, "/account?error="+url.QueryEscape("Failed to update profile"), http.StatusFound)
		return
	}

	http.Redirect(w, r, "/account?message="+url.QueryEscape("Profile updated"), http.StatusFound)
}

func (h *AccountHandler) UpdatePassword(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(string)

	oldPassword := r.FormValue("old_password")
	newPassword := r.FormValue("new_password")

	if oldPassword == "" || newPassword == "" {
		http.Redirect(w, r, "/account?error="+url.QueryEscape("Missing passwords"), http.StatusFound)
		return
	}

	if err := validatePassword(newPassword); err != nil {
		http.Redirect(w, r, "/account?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}

	user, err := h.userStore.GetByID(userID)
	if err != nil {
		http.Redirect(w, r, "/account?error="+url.QueryEscape("User not found"), http.StatusFound)
		return
	}

	// Verify old password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword))
	if err != nil {
		http.Redirect(w, r, "/account?error="+url.QueryEscape("Incorrect old password"), http.StatusFound)
		return
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Redirect(w, r, "/account?error="+url.QueryEscape("Server Error"), http.StatusFound)
		return
	}

	err = h.userStore.UpdatePassword(userID, string(hash))
	if err != nil {
		http.Redirect(w, r, "/account?error="+url.QueryEscape("Failed to update password"), http.StatusFound)
		return
	}

	http.Redirect(w, r, "/account?message="+url.QueryEscape("Password updated"), http.StatusFound)
}

// userDeletionTombstoneTTL matches the OAuth2 access token max lifetime so
// tokens issued before deletion are rejected at /userinfo until they expire.
const userDeletionTombstoneTTL = 2 * time.Hour

// DeleteSelf handles POST /account/delete — self-service account deletion.
func (h *AccountHandler) DeleteSelf(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(string)

	if err := h.userStore.DeleteUser(r.Context(), userID); err != nil {
		if errors.Is(err, postgres.ErrUserOwnsOrg) {
			http.Redirect(w, r, "/account?error="+url.QueryEscape("Transfer or delete your organizations before deleting your account"), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/account?error="+url.QueryEscape("Failed to delete account"), http.StatusFound)
		return
	}

	// Revoke all sessions.
	_ = h.sessionStore.DeleteAllForUser(r.Context(), userID)

	// Tombstone for in-flight JWTs — checked by /userinfo.
	if h.rdb != nil {
		h.rdb.Set(r.Context(), "deleted:user:"+userID, "1", userDeletionTombstoneTTL)
	}

	// Audit log — fire-and-forget; deletion has already committed.
	if h.auditStore != nil {
		go func() {
			_ = h.auditStore.Log(context.Background(), userID, postgres.AuditActionDeleteUser,
				"user", userID, "", "self")
		}()
	}

	// Clear session cookie and redirect to login.
	http.SetCookie(w, &http.Cookie{Name: "session_id", MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/login?message="+url.QueryEscape("Your account has been deleted"), http.StatusFound)
}
