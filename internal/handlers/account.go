package handlers

import (
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/models"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/types"
	"github.com/iabhishekrajput/anekdote-auth/web/ui"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/nosurf"
	"golang.org/x/crypto/bcrypt"
)

type AccountHandler struct {
	userStore *postgres.UserStore
}

func NewAccountHandler(uStore *postgres.UserStore) *AccountHandler {
	return &AccountHandler{
		userStore: uStore,
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

	switch name {
	case "account.tmpl":
		user, _ := data["User"].(*models.User)
		component := ui.AccountPage(csrfToken, user, errorMsg, successMsg)
		_ = component.Render(r.Context(), w)
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("template not found"))
	}
}

func (h *AccountHandler) ViewAccount(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)

	user, err := h.userStore.GetByID(userID)
	if err != nil {
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Session user not found"), http.StatusFound)
		return
	}

	errMsg := r.URL.Query().Get("error")
	successMsg := r.URL.Query().Get("message")

	h.render(w, r, "account.tmpl", map[string]interface{}{
		"User":    user,
		"Error":   errMsg,
		"Success": successMsg,
	})
}

func (h *AccountHandler) UpdateProfile(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
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
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)

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
