package handlers

import (
	"html/template"
	"net/http"

	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/types"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"
)

type AccountHandler struct {
	userStore *postgres.UserStore
	templates *template.Template
}

func NewAccountHandler(uStore *postgres.UserStore) *AccountHandler {
	tmpl := template.Must(template.ParseGlob("web/templates/*.html"))
	return &AccountHandler{
		userStore: uStore,
		templates: tmpl,
	}
}

func (h *AccountHandler) ViewAccount(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)

	user, err := h.userStore.GetByID(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	h.templates.ExecuteTemplate(w, "account.html", map[string]interface{}{
		"User": user,
	})
}

func (h *AccountHandler) UpdateProfile(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)
	newName := r.FormValue("name")

	if newName == "" {
		http.Error(w, "Name cannot be empty", http.StatusBadRequest)
		return
	}

	err := h.userStore.UpdateName(userID, newName)
	if err != nil {
		http.Error(w, "Failed to update profile", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/account?message=Profile+updated", http.StatusFound)
}

func (h *AccountHandler) UpdatePassword(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	userID := r.Context().Value(types.UserContextKey).(uuid.UUID)

	oldPassword := r.FormValue("old_password")
	newPassword := r.FormValue("new_password")

	if oldPassword == "" || newPassword == "" {
		http.Error(w, "Missing passwords", http.StatusBadRequest)
		return
	}

	user, err := h.userStore.GetByID(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Verify old password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword))
	if err != nil {
		http.Error(w, "Incorrect old password", http.StatusUnauthorized)
		return
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	err = h.userStore.UpdatePassword(userID, string(hash))
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/account?message=Password+updated", http.StatusFound)
}
