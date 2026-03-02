package handlers

import (
	"context"
	"html/template"
	"net/http"
	"time"

	"github.com/iabhishekrajput/anekdote-auth/internal/mailer"
	"github.com/iabhishekrajput/anekdote-auth/internal/session"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"
)

type IdentityHandler struct {
	userStore    *postgres.UserStore
	sessionStore *session.Store
	mailer       *mailer.Mailer
	templates    *template.Template
}

func NewIdentityHandler(uStore *postgres.UserStore, sStore *session.Store, mailSvc *mailer.Mailer) *IdentityHandler {
	// Pre-parse templates for performance
	tmpl := template.Must(template.ParseGlob("web/templates/*.html"))

	return &IdentityHandler{
		userStore:    uStore,
		sessionStore: sStore,
		mailer:       mailSvc,
		templates:    tmpl,
	}
}

func (h *IdentityHandler) RegisterFunc(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		h.templates.ExecuteTemplate(w, "register.html", nil)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	name := r.FormValue("name")

	if email == "" || password == "" {
		http.Error(w, "Email and password required", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	_, err = h.userStore.Create(email, name, string(hash))
	if err != nil {
		http.Error(w, "Error creating user (maybe email exists)", http.StatusConflict)
		return
	}

	http.Redirect(w, r, "/login", http.StatusFound)
}

func (h *IdentityHandler) LoginFunc(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if r.Method == http.MethodGet {
		reqURI := r.URL.Query().Get("req")
		w.Header().Set("Content-Type", "text/html")
		h.templates.ExecuteTemplate(w, "login.html", map[string]string{
			"Req": reqURI,
		})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	oauthReq := r.FormValue("req") // Originating OAuth request URL

	user, err := h.userStore.GetByEmail(email)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create Session in Redis
	sessionID, err := h.sessionStore.Create(context.Background(), user.ID)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	// Set Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_session",
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   false, // Set to true in prod with HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect back to Authorization flow if it exists
	if oauthReq != "" {
		http.Redirect(w, r, oauthReq, http.StatusFound)
		return
	}

	http.Redirect(w, r, "/account", http.StatusFound)
}

func (h *IdentityHandler) LogoutFunc(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	cookie, err := r.Cookie("auth_session")
	if err == nil && cookie.Value != "" {
		// Invalidate session in Redis
		_ = h.sessionStore.Delete(context.Background(), cookie.Value)
	}

	// Clear the cookie in the browser
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})

	http.Redirect(w, r, "/login", http.StatusFound)
}

func (h *IdentityHandler) ForgotPasswordFunc(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		h.templates.ExecuteTemplate(w, "forgot_password.html", nil)
		return
	}

	email := r.FormValue("email")
	user, err := h.userStore.GetByEmail(email)
	if err != nil {
		// Do not reveal if email exists or not to prevent enumeration
		w.Write([]byte("If your email is registered, you will receive a reset link shortly."))
		return
	}

	resetToken, err := h.sessionStore.CreateResetToken(context.Background(), user.ID)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	resetLink := "http://" + r.Host + "/reset-password?token=" + resetToken

	if h.mailer != nil {
		err = h.mailer.SendPasswordReset(context.Background(), user.Email, resetLink)
		if err != nil {
			// Do not log the specific email out to the client
			http.Error(w, "Failed to dispatch email", http.StatusInternalServerError)
			return
		}
	} else {
		// Fallback logging for local testing if SMTP config is missing
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`Reset link generated (check logs/console). <br><a href="` + resetLink + `">Click here to test the reset flow</a>`))
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`Reset link dispatched! Please check your email inbox.`))
}

func (h *IdentityHandler) ResetPasswordFunc(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.FormValue("token") // Try Post body
	}

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		h.templates.ExecuteTemplate(w, "reset_password.html", map[string]string{
			"Token": token,
		})
		return
	}

	password := r.FormValue("password")
	if token == "" || password == "" {
		http.Error(w, "Missing inputs", http.StatusBadRequest)
		return
	}

	userID, err := h.sessionStore.GetUserByResetToken(context.Background(), token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	err = h.userStore.UpdatePassword(userID, string(hash))
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	// Invalidate the token so it can't be reused
	h.sessionStore.DeleteResetToken(context.Background(), token)

	w.Write([]byte("Password updated successfully! <a href='/login'>Login Now</a>"))
}
