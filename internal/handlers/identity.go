package handlers

import (
	"context"
	"crypto/rand"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"time"

	"github.com/google/uuid"
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
	tmpl := template.Must(template.ParseGlob("web/templates/web/*.tmpl"))

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
		h.templates.ExecuteTemplate(w, "register.tmpl", nil)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	name := r.FormValue("name")

	if email == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		h.templates.ExecuteTemplate(w, "register.tmpl", map[string]string{"Error": "Email and password required"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.templates.ExecuteTemplate(w, "register.tmpl", map[string]string{"Error": "Server Error"})
		return
	}

	user, err := h.userStore.Create(email, name, string(hash))
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		h.templates.ExecuteTemplate(w, "register.tmpl", map[string]string{"Error": "Error creating user (maybe email exists)"})
		return
	}

	// Generate 6-digit OTP
	otp, _ := generateOTP()

	if h.mailer != nil {
		_ = h.sessionStore.CreateOTP(context.Background(), user.ID, otp)
		_ = h.mailer.SendOTP(context.Background(), user.Email, otp)
	} else {
		// Log the OTP if no mailer is configured for dev
		fmt.Printf("[DEV] OTP for %s: %s\n", email, otp)
		_ = h.sessionStore.CreateOTP(context.Background(), user.ID, otp)
	}

	http.Redirect(w, r, fmt.Sprintf("/verify-email?user_id=%s", user.ID.String()), http.StatusFound)
}

// Helper to generate a 6-digit cryptographic OTP
func generateOTP() (string, error) {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func (h *IdentityHandler) VerifyEmailFunc(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if r.Method == http.MethodGet {
		userID := r.URL.Query().Get("user_id")
		w.Header().Set("Content-Type", "text/html")
		h.templates.ExecuteTemplate(w, "verify_email.tmpl", map[string]string{
			"UserID": userID,
		})
		return
	}

	userIDStr := r.FormValue("user_id")
	otp := r.FormValue("otp")

	if userIDStr == "" || otp == "" {
		w.WriteHeader(http.StatusBadRequest)
		h.templates.ExecuteTemplate(w, "verify_email.tmpl", map[string]string{"Error": "User ID and OTP required", "UserID": userIDStr})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.templates.ExecuteTemplate(w, "verify_email.tmpl", map[string]string{"Error": "Invalid User ID format", "UserID": userIDStr})
		return
	}

	valid, err := h.sessionStore.VerifyOTP(context.Background(), userID, otp)
	if err != nil || !valid {
		w.WriteHeader(http.StatusUnauthorized)
		h.templates.ExecuteTemplate(w, "verify_email.tmpl", map[string]string{"Error": "Invalid or expired OTP", "UserID": userIDStr})
		return
	}

	// Update the database to mark user as verified
	err = h.userStore.UpdateVerified(userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.templates.ExecuteTemplate(w, "verify_email.tmpl", map[string]string{"Error": "Failed to update user status", "UserID": userIDStr})
		return
	}

	// Automatically log the user in by creating a session
	sessionID, err := h.sessionStore.Create(context.Background(), userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.templates.ExecuteTemplate(w, "login.tmpl", map[string]string{"Error": "Verified but failed to create session. Please login."})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_session",
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   false, // Set to true in prod
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/account", http.StatusFound)
}

func (h *IdentityHandler) LoginFunc(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if r.Method == http.MethodGet {
		reqURI := r.URL.Query().Get("req")
		w.Header().Set("Content-Type", "text/html")
		h.templates.ExecuteTemplate(w, "login.tmpl", map[string]string{
			"Req": reqURI,
		})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	oauthReq := r.FormValue("req") // Originating OAuth request URL

	user, err := h.userStore.GetByEmail(email)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		h.templates.ExecuteTemplate(w, "login.tmpl", map[string]string{"Error": "Invalid credentials", "Req": oauthReq})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		h.templates.ExecuteTemplate(w, "login.tmpl", map[string]string{"Error": "Invalid credentials", "Req": oauthReq})
		return
	}

	if !user.IsVerified {
		w.WriteHeader(http.StatusForbidden)
		h.templates.ExecuteTemplate(w, "login.tmpl", map[string]interface{}{
			"Error": template.HTML(fmt.Sprintf(`Please check your email and verify your account first. <a href="/verify-email?user_id=%s" style="color:#58a6ff; text-decoration:underline;">Enter Code</a>`, user.ID.String())),
			"Req":   oauthReq,
		})
		return
	}

	// Create Session in Redis
	sessionID, err := h.sessionStore.Create(context.Background(), user.ID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.templates.ExecuteTemplate(w, "login.tmpl", map[string]string{"Error": "Server Error", "Req": oauthReq})
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
		h.templates.ExecuteTemplate(w, "forgot_password.tmpl", nil)
		return
	}

	email := r.FormValue("email")
	user, err := h.userStore.GetByEmail(email)
	if err != nil {
		// Do not reveal if email exists or not to prevent enumeration
		h.templates.ExecuteTemplate(w, "forgot_password.tmpl", map[string]string{"Success": "If your email is registered, you will receive a reset link shortly."})
		return
	}

	resetToken, err := h.sessionStore.CreateResetToken(context.Background(), user.ID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.templates.ExecuteTemplate(w, "forgot_password.tmpl", map[string]string{"Error": "Error generating token"})
		return
	}

	resetLink := "http://" + r.Host + "/reset-password?token=" + resetToken

	if h.mailer != nil {
		err = h.mailer.SendPasswordReset(context.Background(), user.Email, resetLink)
		if err != nil {
			// Do not log the specific email out to the client
			w.WriteHeader(http.StatusInternalServerError)
			h.templates.ExecuteTemplate(w, "forgot_password.tmpl", map[string]string{"Error": "Failed to dispatch email"})
			return
		}
	} else {
		// Fallback logging for local testing if SMTP config is missing
		h.templates.ExecuteTemplate(w, "forgot_password.tmpl", map[string]interface{}{
			"Success": template.HTML(`Reset link generated (check logs/console). <br><a href="` + resetLink + `">Click here to test the reset flow</a>`),
		})
		return
	}

	h.templates.ExecuteTemplate(w, "forgot_password.tmpl", map[string]string{"Success": "Reset link dispatched! Please check your email inbox."})
}

func (h *IdentityHandler) ResetPasswordFunc(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.FormValue("token") // Try Post body
	}

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		h.templates.ExecuteTemplate(w, "reset_password.tmpl", map[string]string{
			"Token": token,
		})
		return
	}

	password := r.FormValue("password")
	if token == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		h.templates.ExecuteTemplate(w, "reset_password.tmpl", map[string]string{"Error": "Missing inputs", "Token": token})
		return
	}

	userID, err := h.sessionStore.GetUserByResetToken(context.Background(), token)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.templates.ExecuteTemplate(w, "reset_password.tmpl", map[string]string{"Error": "Invalid or expired token", "Token": token})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.templates.ExecuteTemplate(w, "reset_password.tmpl", map[string]string{"Error": "Server Error", "Token": token})
		return
	}

	err = h.userStore.UpdatePassword(userID, string(hash))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.templates.ExecuteTemplate(w, "reset_password.tmpl", map[string]string{"Error": "Failed to update password", "Token": token})
		return
	}

	// Invalidate the token so it can't be reused
	h.sessionStore.DeleteResetToken(context.Background(), token)

	h.templates.ExecuteTemplate(w, "login.tmpl", map[string]string{"Success": "Password updated successfully! Please login."})
}
