package handlers

import (
	"context"
	"crypto/rand"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/config"
	"github.com/iabhishekrajput/anekdote-auth/internal/mailer"
	"github.com/iabhishekrajput/anekdote-auth/internal/session"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/nosurf"
	"golang.org/x/crypto/bcrypt"
)

type IdentityHandler struct {
	config       *config.Config
	userStore    *postgres.UserStore
	sessionStore *session.Store
	mailer       *mailer.Mailer
	templates    *template.Template
}

func NewIdentityHandler(cfg *config.Config, uStore *postgres.UserStore, sStore *session.Store, mailSvc *mailer.Mailer) *IdentityHandler {
	// Pre-parse templates for performance
	tmpl := template.Must(template.ParseGlob("web/templates/web/*.tmpl"))

	return &IdentityHandler{
		config:       cfg,
		userStore:    uStore,
		sessionStore: sStore,
		mailer:       mailSvc,
		templates:    tmpl,
	}
}

func (h *IdentityHandler) render(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
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

	data["CSRFField"] = template.HTML(fmt.Sprintf(`<input type="hidden" name="csrf_token" value="%s">`, nosurf.Token(r)))
	h.templates.ExecuteTemplate(w, name, data)
}

func (h *IdentityHandler) RegisterFunc(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		h.render(w, r, "register.tmpl", nil)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	name := r.FormValue("name")

	if email == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		h.render(w, r, "register.tmpl", map[string]interface{}{"Error": "Email and password required"})
		return
	}

	if err := validatePassword(password); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.render(w, r, "register.tmpl", map[string]interface{}{"Error": err.Error()})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.render(w, r, "register.tmpl", map[string]interface{}{"Error": "Server Error"})
		return
	}

	user, err := h.userStore.Create(email, name, string(hash))
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		h.render(w, r, "register.tmpl", map[string]interface{}{"Error": "Error creating user (maybe email exists)"})
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

// validatePassword checks if a password meets complexity requirements
func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	if !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one number")
	}
	if !regexp.MustCompile(`[!@#~$%^&*(),.?":{}|<>]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one special character")
	}
	return nil
}

func (h *IdentityHandler) VerifyEmailFunc(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if r.Method == http.MethodGet {
		userID := r.URL.Query().Get("user_id")
		w.Header().Set("Content-Type", "text/html")
		h.render(w, r, "verify_email.tmpl", map[string]interface{}{
			"UserID": userID,
		})
		return
	}

	userIDStr := r.FormValue("user_id")
	otp := r.FormValue("otp")

	if userIDStr == "" || otp == "" {
		w.WriteHeader(http.StatusBadRequest)
		h.render(w, r, "verify_email.tmpl", map[string]interface{}{"Error": "User ID and OTP required", "UserID": userIDStr})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.render(w, r, "verify_email.tmpl", map[string]interface{}{"Error": "Invalid User ID format", "UserID": userIDStr})
		return
	}

	valid, err := h.sessionStore.VerifyOTP(context.Background(), userID, otp)
	if err != nil || !valid {
		w.WriteHeader(http.StatusUnauthorized)
		h.render(w, r, "verify_email.tmpl", map[string]interface{}{"Error": "Invalid or expired OTP", "UserID": userIDStr})
		return
	}

	// Update the database to mark user as verified
	err = h.userStore.UpdateVerified(userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.render(w, r, "verify_email.tmpl", map[string]interface{}{"Error": "Failed to update user status", "UserID": userIDStr})
		return
	}

	// Automatically log the user in by creating a session
	sessionID, err := h.sessionStore.Create(context.Background(), userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.render(w, r, "login.tmpl", map[string]interface{}{"Error": "Verified but failed to create session. Please login."})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_session",
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   h.config.AppEnv == "production",
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/account", http.StatusFound)
}

func (h *IdentityHandler) LoginFunc(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if r.Method == http.MethodGet {
		reqURI := r.URL.Query().Get("req")
		w.Header().Set("Content-Type", "text/html")
		h.render(w, r, "login.tmpl", map[string]interface{}{
			"Req": reqURI,
		})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	oauthReq := r.FormValue("req") // Originating OAuth request URL

	fails, _ := h.sessionStore.GetFailedLogin(context.Background(), email)
	if fails >= 5 {
		w.WriteHeader(http.StatusTooManyRequests)
		h.render(w, r, "login.tmpl", map[string]interface{}{"Error": "Account locked due to too many failed attempts. Try again in 15 minutes.", "Req": oauthReq})
		return
	}

	user, err := h.userStore.GetByEmail(email)
	if err != nil {
		h.sessionStore.IncrementFailedLogin(context.Background(), email)
		w.WriteHeader(http.StatusUnauthorized)
		h.render(w, r, "login.tmpl", map[string]interface{}{"Error": "Invalid credentials", "Req": oauthReq})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		h.sessionStore.IncrementFailedLogin(context.Background(), email)
		w.WriteHeader(http.StatusUnauthorized)
		h.render(w, r, "login.tmpl", map[string]interface{}{"Error": "Invalid credentials", "Req": oauthReq})
		return
	}

	h.sessionStore.ResetFailedLogin(context.Background(), email)

	if !user.IsVerified {
		w.WriteHeader(http.StatusForbidden)
		h.render(w, r, "login.tmpl", map[string]interface{}{
			"Error": template.HTML(fmt.Sprintf(`Please check your email and verify your account first. <a href="/verify-email?user_id=%s" style="color:#58a6ff; text-decoration:underline;">Enter Code</a>`, user.ID.String())),
			"Req":   oauthReq,
		})
		return
	}

	// Create Session in Redis
	sessionID, err := h.sessionStore.Create(context.Background(), user.ID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.render(w, r, "login.tmpl", map[string]interface{}{"Error": "Server Error", "Req": oauthReq})
		return
	}

	// Set Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_session",
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   h.config.AppEnv == "production",
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
		h.render(w, r, "forgot_password.tmpl", nil)
		return
	}

	email := r.FormValue("email")
	user, err := h.userStore.GetByEmail(email)
	if err != nil {
		// Do not reveal if email exists or not to prevent enumeration
		h.render(w, r, "forgot_password.tmpl", map[string]interface{}{"Success": "If your email is registered, you will receive a reset link shortly."})
		return
	}

	resetToken, err := h.sessionStore.CreateResetToken(context.Background(), user.ID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.render(w, r, "forgot_password.tmpl", map[string]interface{}{"Error": "Error generating token"})
		return
	}

	resetLink := "http://" + r.Host + "/reset-password?token=" + resetToken

	if h.mailer != nil {
		err = h.mailer.SendPasswordReset(context.Background(), user.Email, resetLink)
		if err != nil {
			// Do not log the specific email out to the client
			w.WriteHeader(http.StatusInternalServerError)
			h.render(w, r, "forgot_password.tmpl", map[string]interface{}{"Error": "Failed to dispatch email"})
			return
		}
	} else {
		// Fallback logging for local testing if SMTP config is missing
		h.render(w, r, "forgot_password.tmpl", map[string]interface{}{
			"Success": template.HTML(`Reset link generated (check logs/console). <br><a href="` + resetLink + `">Click here to test the reset flow</a>`),
		})
		return
	}

	h.render(w, r, "forgot_password.tmpl", map[string]interface{}{"Success": "Reset link dispatched! Please check your email inbox."})
}

func (h *IdentityHandler) ResetPasswordFunc(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.FormValue("token") // Try Post body
	}

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		h.render(w, r, "reset_password.tmpl", map[string]interface{}{
			"Token": token,
		})
		return
	}

	password := r.FormValue("password")
	if token == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		h.render(w, r, "reset_password.tmpl", map[string]interface{}{"Error": "Missing inputs", "Token": token})
		return
	}

	if err := validatePassword(password); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.render(w, r, "reset_password.tmpl", map[string]interface{}{"Error": err.Error(), "Token": token})
		return
	}

	userID, err := h.sessionStore.GetUserByResetToken(context.Background(), token)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.render(w, r, "reset_password.tmpl", map[string]interface{}{"Error": "Invalid or expired token", "Token": token})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.render(w, r, "reset_password.tmpl", map[string]interface{}{"Error": "Server Error", "Token": token})
		return
	}

	err = h.userStore.UpdatePassword(userID, string(hash))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.render(w, r, "reset_password.tmpl", map[string]interface{}{"Error": "Failed to update password", "Token": token})
		return
	}

	// Invalidate the token so it can't be reused
	h.sessionStore.DeleteResetToken(context.Background(), token)

	h.render(w, r, "login.tmpl", map[string]interface{}{"Success": "Password updated successfully! Please login."})
}
