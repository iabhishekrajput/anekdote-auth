package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/iabhishekrajput/anekdote-auth/internal/config"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
	"github.com/iabhishekrajput/anekdote-auth/internal/types"
	"github.com/julienschmidt/httprouter"
)

// RequireAuth is a middleware that enforces an active user session.
func RequireAuth(sessionStore *redis.SessionStore, next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		userID, err := sessionStore.GetUserFromSession(r)
		if err != nil {
			// No valid session, redirect to login
			http.Redirect(w, r, "/login?req="+r.URL.Path, http.StatusFound)
			return
		}

		// Inject User ID into request context
		ctx := context.WithValue(r.Context(), types.UserContextKey, userID)
		r = r.WithContext(ctx)

		next(w, r, ps)
	}
}

// RequireAdmin enforces that the requester is both authenticated and an admin email.
// Admin status is re-checked against cfg.AdminEmails on every request so that removing
// an email from config takes effect immediately without waiting for session expiry.
func RequireAdmin(cfg *config.Config, sessionStore *redis.SessionStore, userStore *postgres.UserStore, next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		userID, err := sessionStore.GetUserFromSession(r)
		if err != nil {
			http.Redirect(w, r, "/login?req="+r.URL.Path, http.StatusFound)
			return
		}

		user, err := userStore.GetByID(userID)
		if err != nil || !isAdminEmail(cfg.AdminEmails, user.Email) {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), types.UserContextKey, userID)
		r = r.WithContext(ctx)
		next(w, r, ps)
	}
}

func isAdminEmail(adminEmails []string, email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	for _, ae := range adminEmails {
		if ae == email {
			return true
		}
	}
	return false
}

// RedirectIfAuthenticated is a middleware that redirects already logged-in users away from auth pages.
func RedirectIfAuthenticated(sessionStore *redis.SessionStore, next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		_, err := sessionStore.GetUserFromSession(r)
		if err == nil {
			// User is already logged in, redirect to account
			http.Redirect(w, r, "/account", http.StatusFound)
			return
		}

		next(w, r, ps)
	}
}
