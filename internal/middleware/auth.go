package middleware

import (
	"context"
	"net/http"
	"net/url"

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

// RequireAdmin enforces that the requester is both authenticated and an admin.
// Admin status is determined solely by user.IsAdmin in the database.
// Injects userID and adminRole into context for downstream handlers.
func RequireAdmin(sessionStore *redis.SessionStore, userStore *postgres.UserStore, next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		userID, err := sessionStore.GetUserFromSession(r)
		if err != nil {
			http.Redirect(w, r, "/login?req="+r.URL.Path, http.StatusFound)
			return
		}

		user, err := userStore.GetByID(userID)
		if err != nil || !user.IsAdmin {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), types.UserContextKey, userID)
		ctx = context.WithValue(ctx, types.AdminRoleContextKey, user.AdminRole)
		r = r.WithContext(ctx)
		next(w, r, ps)
	}
}

// RequireRole wraps a handler that is already behind RequireAdmin and enforces
// that the admin's role is one of the allowed roles. Must be applied after
// RequireAdmin so that AdminRoleContextKey is already set.
func RequireRole(next httprouter.Handle, roles ...string) httprouter.Handle {
	allowed := make(map[string]bool, len(roles))
	for _, role := range roles {
		allowed[role] = true
	}
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		adminRole, _ := r.Context().Value(types.AdminRoleContextKey).(string)
		if !allowed[adminRole] {
			http.Error(w, "403 Forbidden — insufficient admin role", http.StatusForbidden)
			return
		}
		next(w, r, ps)
	}
}

// InjectAdminStatus reads the userID already injected by RequireAuth and stores isAdmin bool in context.
// Also enforces DisabledAt — a disabled user with a live session is redirected to /login immediately.
// Must run inside RequireAuth in the chain — unauthenticated requests are rejected before reaching this.
func InjectAdminStatus(userStore *postgres.UserStore, next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		isAdmin := false
		if userID, ok := r.Context().Value(types.UserContextKey).(string); ok {
			if user, err := userStore.GetByID(userID); err == nil {
				if user.DisabledAt != nil {
					http.Redirect(w, r, "/login?error="+url.QueryEscape("Your account has been disabled"), http.StatusFound)
					return
				}
				if user.DeletedAt != nil {
					http.SetCookie(w, &http.Cookie{Name: "session_id", MaxAge: -1, Path: "/"})
					http.Redirect(w, r, "/login?error="+url.QueryEscape("Account not found"), http.StatusFound)
					return
				}
				isAdmin = user.IsAdmin
			} else {
				// GetByID returns ErrUserNotFound for deleted users (deleted_at IS NULL filter).
				// Clear the dangling session so subsequent requests don't repeat the DB lookup.
				http.SetCookie(w, &http.Cookie{Name: "session_id", MaxAge: -1, Path: "/"})
				http.Redirect(w, r, "/login?error="+url.QueryEscape("Account not found"), http.StatusFound)
				return
			}
		}
		ctx := context.WithValue(r.Context(), types.IsAdminContextKey, isAdmin)
		next(w, r.WithContext(ctx), ps)
	}
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
