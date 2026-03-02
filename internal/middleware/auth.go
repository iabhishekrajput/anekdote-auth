package middleware

import (
	"context"
	"net/http"

	"github.com/iabhishekrajput/anekdote-auth/internal/session"
	"github.com/iabhishekrajput/anekdote-auth/internal/types"
	"github.com/julienschmidt/httprouter"
)

// RequireAuth is a middleware that enforces an active user session.
func RequireAuth(sessionStore *session.Store, next httprouter.Handle) httprouter.Handle {
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

// RedirectIfAuthenticated is a middleware that redirects already logged-in users away from auth pages.
func RedirectIfAuthenticated(sessionStore *session.Store, next httprouter.Handle) httprouter.Handle {
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
