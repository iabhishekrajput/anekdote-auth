package handlers

import (
	"log/slog"
	"net/http"

	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/iabhishekrajput/anekdote-auth/internal/session"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
	"github.com/julienschmidt/httprouter"
)

type OAuth2Handler struct {
	server       *server.Server
	sessionStore *session.Store
	revocStore   *redis.RevocationStore
}

func NewOAuth2Handler(srv *server.Server, sess *session.Store, rev *redis.RevocationStore) *OAuth2Handler {
	return &OAuth2Handler{
		server:       srv,
		sessionStore: sess,
		revocStore:   rev,
	}
}

// Authorize handles the initial redirect from the client
func (h *OAuth2Handler) Authorize(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// 1. Check if the user is logged in
	userID, err := h.sessionStore.GetUserFromSession(r)
	if err != nil || userID.String() == "00000000-0000-0000-0000-000000000000" {
		// Store the current URL to redirect back after login
		loginURL := "/login?req=" + r.URL.String()
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// 2. Wrap the request to provide the authenticated UserID to the OAuth2 Engine
	r.Form = r.URL.Query()

	err = h.server.HandleAuthorizeRequest(w, r)
	if err != nil {
		slog.Error("Authorize Request Error", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// Token handles the exchange of an Authorization Code (or Refresh Token) for an Access JWT
func (h *OAuth2Handler) Token(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	err := h.server.HandleTokenRequest(w, r)
	if err != nil {
		slog.Error("Token Request Error", "error", err)
		// The `go-oauth2` engine writes standard JSON error responses natively here.
	}
}

// Revoke handles invalidating a specific JWT by its JTI blocklist
func (h *OAuth2Handler) Revoke(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	jti := r.FormValue("jti")
	if jti == "" {
		http.Error(w, "missing jti parameter", http.StatusBadRequest)
		return
	}

	// Ideally calculate the remaining Time-To-Live from the token directly.
	// We'll hardcode 10 hours for now based on the `manage.DefaultAuthorizeCodeTokenCfg`
	err := h.revocStore.RevokeJTI(r.Context(), jti, 10)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"revoked"}`))
}
