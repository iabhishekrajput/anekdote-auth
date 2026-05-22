package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/iabhishekrajput/anekdote-auth/internal/models"
	"github.com/julienschmidt/httprouter"
)

// UserInfoUserStore is the minimal interface UserInfoHandler needs for user lookup.
type UserInfoUserStore interface {
	GetByID(id uuid.UUID) (*models.User, error)
}

// UserInfoRevStore is the minimal interface UserInfoHandler needs for revocation checks.
type UserInfoRevStore interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

type UserInfoHandler struct {
	keyStore  *crypto.KeyStore
	userStore UserInfoUserStore
	revStore  UserInfoRevStore
}

func NewUserInfoHandler(userStore UserInfoUserStore, keyStore *crypto.KeyStore, revStore UserInfoRevStore) *UserInfoHandler {
	return &UserInfoHandler{
		keyStore:  keyStore,
		userStore: userStore,
		revStore:  revStore,
	}
}

// UserInfo serves GET and POST /userinfo per OIDC Core §5.3.
func (h *UserInfoHandler) UserInfo(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// 1. Extract Bearer token per RFC 6750
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="anekdote-auth"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "no_token"})
		return
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) || len(authHeader) == len(prefix) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "malformed Authorization header",
		})
		return
	}
	tokenStr := authHeader[len(prefix):]

	// 2. Parse and verify JWT with kid-based keyFunc + explicit algorithm allowlist
	parsedToken, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, errors.New("unexpected signing method")
			}
			kid, _ := token.Header["kid"].(string)
			if kid != h.keyStore.KeyID {
				return nil, errors.New("unknown kid")
			}
			return h.keyStore.PublicKey, nil
		},
		jwt.WithValidMethods([]string{"RS256"}),
	)
	if err != nil || !parsedToken.Valid {
		h.writeTokenError(w, "invalid_token", "token validation failed")
		return
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		h.writeTokenError(w, "invalid_token", "invalid claims")
		return
	}

	// 3. Check revocation — fail closed on Redis error to prevent claim disclosure
	jti, _ := claims["jti"].(string)
	if jti == "" {
		h.writeTokenError(w, "invalid_token", "missing jti")
		return
	}
	revoked, revErr := h.revStore.IsRevoked(r.Context(), jti)
	if revErr != nil || revoked {
		h.writeTokenError(w, "invalid_token", "token revoked")
		return
	}

	// 4. Extract sub — empty sub means client_credentials (no user context)
	sub, _ := claims["sub"].(string)
	if sub == "" {
		h.writeTokenError(w, "invalid_token", "no user context")
		return
	}
	userID, parseErr := uuid.Parse(sub)
	if parseErr != nil {
		h.writeTokenError(w, "invalid_token", "invalid sub")
		return
	}

	// 5. Fetch user; check for disabled account
	user, lookupErr := h.userStore.GetByID(userID)
	if lookupErr != nil {
		h.writeTokenError(w, "invalid_token", "user not found")
		return
	}
	if user.DisabledAt != nil {
		h.writeTokenError(w, "invalid_token", "account disabled")
		return
	}

	// 6. Build response from scope using exact-word matching
	scope, _ := claims["scope"].(string)
	scopeSet := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		scopeSet[s] = true
	}

	resp := map[string]interface{}{
		"sub": user.ID.String(),
	}
	if scopeSet["profile"] {
		resp["updated_at"] = user.UpdatedAt.Unix()
		if user.Name != "" {
			resp["name"] = user.Name
		}
	}
	if scopeSet["email"] {
		resp["email"] = user.Email
		resp["email_verified"] = user.IsVerified
	}

	// 7. Write response with required OIDC/RFC 6749 headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

func (h *UserInfoHandler) writeTokenError(w http.ResponseWriter, code, desc string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s" error_description="%s"`, code, desc))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}
