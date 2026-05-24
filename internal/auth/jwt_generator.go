package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	oauth2errors "github.com/go-oauth2/oauth2/v4/errors"
	goredis "github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/iabhishekrajput/anekdote-auth/internal/models"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
)

// OrgMembershipReader is the minimal interface JWTGenerator needs.
// Implemented by *postgres.OrgStore.
type OrgMembershipReader interface {
	// GetMembership returns the user's active role in the org.
	// Returns "", nil if the user has no active membership (not an error).
	// Returns "", err for infrastructure failures (DB timeout, etc.).
	GetMembership(ctx context.Context, orgID, userID uuid.UUID) (role string, err error)
}

// GrantChecker verifies that a multi-org client has been granted access to an org.
// Implemented by *postgres.ClientStore.
type GrantChecker interface {
	HasGrant(ctx context.Context, clientID string, orgID uuid.UUID) (bool, error)
}

// UserReader is the minimal interface JWTGenerator needs for scope-driven claims.
// Implemented by *postgres.UserStore.
type UserReader interface {
	GetByID(id uuid.UUID) (*models.User, error)
}

// JWTGenerator implements oauth2.AccessGenerate
type JWTGenerator struct {
	keyStore     *crypto.KeyStore
	issuer       string
	orgStore     OrgMembershipReader
	grantChecker GrantChecker
	rdb          *goredis.Client
	userStore    UserReader
}

func NewJWTGenerator(keyStore *crypto.KeyStore, issuer string, orgStore OrgMembershipReader, grantChecker GrantChecker, rdb *goredis.Client, userStore UserReader) *JWTGenerator {
	return &JWTGenerator{
		keyStore:     keyStore,
		issuer:       issuer,
		orgStore:     orgStore,
		grantChecker: grantChecker,
		rdb:          rdb,
		userStore:    userStore,
	}
}

// Token creates a signed JWT Access Token and an optional opaque refresh token.
func (g *JWTGenerator) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	jti := uuid.New().String()

	// data.UserID may be encoded as "{userUUID}|{orgID}" when the user selected a specific
	// org during multi-org consent. Split here so sub is always a plain UUID.
	rawUserID := data.UserID
	subUserID := rawUserID
	var encodedOrgID string
	if idx := strings.Index(rawUserID, "|"); idx >= 0 {
		subUserID = rawUserID[:idx]
		encodedOrgID = rawUserID[idx+1:]
	}

	claims := jwt.MapClaims{
		"iss":   g.issuer,
		"sub":   subUserID,
		"aud":   data.Client.GetID(),
		"exp":   time.Now().Add(data.TokenInfo.GetAccessExpiresIn()).Unix(),
		"iat":   time.Now().Unix(),
		"jti":   jti,
		"scope": data.TokenInfo.GetScope(),
	}

	// Inject org claims when:
	//   (a) legacy single-org client: OrgClientInfo.OrgID != nil, or
	//   (b) multi-org consent: encodedOrgID is set in the UserID field.
	// Skip for client_credentials grants (data.UserID is empty).
	if subUserID != "" {
		var resolvedOrgID *uuid.UUID
		if encodedOrgID != "" {
			if id, parseErr := uuid.Parse(encodedOrgID); parseErr == nil {
				resolvedOrgID = &id
			}
		} else if oci, ok := data.Client.(*postgres.OrgClientInfo); ok && oci.OrgID != nil {
			resolvedOrgID = oci.OrgID
		}

		if resolvedOrgID != nil {
			userID, parseErr := uuid.Parse(subUserID)
			if parseErr != nil {
				return "", "", fmt.Errorf("invalid user_id in token data: %w", parseErr)
			}
			// Re-validate membership at token time (defends against tampering + membership removal between consent and exchange).
			role, lookupErr := g.orgStore.GetMembership(ctx, *resolvedOrgID, userID)
			if lookupErr != nil {
				return "", "", fmt.Errorf("org membership lookup failed: %w", lookupErr)
			}
			if role == "" {
				return "", "", oauth2errors.ErrAccessDenied
			}
			// For multi-org consent (encodedOrgID set), also verify the client has an
			// active grant for the selected org. This prevents a user who is a member of
			// org B from forging a token for a client that was never granted to org B.
			if encodedOrgID != "" && g.grantChecker != nil {
				needsGrantCheck := true
				if oci, isOrgClient := data.Client.(*postgres.OrgClientInfo); isOrgClient && oci.OrgID != nil && oci.OrgID.String() == encodedOrgID {
					needsGrantCheck = false
				}

				if needsGrantCheck {
					ok, grantErr := g.grantChecker.HasGrant(ctx, data.Client.GetID(), *resolvedOrgID)
					if grantErr != nil {
						return "", "", fmt.Errorf("grant check failed: %w", grantErr)
					}
					if !ok {
						return "", "", oauth2errors.ErrAccessDenied
					}
				}
			}
			claims["org_id"] = resolvedOrgID.String()
			claims["org_role"] = role

			if g.rdb != nil {
				g.rdb.SAdd(ctx, "oauth:user-org-tokens:"+subUserID+":"+resolvedOrgID.String(), jti)
			}
		}
	}

	// Inject profile/email claims when scopes are granted (user-context tokens only).
	if subUserID != "" && g.userStore != nil {
		g.injectScopeClaims(ctx, claims, subUserID, data.TokenInfo.GetScope())
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = g.keyStore.KeyID

	access, err = token.SignedString(g.keyStore.PrivateKey)
	if err != nil {
		return "", "", errors.New("internal server error signing jwt")
	}

	if g.rdb != nil {
		g.rdb.SAdd(ctx, "oauth:client-tokens:"+data.Client.GetID(), jti)
	}

	if isGenRefresh {
		refresh = uuid.New().String()
	}

	return access, refresh, nil
}

// injectScopeClaims adds email/profile claims to dst when the scope grants them.
// Uses exact-word matching to prevent false positives on scopes like "email_read".
func (g *JWTGenerator) injectScopeClaims(ctx context.Context, dst jwt.MapClaims, userIDStr, scope string) {
	scopeSet := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		scopeSet[s] = true
	}
	if !scopeSet["profile"] && !scopeSet["email"] {
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return
	}
	user, err := g.userStore.GetByID(userID)
	if err != nil {
		slog.Warn("user lookup failed for scope claims; claims omitted", "user_id", userIDStr, "error", err)
		return
	}
	if scopeSet["profile"] {
		if user.Name != "" {
			dst["name"] = user.Name
		}
		dst["updated_at"] = user.UpdatedAt.Unix()
	}
	if scopeSet["email"] {
		dst["email"] = user.Email
		dst["email_verified"] = user.IsVerified
	}
}

// GenerateIDToken creates a signed OIDC ID token for the authorization_code flow.
// sub is the user UUID string, aud is the client_id, accessToken is the just-issued access token.
func (g *JWTGenerator) GenerateIDToken(ctx context.Context, sub, aud, scope, accessToken string, expiry time.Duration) (string, error) {
	// at_hash: left half of SHA256 of the access token, base64url-encoded (OIDC Core §3.3.2.9)
	h := sha256.Sum256([]byte(accessToken))
	atHash := base64.RawURLEncoding.EncodeToString(h[:len(h)/2])

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":     g.issuer,
		"sub":     sub,
		"aud":     aud,
		"exp":     now.Add(expiry).Unix(),
		"iat":     now.Unix(),
		"at_hash": atHash,
	}

	if g.userStore != nil {
		g.injectScopeClaims(ctx, claims, sub, scope)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = g.keyStore.KeyID

	signed, err := token.SignedString(g.keyStore.PrivateKey)
	if err != nil {
		return "", errors.New("internal server error signing id_token")
	}
	return signed, nil
}
