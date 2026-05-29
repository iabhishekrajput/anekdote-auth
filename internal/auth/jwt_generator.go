package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"slices"
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
	GetMembership(ctx context.Context, orgID, userID string) (role string, err error)
}

// GrantChecker verifies that a multi-org client has been granted access to an org,
// and provides the per-org scope restriction if one has been set.
// Implemented by *postgres.ClientStore.
type GrantChecker interface {
	HasGrant(ctx context.Context, clientID string, orgID string) (bool, error)
	// GetGrantAllowedScopes returns the scope whitelist for a grant (nil = unrestricted).
	GetGrantAllowedScopes(ctx context.Context, clientID string, orgID string) (*string, error)
}

// UserReader is the minimal interface JWTGenerator needs for scope-driven claims.
// Implemented by *postgres.UserStore.
type UserReader interface {
	GetByID(id string) (*models.User, error)
}

// CustomClaimsReader reads per-client custom claims filtered by scope and destination.
// Implemented by *postgres.ClientStore.
type CustomClaimsReader interface {
	GetCustomClaims(ctx context.Context, clientID, grantedScope, destination string) (map[string]any, error)
	GetCustomClaimsForContext(ctx context.Context, clientID, grantedScope, destination string, claimCtx postgres.CustomClaimContext) (map[string]any, error)
}

// reservedClaims is the lowercase set of claim names that may not be overridden.
var reservedClaims = map[string]struct{}{
	"sub": {}, "iss": {}, "aud": {}, "exp": {}, "iat": {}, "jti": {}, "nbf": {},
	"scope": {}, "org_id": {}, "org_role": {}, "name": {}, "email": {},
	"email_verified": {}, "updated_at": {}, "at_hash": {},
	"auth_time": {}, "nonce": {}, "acr": {}, "amr": {}, "azp": {}, "client_id": {},
	"preferred_username": {},
}

// JWTGenerator implements oauth2.AccessGenerate
type JWTGenerator struct {
	keyStore     *crypto.KeyStore
	issuer       string
	orgStore     OrgMembershipReader
	grantChecker GrantChecker
	rdb          *goredis.Client
	userStore    UserReader
	claimsReader CustomClaimsReader
}

func NewJWTGenerator(keyStore *crypto.KeyStore, issuer string, orgStore OrgMembershipReader, grantChecker GrantChecker, rdb *goredis.Client, userStore UserReader, claimsReader CustomClaimsReader) *JWTGenerator {
	return &JWTGenerator{
		keyStore:     keyStore,
		issuer:       issuer,
		orgStore:     orgStore,
		grantChecker: grantChecker,
		rdb:          rdb,
		userStore:    userStore,
		claimsReader: claimsReader,
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

	// Effective scope may be narrowed by a per-org grant restriction (set later).
	effectiveScope := data.TokenInfo.GetScope()
	var claimCtx postgres.CustomClaimContext

	claims := jwt.MapClaims{
		"iss": g.issuer,
		"sub": subUserID,
		"aud": data.Client.GetID(),
		"exp": time.Now().Add(data.TokenInfo.GetAccessExpiresIn()).Unix(),
		"iat": time.Now().Unix(),
		"jti": jti,
		// "scope" is set after org resolution so the per-org restriction can narrow it.
	}

	// Inject org claims when:
	//   (a) legacy single-org client: OrgClientInfo.OrgID != nil, or
	//   (b) multi-org consent: encodedOrgID is set in the UserID field.
	// Skip for client_credentials grants (data.UserID is empty).
	if subUserID != "" {
		var resolvedOrgID *string
		if encodedOrgID != "" {
			eid := encodedOrgID
			resolvedOrgID = &eid
		} else if oci, ok := data.Client.(*postgres.OrgClientInfo); ok && oci.OrgID != nil {
			resolvedOrgID = oci.OrgID
		}

		if resolvedOrgID != nil {
			// Re-validate membership at token time (defends against tampering + membership removal between consent and exchange).
			role, lookupErr := g.orgStore.GetMembership(ctx, *resolvedOrgID, subUserID)
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
				if oci, isOrgClient := data.Client.(*postgres.OrgClientInfo); isOrgClient && oci.OrgID != nil && *oci.OrgID == encodedOrgID {
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
					// Enforce per-org scope restriction, if one has been set.
					if allowedScopes, scopeErr := g.grantChecker.GetGrantAllowedScopes(ctx, data.Client.GetID(), *resolvedOrgID); scopeErr == nil && allowedScopes != nil {
						effectiveScope = intersectScopes(effectiveScope, *allowedScopes)
					}
				}
			}
			claims["org_id"] = *resolvedOrgID
			claims["org_role"] = role
			claimCtx.OrgID = *resolvedOrgID
			claimCtx.OrgRole = role

			if g.rdb != nil {
				g.rdb.SAdd(ctx, "oauth:user-org-tokens:"+subUserID+":"+*resolvedOrgID, jti)
			}
		}
	}

	// Service account: client_credentials grant with org_id binding on the client record.
	// Inject org_id so the Management API can enforce org ownership without a user session.
	if subUserID == "" {
		if oci, ok := data.Client.(*postgres.OrgClientInfo); ok && oci.OrgID != nil {
			claims["org_id"] = *oci.OrgID
			claimCtx.OrgID = *oci.OrgID
		}
	}

	claims["scope"] = effectiveScope

	// Inject profile/email claims when scopes are granted (user-context tokens only).
	// Use effectiveScope so per-org restrictions are respected in scope-driven claims.
	var tokenUser *models.User
	if subUserID != "" && g.userStore != nil {
		tokenUser = g.injectScopeClaims(ctx, claims, subUserID, effectiveScope)
		claimCtx.UserID = subUserID
		if tokenUser == nil && g.claimsReader != nil {
			tokenUser, _ = g.userStore.GetByID(subUserID)
		}
		if tokenUser != nil {
			claimCtx.Email = tokenUser.Email
			claimCtx.Name = tokenUser.Name
			claimCtx.Username = tokenUser.Username
		}
	}

	// Inject per-client custom claims (fail-closed: error blocks token issuance).
	if g.claimsReader != nil {
		if err := g.injectCustomClaims(ctx, claims, data.Client.GetID(), effectiveScope, "access_token", claimCtx); err != nil {
			return "", "", fmt.Errorf("custom claims read failed: %w", err)
		}
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

	// OIDC §11: only mint a refresh token when the client requested offline_access.
	// Applies to user grants (authorization_code). client_credentials never receives
	// a refresh token (library default; refresh_token is unnecessary for that flow).
	if isGenRefresh && subUserID != "" && hasScope(effectiveScope, "offline_access") {
		refresh = uuid.New().String()
	}

	return access, refresh, nil
}

// injectScopeClaims adds email/profile claims to dst when the scope grants them.
// Uses exact-word matching to prevent false positives on scopes like "email_read".
func (g *JWTGenerator) injectScopeClaims(ctx context.Context, dst jwt.MapClaims, userIDStr, scope string) *models.User {
	scopeSet := make(map[string]bool)
	for s := range strings.FieldsSeq(scope) {
		scopeSet[s] = true
	}
	if !scopeSet["profile"] && !scopeSet["email"] {
		return nil
	}
	user, err := g.userStore.GetByID(userIDStr)
	if err != nil {
		slog.Warn("user lookup failed for scope claims; claims omitted", "user_id", userIDStr, "error", err)
		return nil
	}
	if scopeSet["profile"] {
		if user.Name != "" {
			dst["name"] = user.Name
		}
		if user.Username != "" {
			dst["preferred_username"] = user.Username
		}
		dst["updated_at"] = user.UpdatedAt.Unix()
	}
	if scopeSet["email"] {
		dst["email"] = user.Email
		dst["email_verified"] = user.IsVerified
	}
	return user
}

// hasScope reports whether scope (space-delimited) contains target as an exact token.
func hasScope(scope, target string) bool {
	return slices.Contains(strings.Fields(scope), target)
}

// intersectScopes returns only the scopes from requested that are present in allowed.
func intersectScopes(requested, allowed string) string {
	allowedSet := make(map[string]bool)
	for s := range strings.FieldsSeq(allowed) {
		allowedSet[s] = true
	}
	var result []string
	for s := range strings.FieldsSeq(requested) {
		if allowedSet[s] {
			result = append(result, s)
		}
	}
	return strings.Join(result, " ")
}

// GenerateIDToken creates a signed OIDC ID token for the authorization_code flow.
// sub is the user UUID string, aud is the client_id, accessToken is the just-issued access token.
// nonce is echoed back when non-empty (OIDC Core §3.1.3.6).
func (g *JWTGenerator) GenerateIDToken(ctx context.Context, sub, aud, scope, accessToken string, expiry time.Duration, nonce string) (string, error) {
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

	if nonce != "" {
		claims["nonce"] = nonce
	}

	claimCtx := postgres.CustomClaimContext{UserID: sub}
	parser := jwt.NewParser()
	if parsed, _, parseErr := parser.ParseUnverified(accessToken, jwt.MapClaims{}); parseErr == nil {
		if accessClaims, ok := parsed.Claims.(jwt.MapClaims); ok {
			if v, _ := accessClaims["email"].(string); v != "" {
				claims["email"] = v
				claimCtx.Email = v
			}
			if v, _ := accessClaims["name"].(string); v != "" {
				claims["name"] = v
				claimCtx.Name = v
			}
			if v, _ := accessClaims["preferred_username"].(string); v != "" {
				claims["preferred_username"] = v
				claimCtx.Username = v
			}
			if v, ok := accessClaims["email_verified"].(bool); ok {
				claims["email_verified"] = v
			}
			if v, ok := accessClaims["updated_at"].(float64); ok {
				claims["updated_at"] = int64(v)
			}
			if v, _ := accessClaims["org_id"].(string); v != "" {
				claimCtx.OrgID = v
			}
			if v, _ := accessClaims["org_role"].(string); v != "" {
				claimCtx.OrgRole = v
			}
		}
	}

	// Inject per-client custom claims into id_token.
	if g.claimsReader != nil {
		if err := g.injectCustomClaims(ctx, claims, aud, scope, "id_token", claimCtx); err != nil {
			return "", fmt.Errorf("custom claims read failed for id_token: %w", err)
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = g.keyStore.KeyID

	signed, err := token.SignedString(g.keyStore.PrivateKey)
	if err != nil {
		return "", errors.New("internal server error signing id_token")
	}
	return signed, nil
}

// injectCustomClaims reads per-client custom claims filtered by scope and destination,
// and merges them into dst. Reserved keys are silently skipped (defensive guard).
func (g *JWTGenerator) injectCustomClaims(ctx context.Context, dst jwt.MapClaims, clientID, grantedScope, destination string, claimCtx postgres.CustomClaimContext) error {
	custom, err := g.claimsReader.GetCustomClaimsForContext(ctx, clientID, grantedScope, destination, claimCtx)
	if err != nil {
		return err
	}
	for k, v := range custom {
		if _, reserved := reservedClaims[strings.ToLower(k)]; reserved {
			slog.Warn("custom claim key is reserved; skipping", "key", k, "client_id", clientID)
			continue
		}
		switch v.(type) {
		case string, float64, bool:
			dst[k] = v
		default:
			slog.Warn("custom claim has unsupported value type; skipping", "key", k, "client_id", clientID)
		}
	}
	return nil
}
