package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	oauth2errors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
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

// JWTGenerator implements oauth2.AccessGenerate
type JWTGenerator struct {
	keyStore *crypto.KeyStore
	issuer   string
	orgStore OrgMembershipReader
}

func NewJWTGenerator(keyStore *crypto.KeyStore, issuer string, orgStore OrgMembershipReader) *JWTGenerator {
	return &JWTGenerator{
		keyStore: keyStore,
		issuer:   issuer,
		orgStore: orgStore,
	}
}

// Token creates a signed JWT Access Token and an optional opaque refresh token.
func (g *JWTGenerator) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	jti := uuid.New().String()

	claims := jwt.MapClaims{
		"iss":   g.issuer,
		"sub":   data.UserID,
		"aud":   data.Client.GetID(),
		"exp":   time.Now().Add(data.TokenInfo.GetAccessExpiresIn()).Unix(),
		"iat":   time.Now().Unix(),
		"jti":   jti,
		"scope": data.TokenInfo.GetScope(),
	}

	// Inject org claims only for org-scoped clients with a user context.
	// Skip for client_credentials grants (data.UserID is empty).
	if oci, ok := data.Client.(*postgres.OrgClientInfo); ok && oci.OrgID != nil && data.UserID != "" {
		userID, parseErr := uuid.Parse(data.UserID)
		if parseErr != nil {
			return "", "", fmt.Errorf("invalid user_id in token data: %w", parseErr)
		}
		role, lookupErr := g.orgStore.GetMembership(ctx, *oci.OrgID, userID)
		if lookupErr != nil {
			return "", "", fmt.Errorf("org membership lookup failed: %w", lookupErr)
		}
		if role == "" {
			return "", "", oauth2errors.ErrAccessDenied
		}
		claims["org_id"] = oci.OrgID.String()
		claims["org_role"] = role
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = g.keyStore.KeyID

	access, err = token.SignedString(g.keyStore.PrivateKey)
	if err != nil {
		return "", "", errors.New("internal server error signing jwt")
	}

	if isGenRefresh {
		refresh = uuid.New().String()
	}

	return access, refresh, nil
}
