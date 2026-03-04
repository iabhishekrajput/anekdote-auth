package auth

import (
	"log/slog"
	"time"

	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	oredis "github.com/go-oauth2/redis/v4"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
)

func BuildServer(
	clientStore *postgres.ClientStore,
	tokenStore *oredis.TokenStore,
	revStore *redis.RevocationStore,
	keyStore *crypto.KeyStore,
	issuer string,
) *server.Server {
	manager := manage.NewDefaultManager()

	// 1. Token Expiration Configuration
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// 2. Map the Postgres Client Store
	manager.MapClientStorage(clientStore)

	// 3. For Tokens, use the Redis store
	manager.MapTokenStorage(tokenStore)

	// 4. Custom JWT Generation
	jwtGen := NewJWTGenerator(keyStore, issuer)
	manager.MapAccessGenerate(jwtGen)

	// 5. Build the Server
	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(false) // Security: Require POST for tokens
	srv.SetClientInfoHandler(server.ClientFormHandler)

	// Enable PKCE (Proof Key for Code Exchange) Support
	// go-oauth2 handles PKCE generation and validation automatically if requested by the client.
	manager.SetAuthorizeCodeExp(time.Minute * 10)

	slog.Info("OAuth2 Server Manager Initialized", "issuer", issuer)

	return srv
}
