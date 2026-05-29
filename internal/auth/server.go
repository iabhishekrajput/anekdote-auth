package auth

import (
	"log/slog"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	oredis "github.com/go-oauth2/redis/v4"
	goredis "github.com/go-redis/redis/v8"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
)

func BuildServer(
	clientStore *postgres.ClientStore,
	tokenStore *oredis.TokenStore,
	revStore *redis.RevocationStore,
	keyStore *crypto.KeyStore,
	orgReader OrgMembershipReader,
	issuer string,
	rdb *goredis.Client,
	userStore UserReader,
) (*server.Server, *JWTGenerator) {
	manager := manage.NewDefaultManager()

	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	manager.MapClientStorage(clientStore)
	manager.MapTokenStorage(tokenStore)

	jwtGen := NewJWTGenerator(keyStore, issuer, orgReader, clientStore, rdb, userStore, clientStore)
	manager.MapAccessGenerate(jwtGen)

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(false)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	srv.Config.ForcePKCE = true
	srv.SetAllowedGrantType(
		oauth2.AuthorizationCode,
		oauth2.Refreshing,
		oauth2.ClientCredentials,
	)

	manager.SetAuthorizeCodeExp(time.Minute * 10)

	slog.Info("OAuth2 Server Manager Initialized", "issuer", issuer)

	return srv, jwtGen
}
