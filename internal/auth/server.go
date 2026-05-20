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
	orgReader OrgMembershipReader,
	issuer string,
) *server.Server {
	manager := manage.NewDefaultManager()

	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	manager.MapClientStorage(clientStore)
	manager.MapTokenStorage(tokenStore)

	jwtGen := NewJWTGenerator(keyStore, issuer, orgReader)
	manager.MapAccessGenerate(jwtGen)

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(false)
	srv.SetClientInfoHandler(server.ClientFormHandler)

	manager.SetAuthorizeCodeExp(time.Minute * 10)

	slog.Info("OAuth2 Server Manager Initialized", "issuer", issuer)

	return srv
}
