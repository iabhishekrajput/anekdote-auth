package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/iabhishekrajput/anekdote-auth/internal/config"
	"github.com/iabhishekrajput/anekdote-auth/internal/handlers"
	"github.com/iabhishekrajput/anekdote-auth/internal/middleware"
	redisstore "github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
	"github.com/julienschmidt/httprouter"
)

func NewRouter(
	cfg *config.Config,
	identH *handlers.IdentityHandler,
	oauthH *handlers.OAuth2Handler,
	discH *handlers.DiscoveryHandler,
	accountH *handlers.AccountHandler,
	orgH *handlers.OrgHandler,
	probeH *handlers.ProbeHandler,
	sessionStore *redisstore.SessionStore,
	redisClient *redis.Client,
) *httprouter.Router {
	router := httprouter.New()

	// Apply Middlewares
	secure := func(h httprouter.Handle) httprouter.Handle {
		return middleware.Chain(h,
			middleware.SecurityHeadersMiddleware(cfg.CORSAllowedOrigins),
			func(next httprouter.Handle) httprouter.Handle {
				return middleware.RateLimitMiddleware(redisClient, "global", 100, time.Minute, next)
			},
		)
	}

	authRateLimit := func(h httprouter.Handle) httprouter.Handle {
		return middleware.Chain(h, func(next httprouter.Handle) httprouter.Handle {
			return middleware.RateLimitMiddleware(redisClient, "auth", 10, time.Minute, next)
		})
	}

	secureUnauth := func(h httprouter.Handle) httprouter.Handle {
		return secure(authRateLimit(middleware.RedirectIfAuthenticated(sessionStore, h)))
	}

	// 1. Identity Endpoints (UI / Form Submissions)
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	router.GET("/register", secureUnauth(identH.RegisterFunc))
	router.POST("/register", secureUnauth(identH.RegisterFunc))

	router.GET("/login", secureUnauth(identH.LoginFunc))
	router.POST("/login", secureUnauth(identH.LoginFunc))

	router.GET("/verify-email", secureUnauth(identH.VerifyEmailFunc))
	router.POST("/verify-email", secureUnauth(identH.VerifyEmailFunc))

	router.GET("/forgot-password", secureUnauth(identH.ForgotPasswordFunc))
	router.POST("/forgot-password", secureUnauth(identH.ForgotPasswordFunc))

	router.GET("/reset-password", secureUnauth(identH.ResetPasswordFunc))
	router.POST("/reset-password", secureUnauth(identH.ResetPasswordFunc))

	router.POST("/logout", secure(identH.LogoutFunc))

	router.GET("/account", secure(middleware.RequireAuth(sessionStore, accountH.ViewAccount)))
	router.POST("/account/profile", secure(middleware.RequireAuth(sessionStore, accountH.UpdateProfile)))
	router.POST("/account/password", secure(middleware.RequireAuth(sessionStore, accountH.UpdatePassword)))

	// Org routes — /join is the public accept route (unauthenticated invite link)
	router.GET("/join", secure(orgH.AcceptInvite))
	router.GET("/account/orgs", secure(middleware.RequireAuth(sessionStore, orgH.ListOrgs)))
	router.POST("/account/orgs", secure(authRateLimit(middleware.RequireAuth(sessionStore, orgH.CreateOrg))))
	router.GET("/account/orgs/:slug", secure(middleware.RequireAuth(sessionStore, orgH.OrgDetail)))
	router.GET("/account/orgs/:slug/clients", secure(middleware.RequireAuth(sessionStore, orgH.OrgClients)))
	router.POST("/account/orgs/:slug/invites", secure(authRateLimit(middleware.RequireAuth(sessionStore, orgH.SendInvite))))
	router.POST("/account/orgs/:slug/invites/:token/revoke", secure(authRateLimit(middleware.RequireAuth(sessionStore, orgH.RevokeInvite))))
	router.POST("/account/orgs/:slug/members/:userID/role", secure(authRateLimit(middleware.RequireAuth(sessionStore, orgH.ChangeMemberRole))))
	router.POST("/account/orgs/:slug/members/:userID/remove", secure(authRateLimit(middleware.RequireAuth(sessionStore, orgH.RemoveMember))))
	router.POST("/account/orgs/:slug/clients", secure(authRateLimit(middleware.RequireAuth(sessionStore, orgH.RegisterClient))))
	router.POST("/account/orgs/:slug/clients/:clientID/delete", secure(authRateLimit(middleware.RequireAuth(sessionStore, orgH.DeleteClient))))
	router.POST("/account/orgs/:slug/clients/:clientID/rotate-secret", secure(authRateLimit(middleware.RequireAuth(sessionStore, orgH.RotateClientSecret))))

	// 2. OAuth2 Endpoints
	router.GET("/authorize", secure(oauthH.Authorize))
	router.POST("/authorize", secure(oauthH.Authorize)) // Depending on flow
	router.POST("/token", secure(oauthH.Token))
	router.POST("/revoke", secure(oauthH.Revoke))

	// 3. Discovery (OIDC/JWKS)
	router.GET("/.well-known/jwks.json", secure(discH.WellKnownJWKS))
	router.GET("/.well-known/openid-configuration", secure(discH.OpenIDConfiguration))

	// 4. Health/Readiness Probes
	router.GET("/healthz", probeH.Health)
	router.GET("/readyz", probeH.Ready)

	// 5. Static Files
	router.ServeFiles("/static/*filepath", http.Dir("web/static"))

	slog.Info("Router initialized with endpoints")
	return router
}
