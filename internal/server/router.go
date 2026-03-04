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

	// 2. OAuth2 Endpoints
	router.GET("/authorize", secure(oauthH.Authorize))
	router.POST("/authorize", secure(oauthH.Authorize)) // Depending on flow
	router.POST("/token", secure(oauthH.Token))
	router.POST("/revoke", secure(oauthH.Revoke))

	// 3. Discovery (OIDC/JWKS)
	router.GET("/.well-known/jwks.json", secure(discH.WellKnownJWKS))
	router.GET("/.well-known/openid-configuration", secure(discH.OpenIDConfiguration))

	// 4. Static Files
	router.ServeFiles("/static/*filepath", http.Dir("web/static"))

	slog.Info("Router initialized with endpoints")
	return router
}
