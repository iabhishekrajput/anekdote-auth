package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/iabhishekrajput/anekdote-auth/internal/handlers"
	"github.com/iabhishekrajput/anekdote-auth/internal/middleware"
	"github.com/iabhishekrajput/anekdote-auth/internal/session"
	"github.com/julienschmidt/httprouter"
	"github.com/redis/go-redis/v9"
)

func NewRouter(
	identH *handlers.IdentityHandler,
	oauthH *handlers.OAuth2Handler,
	discH *handlers.DiscoveryHandler,
	accountH *handlers.AccountHandler,
	sessionStore *session.Store,
	redisClient *redis.Client,
) *httprouter.Router {
	router := httprouter.New()

	// Apply Middlewares
	secure := func(h httprouter.Handle) httprouter.Handle {
		return middleware.Chain(h,
			middleware.SecurityHeadersMiddleware,
			func(next httprouter.Handle) httprouter.Handle {
				return middleware.RateLimitMiddleware(redisClient, 100, time.Minute, next)
			},
		)
	}

	secureUnauth := func(h httprouter.Handle) httprouter.Handle {
		return secure(middleware.RedirectIfAuthenticated(sessionStore, h))
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
