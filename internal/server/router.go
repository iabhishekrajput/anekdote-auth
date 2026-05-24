package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/iabhishekrajput/anekdote-auth/internal/config"
	"github.com/iabhishekrajput/anekdote-auth/internal/handlers"
	"github.com/iabhishekrajput/anekdote-auth/internal/middleware"
	pgstore "github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
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
	adminH *handlers.AdminHandler,
	probeH *handlers.ProbeHandler,
	userInfoH *handlers.UserInfoHandler,
	sessionStore *redisstore.SessionStore,
	userStore *pgstore.UserStore,
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

	requireAdmin := func(h httprouter.Handle) httprouter.Handle {
		return secure(middleware.RequireAdmin(sessionStore, userStore, h))
	}

	// requireSuperAdmin wraps requireAdmin with an additional role check.
	// Use for all mutation routes that a readonly or org_admin should not access.
	requireSuperAdmin := func(h httprouter.Handle) httprouter.Handle {
		return requireAdmin(middleware.RequireRole(h, "superadmin"))
	}

	// requireSuperOrOrgAdmin allows both superadmin and org_admin roles.
	requireSuperOrOrgAdmin := func(h httprouter.Handle) httprouter.Handle {
		return requireAdmin(middleware.RequireRole(h, "superadmin", "org_admin"))
	}

	// withAuth chains RequireAuth then InjectAdminStatus so account/org handlers
	// always have both userID and isAdmin available in context.
	withAuth := func(h httprouter.Handle) httprouter.Handle {
		return secure(middleware.RequireAuth(sessionStore, middleware.InjectAdminStatus(userStore, h)))
	}

	withAuthRateLimit := func(h httprouter.Handle) httprouter.Handle {
		return secure(authRateLimit(middleware.RequireAuth(sessionStore, middleware.InjectAdminStatus(userStore, h))))
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
	router.POST("/verify-email/resend", authRateLimit(identH.ResendOTPFunc))

	router.GET("/resend-verification", secureUnauth(identH.ResendVerificationFunc))
	router.POST("/resend-verification", authRateLimit(identH.ResendVerificationFunc))

	router.GET("/forgot-password", secureUnauth(identH.ForgotPasswordFunc))
	router.POST("/forgot-password", secureUnauth(identH.ForgotPasswordFunc))

	router.GET("/reset-password", secureUnauth(identH.ResetPasswordFunc))
	router.POST("/reset-password", secureUnauth(identH.ResetPasswordFunc))

	router.POST("/logout", secure(identH.LogoutFunc))

	router.GET("/account", withAuth(accountH.ViewAccount))
	router.POST("/account/profile", withAuth(accountH.UpdateProfile))
	router.POST("/account/password", withAuth(accountH.UpdatePassword))

	// Org routes — /join is the public accept route (unauthenticated invite link)
	router.GET("/join", secure(orgH.AcceptInvite))
	router.GET("/account/orgs", withAuth(orgH.ListOrgs))
	router.POST("/account/orgs", withAuthRateLimit(orgH.CreateOrg))
	router.GET("/account/orgs/:slug", withAuth(orgH.OrgDetail))
	router.GET("/account/orgs/:slug/clients", withAuth(orgH.OrgClients))
	router.GET("/account/orgs/:slug/explore", withAuth(orgH.ExploreApps))
	router.POST("/account/orgs/:slug/invites", withAuthRateLimit(orgH.SendInvite))
	router.POST("/account/orgs/:slug/invites/:token/revoke", withAuthRateLimit(orgH.RevokeInvite))
	router.POST("/account/orgs/:slug/members/:userID/role", withAuthRateLimit(orgH.ChangeMemberRole))
	router.POST("/account/orgs/:slug/members/:userID/remove", withAuthRateLimit(orgH.RemoveMember))
	router.POST("/account/orgs/:slug/leave", withAuthRateLimit(orgH.LeaveOrg))
	router.POST("/account/orgs/:slug/transfer-ownership", withAuthRateLimit(orgH.TransferOwnershipAndLeave))
	router.POST("/account/orgs/:slug/clients", withAuthRateLimit(orgH.RegisterClient))
	router.POST("/account/orgs/:slug/clients/:clientID/delete", withAuthRateLimit(orgH.DeleteClient))
	router.POST("/account/orgs/:slug/clients/:clientID/rotate-secret", withAuthRateLimit(orgH.RotateClientSecret))
	router.POST("/account/orgs/:slug/delete", withAuthRateLimit(orgH.DeleteOrg))
	router.POST("/account/orgs/:slug/grants", withAuthRateLimit(orgH.GrantClientAccess))
	router.POST("/account/orgs/:slug/grants/:clientID/revoke", withAuthRateLimit(orgH.RevokeClientAccess))
	router.POST("/account/orgs/:slug/clients/:clientID/requests/:requestID/approve", withAuthRateLimit(orgH.ApproveGrantRequest))
	router.POST("/account/orgs/:slug/clients/:clientID/requests/:requestID/deny", withAuthRateLimit(orgH.DenyGrantRequest))
	router.GET("/account/orgs/:slug/clients/:clientID/edit", withAuth(orgH.EditClient))
	router.POST("/account/orgs/:slug/clients/:clientID/edit", withAuthRateLimit(orgH.EditClientPost))
	router.GET("/account/orgs/:slug/clients/:clientID/requests", withAuth(orgH.ClientRequestHistory))
	router.POST("/account/delete", withAuthRateLimit(accountH.DeleteSelf))

	// Admin routes — GET routes: any admin; mutations: role-scoped
	router.GET("/admin", requireAdmin(adminH.Dashboard))
	router.GET("/admin/users", requireAdmin(adminH.UserList))
	router.GET("/admin/users/:id", requireAdmin(adminH.UserDetail))
	router.POST("/admin/users/:id/disable", requireSuperAdmin(adminH.DisableUser))
	router.POST("/admin/users/:id/enable", requireSuperAdmin(adminH.EnableUser))
	router.POST("/admin/users/:id/promote", requireSuperAdmin(adminH.PromoteAdmin))
	router.POST("/admin/users/:id/demote", requireSuperAdmin(adminH.DemoteAdmin))
	router.POST("/admin/users/:id/admin-role", requireSuperAdmin(adminH.ChangeAdminRole))
	router.GET("/admin/clients", requireAdmin(adminH.ClientList))
	router.POST("/admin/clients/:id/delete", requireSuperAdmin(adminH.DeleteClient))
	router.GET("/admin/orgs", requireAdmin(adminH.OrgList))
	router.GET("/admin/orgs/:slug", requireAdmin(adminH.OrgDetail))
	router.POST("/admin/orgs/:slug/members/:user_id/remove", requireSuperOrOrgAdmin(adminH.RemoveOrgMember))
	router.POST("/admin/users/:id/delete", requireSuperAdmin(adminH.DeleteUser))
	router.POST("/admin/orgs/:slug/delete", requireSuperAdmin(adminH.DeleteOrg))
	router.GET("/admin/audit", requireAdmin(adminH.AuditLog))
	router.GET("/admin/audit/export.csv", requireAdmin(adminH.ExportAuditCSV))
	router.GET("/admin/grants", requireSuperAdmin(adminH.GrantList))
	router.POST("/admin/grants/:clientID/:orgID/revoke", requireSuperAdmin(adminH.RevokeGrant))

	// 2. OAuth2 Endpoints
	router.GET("/authorize", secure(oauthH.Authorize))
	router.POST("/authorize", secure(oauthH.Authorize)) // Depending on flow
	router.POST("/token", secure(oauthH.Token))
	router.POST("/revoke", secure(oauthH.Revoke))

	// 3. Discovery (OIDC/JWKS) + UserInfo
	router.GET("/.well-known/jwks.json", secure(discH.WellKnownJWKS))
	router.GET("/.well-known/openid-configuration", secure(discH.OpenIDConfiguration))
	// /userinfo: bearer-auth in handler, not RequireAuth (which uses cookie sessions).
	// Both GET and POST required per OIDC Core §5.3.
	router.GET("/userinfo", secure(userInfoH.UserInfo))
	router.POST("/userinfo", secure(userInfoH.UserInfo))

	// 4. Health/Readiness Probes
	router.GET("/healthz", probeH.Health)
	router.GET("/readyz", probeH.Ready)

	// 5. Static Files
	router.ServeFiles("/static/*filepath", http.Dir("web/static"))

	slog.Info("Router initialized with endpoints")
	return router
}
