package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/iabhishekrajput/anekdote-auth/internal/auth"
	"github.com/iabhishekrajput/anekdote-auth/internal/config"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/iabhishekrajput/anekdote-auth/internal/handlers"
	"github.com/iabhishekrajput/anekdote-auth/internal/mailer"
	"github.com/iabhishekrajput/anekdote-auth/internal/middleware"
	"github.com/iabhishekrajput/anekdote-auth/internal/server"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
	"github.com/justinas/nosurf"
)

func runAuditRetention(auditStore *postgres.AuditStore, days int) {
	cutoff := time.Now().AddDate(0, 0, -days)
	n, err := auditStore.DeleteOlderThan(context.Background(), cutoff)
	if err != nil {
		slog.Error("audit: retention cleanup failed", "err", err)
	} else if n > 0 {
		slog.Info("audit: retention cleanup", "deleted", n, "older_than_days", days)
	}
}

func main() {
	// Initialize structured logger. Level is configurable via LOG_LEVEL env var
	// (debug, info, warn, error). Defaults to info.
	logLevel := slog.LevelInfo
	if raw := os.Getenv("LOG_LEVEL"); raw != "" {
		if err := logLevel.UnmarshalText([]byte(raw)); err != nil {
			slog.Warn("invalid LOG_LEVEL, defaulting to info", "value", raw)
		}
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))

	slog.Info("Starting anekdote auth server...")

	cfg := config.Load()
	if err := config.Validate(cfg); err != nil {
		slog.Error("Invalid configuration", "error", err)
		os.Exit(1)
	}

	// 1. Initialize Datastores
	db, err := postgres.InitDB(cfg.DBDsn)
	if err != nil {
		slog.Error("Failed to connect to Postgres", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	rdb, err := redis.InitRedis(cfg.RedisDSN)
	if err != nil {
		slog.Error("Failed to connect to Redis", "error", err)
		os.Exit(1)
	}

	// 2. Load Crypto Keys
	keys, err := crypto.LoadKeys(cfg.RSAPrivateKey, cfg.RSAPublicKey)
	if err != nil {
		slog.Error("Failed to load RSA Keys", "error", err)
		os.Exit(1)
	}

	// 3. Initialize Stores
	userStore := postgres.NewUserStore(db)
	clientStore := postgres.NewClientStore(db)
	orgStore := postgres.NewOrgStore(db)
	auditStore := postgres.NewAuditStore(db)

	sessionStore := redis.NewSessionStore(rdb)
	revocStore := redis.NewRevocationStore(rdb)
	tokenStore := redis.NewTokenStore(rdb)

	// 4. Initialize Core Server
	issuer := cfg.AppURL
	oauth2Srv, jwtGen := auth.BuildServer(clientStore, tokenStore, revocStore, keys, orgStore, issuer, rdb, userStore)

	// 5. Initialize Mailer
	mailSvc, err := mailer.NewMailer(cfg)
	if err != nil {
		slog.Warn("Failed to initialize mailer, forgot password emails may not work", "error", err)
	}

	// 6. Initialize Handlers
	identH := handlers.NewIdentityHandler(cfg, userStore, sessionStore, mailSvc).
		WithOrgSupport(orgStore, rdb)
	oauthH := handlers.NewOAuth2Handler(oauth2Srv, sessionStore, revocStore, keys, orgStore, clientStore, jwtGen)
	discH := handlers.NewDiscoveryHandler(keys, cfg.AppURL)
	accountH := handlers.NewAccountHandler(userStore, orgStore, sessionStore, auditStore, rdb)
	orgH := handlers.NewOrgHandler(orgStore, userStore, clientStore, sessionStore, mailSvc, rdb, revocStore, auditStore, cfg.RedisEncryptionKey, cfg.AppURL)
	adminH := handlers.NewAdminHandler(userStore, orgStore, clientStore, sessionStore, auditStore, revocStore, mailSvc, rdb)
	probeH := handlers.NewProbeHandler(db, rdb)
	userInfoH := handlers.NewUserInfoHandler(userStore, keys, revocStore, rdb)

	// 7. Audit log retention — run once on startup, then every 24 hours
	runAuditRetention(auditStore, cfg.AuditRetentionDays)
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			runAuditRetention(auditStore, cfg.AuditRetentionDays)
		}
	}()

	// 8. Init Router
	router := server.NewRouter(cfg, identH, oauthH, discH, accountH, orgH, adminH, probeH, userInfoH, sessionStore, userStore, rdb)

	csrfHandler := nosurf.New(router)
	csrfHandler.SetBaseCookie(http.Cookie{
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60, // 1 year — matches nosurf default; must be set explicitly because SetBaseCookie replaces the entire struct
		HttpOnly: true,
		Secure:   cfg.AppEnv == "production",
		SameSite: http.SameSiteLaxMode,
	})

	// API endpoints that use bearer tokens (not form sessions) must be CSRF-exempt
	csrfHandler.ExemptPath("/token")
	csrfHandler.ExemptPath("/revoke")
	csrfHandler.ExemptPath("/userinfo")

	csrfHandler.SetFailureHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		errStr := nosurf.Reason(r).Error()
		ref := r.Referer()
		if ref == "" {
			ref = r.URL.Path
		}
		u, err := url.Parse(ref)
		if err != nil {
			u = &url.URL{Path: "/"}
		}
		q := u.Query()
		q.Set("error", "Security Error: "+errStr)
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}))

	// Static files bypass the CSRF handler to prevent a race condition on first
	// page load: parallel GET /static/* requests would each generate a new CSRF
	// base token and set it as a cookie; the browser stores the last one received,
	// which may not match the token embedded in the HTML form → ErrBadToken.
	topMux := http.NewServeMux()
	topMux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
	topMux.Handle("/", csrfHandler)

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: middleware.RequestLogger(topMux),
	}

	// 8. Start Server with Graceful Shutdown
	go func() {
		slog.Info("Server listening", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("ListenAndServe crashed", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	slog.Info("Server is shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	}

	slog.Info("Server exited.")
}
