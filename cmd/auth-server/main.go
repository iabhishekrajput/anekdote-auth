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

	"github.com/gorilla/csrf"
	"github.com/iabhishekrajput/anekdote-auth/internal/auth"
	"github.com/iabhishekrajput/anekdote-auth/internal/config"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/iabhishekrajput/anekdote-auth/internal/handlers"
	"github.com/iabhishekrajput/anekdote-auth/internal/mailer"
	"github.com/iabhishekrajput/anekdote-auth/internal/server"
	"github.com/iabhishekrajput/anekdote-auth/internal/session"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
)

func main() {
	// Initialize structured logger
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	slog.Info("Starting Anekdote Auth Server...")

	cfg := config.Load()

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

	sessionStore := session.NewStore(rdb)
	revocStore := redis.NewRevocationStore(rdb)

	// 4. Initialize Core Server
	issuer := "http://localhost:" + cfg.Port
	oauth2Srv := auth.BuildServer(clientStore, keys, revocStore, issuer)

	// 5. Initialize Mailer
	mailSvc, err := mailer.NewMailer(cfg)
	if err != nil {
		slog.Warn("Failed to initialize mailer, forgot password emails may not work", "error", err)
	}

	// 6. Initialize Handlers
	identH := handlers.NewIdentityHandler(cfg, userStore, sessionStore, mailSvc)
	oauthH := handlers.NewOAuth2Handler(oauth2Srv, sessionStore, revocStore)
	discH := handlers.NewDiscoveryHandler(keys)
	accountH := handlers.NewAccountHandler(userStore)

	// 7. Init Router
	router := server.NewRouter(cfg, identH, oauthH, discH, accountH, sessionStore, rdb)

	csrfMiddleware := csrf.Protect(
		[]byte("32-byte-long-auth-key-change-me"), // In production this would be loaded from env/config
		csrf.Secure(cfg.AppEnv == "production"),
		csrf.Path("/"),
		csrf.ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			errStr := csrf.FailureReason(r).Error()
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
		})),
	)

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: csrfMiddleware(router),
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
