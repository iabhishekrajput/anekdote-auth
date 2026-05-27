package server

import (
	"testing"

	"github.com/go-redis/redis/v8"
	"github.com/iabhishekrajput/anekdote-auth/internal/config"
	"github.com/iabhishekrajput/anekdote-auth/internal/handlers"
	pgstore "github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	redisstore "github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
)

func TestNewRouter(t *testing.T) {
	cfg := &config.Config{
		CORSAllowedOrigins: "*",
	}

	router := NewRouter(
		cfg,
		&handlers.IdentityHandler{},
		&handlers.OAuth2Handler{},
		&handlers.DiscoveryHandler{},
		&handlers.AccountHandler{},
		&handlers.OrgHandler{},
		&handlers.AdminHandler{},
		&handlers.ProbeHandler{},
		&handlers.UserInfoHandler{},
		&handlers.ManagementHandler{},
		&redisstore.SessionStore{},
		&pgstore.UserStore{},
		&redis.Client{},
	)

	if router == nil {
		t.Fatalf("expected non-nil router")
	}
}
