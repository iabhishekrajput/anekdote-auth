package server

import (
	"testing"

	"github.com/go-redis/redis/v8"
	"github.com/iabhishekrajput/anekdote-auth/internal/config"
	"github.com/iabhishekrajput/anekdote-auth/internal/handlers"
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
		&redisstore.SessionStore{},
		&redis.Client{},
	)

	if router == nil {
		t.Fatalf("expected non-nil router")
	}
}
