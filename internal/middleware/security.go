package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/redis/go-redis/v9"
)

// SecurityHeadersMiddleware adds standard web security headers to responses
func SecurityHeadersMiddleware(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		// Optional CORS headers for a public OIDC/OAuth2 API
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r, ps)
	}
}

// RateLimitMiddleware provides a basic Redis-backed fixed-window rate limiter (e.g., 100 requests / minute)
func RateLimitMiddleware(client *redis.Client, limit int, window time.Duration, next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		clientIP := r.RemoteAddr // In production, parse X-Forwarded-For if behind a proxy
		key := "rate_limit:" + clientIP

		ctx := context.Background()

		// Increment request count
		count, err := client.Incr(ctx, key).Result()
		if err != nil {
			http.Error(w, "internal router error", http.StatusInternalServerError)
			return
		}

		// Set expiry on first request in window
		if count == 1 {
			client.Expire(ctx, key, window)
		}

		if count > int64(limit) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next(w, r, ps)
	}
}

// Chain allows wrapping a handler in multiple middlewares easily
func Chain(handler httprouter.Handle, middlewares ...func(httprouter.Handle) httprouter.Handle) httprouter.Handle {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}
