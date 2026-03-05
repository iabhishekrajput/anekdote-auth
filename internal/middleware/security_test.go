package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/julienschmidt/httprouter"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	corsAllowed := "http://example.com"
	middleware := SecurityHeadersMiddleware(corsAllowed)
	handler := middleware(mockHandler())

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	rr := httptest.NewRecorder()

	handler(rr, req, nil)

	// Verify headers are injected
	headers := rr.Header()
	if headers.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("missing nosniff header")
	}
	if headers.Get("Access-Control-Allow-Origin") != corsAllowed {
		t.Errorf("incorrect CORS origin: %s", headers.Get("Access-Control-Allow-Origin"))
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 return from inner handler")
	}
}

func TestSecurityHeadersMiddleware_OPTIONS(t *testing.T) {
	middleware := SecurityHeadersMiddleware("*")
	handler := middleware(mockHandler())

	req := httptest.NewRequest(http.MethodOptions, "/api", nil)
	rr := httptest.NewRecorder()

	handler(rr, req, nil)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK for OPTIONS request, got %d", rr.Code)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	handler := RateLimitMiddleware(client, "test", 2, time.Second, mockHandler())

	// 1st request (Allowed)
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "127.0.0.1:12345"
	rr1 := httptest.NewRecorder()
	handler(rr1, req1, nil)
	if rr1.Code != http.StatusOK {
		t.Errorf("expected 1st request OK, got %d", rr1.Code)
	}

	// 2nd request (Allowed)
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "127.0.0.1:12345"
	rr2 := httptest.NewRecorder()
	handler(rr2, req2, nil)
	if rr2.Code != http.StatusOK {
		t.Errorf("expected 2nd request OK, got %d", rr2.Code)
	}

	// 3rd request (Blocked / Redirect)
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.RemoteAddr = "127.0.0.1:12345"
	rr3 := httptest.NewRecorder()
	handler(rr3, req3, nil)
	if rr3.Code != http.StatusFound { // HTTP 302
		t.Errorf("expected rate limit redirect 302, got %d", rr3.Code)
	}
	if rr3.Header().Get("Location") != "/?error=Rate+limit+exceeded.+Please+try+again+later." {
		t.Errorf("unexpected redirect location: %s", rr3.Header().Get("Location"))
	}
}

func TestChain(t *testing.T) {
	mdw1 := func(next httprouter.Handle) httprouter.Handle {
		return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			w.Header().Add("X-Chain", "1")
			next(w, r, ps)
		}
	}
	mdw2 := func(next httprouter.Handle) httprouter.Handle {
		return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			w.Header().Add("X-Chain", "2")
			next(w, r, ps)
		}
	}

	handler := Chain(mockHandler(), mdw1, mdw2)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler(rr, req, nil)

	chainVals := rr.Header().Values("X-Chain")
	if len(chainVals) != 2 || chainVals[0] != "1" || chainVals[1] != "2" {
		t.Errorf("chain didn't execute in expected order, got headers: %v", chainVals)
	}
}
