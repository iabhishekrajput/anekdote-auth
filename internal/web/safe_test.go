package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsSafeLocalRedirect(t *testing.T) {
	cases := map[string]bool{
		"/account":            true,
		"/authorize?x=1":      true,
		"/":                   true,
		"//evil.com":          false, // protocol-relative
		"/\\evil.com":         false, // backslash → browsers normalize to //evil.com
		"https://evil.com":    false,
		"http://evil.com/foo": false,
		"javascript:alert(1)": false,
		"":                    false,
		"account":             false, // no leading slash
	}
	for in, want := range cases {
		if got := IsSafeLocalRedirect(in); got != want {
			t.Errorf("IsSafeLocalRedirect(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSafeLocalRedirect(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/account", "/account"},
		{"//evil.com/x", "/x"},                        // host stripped, path kept
		{"/\\evil.com", "/"},                          // backslash trick → fallback
		{"http://localhost:8080/account", "/account"}, // full same-origin URL → path
		{"https://evil.com/phish", "/phish"},          // host stripped → local path only
		{"javascript:alert(1)", "/"},                  // no usable path → fallback
		{"", "/"},
	}
	for _, c := range cases {
		if got := SafeLocalRedirect(c.in, "/"); got != c.want {
			t.Errorf("SafeLocalRedirect(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestClearSessionCookie(t *testing.T) {
	t.Run("plain http is not Secure", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://localhost/x", nil)
		ClearSessionCookie(w, r)
		c := w.Result().Cookies()[0]
		if c.Name != SessionCookieName {
			t.Errorf("name = %q, want %q", c.Name, SessionCookieName)
		}
		if c.MaxAge >= 0 {
			t.Errorf("MaxAge = %d, want negative (expire)", c.MaxAge)
		}
		if !c.HttpOnly {
			t.Error("HttpOnly = false, want true")
		}
		if c.Secure {
			t.Error("Secure = true over plain http, want false")
		}
	})

	t.Run("forwarded https is Secure", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://localhost/x", nil)
		r.Header.Set("X-Forwarded-Proto", "https")
		ClearSessionCookie(w, r)
		if !w.Result().Cookies()[0].Secure {
			t.Error("Secure = false behind https proxy, want true")
		}
	})
}
