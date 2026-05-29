// Package web holds small HTTP helpers shared across handlers and middleware:
// open-redirect-safe path validation and session-cookie management.
package web

import (
	"net/http"
	"net/url"
	"strings"
)

// SessionCookieName is the browser cookie that carries the session ID.
const SessionCookieName = "auth_session"

// IsSafeLocalRedirect reports whether next is a safe same-origin path to
// redirect to. It must begin with a single "/" and must not be a
// protocol-relative ("//host") or backslash ("/\host") form — browsers
// normalize both to an absolute off-site URL, which would be an open redirect.
func IsSafeLocalRedirect(next string) bool {
	if !strings.HasPrefix(next, "/") {
		return false
	}
	// Reject "//host" and "/\host": the second byte must not be a slash or
	// backslash. (A lone "/" is fine — it redirects to the site root.)
	if len(next) > 1 && (next[1] == '/' || next[1] == '\\') {
		return false
	}
	return true
}

// SafeLocalRedirect returns a guaranteed same-origin redirect target. Any
// scheme/host on candidate is stripped so a full URL (e.g. a Referer header)
// collapses to its path before validation; if the result is not a safe local
// path, fallback is returned instead.
func SafeLocalRedirect(candidate, fallback string) string {
	if u, err := url.Parse(candidate); err == nil && u.Path != "" {
		// Honor only the path (+query); discard any scheme/host so an
		// attacker-controlled Referer cannot bounce the user off-site.
		candidate = u.Path
		if u.RawQuery != "" {
			candidate += "?" + u.RawQuery
		}
	}
	if IsSafeLocalRedirect(candidate) {
		return candidate
	}
	return fallback
}

// secureRequest reports whether the request arrived over HTTPS, honoring a
// TLS-terminating proxy via X-Forwarded-Proto.
func secureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// ClearSessionCookie expires the session cookie using the same security
// attributes it is set with, so browsers reliably drop it. Using the canonical
// SessionCookieName ensures the live cookie is actually cleared (a prior bug
// cleared a non-existent "session_id" cookie, leaving the session cookie set).
func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})
}
