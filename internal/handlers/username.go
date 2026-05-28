package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	redisstore "github.com/iabhishekrajput/anekdote-auth/internal/store/redis"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/text/unicode/norm"
)

var usernameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{1,28}[a-z0-9]$`)

type UsernameHandler struct {
	userStore *postgres.UserStore
	bloom     *redisstore.UsernameBloom
}

func NewUsernameHandler(userStore *postgres.UserStore, bloom *redisstore.UsernameBloom) *UsernameHandler {
	return &UsernameHandler{userStore: userStore, bloom: bloom}
}

// Check handles GET /api/username-check?username=...
// Returns {"available": true/false, "reason": "..."} — never 4xx unless the param is missing.
func (h *UsernameHandler) Check(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	username := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("username")))

	type result struct {
		Available bool   `json:"available"`
		Reason    string `json:"reason,omitempty"`
	}

	w.Header().Set("Content-Type", "application/json")

	if username == "" {
		json.NewEncoder(w).Encode(result{Available: false, Reason: "required"})
		return
	}

	if !usernameRegex.MatchString(username) {
		json.NewEncoder(w).Encode(result{Available: false, Reason: "invalid"})
		return
	}

	taken, err := h.isTaken(r.Context(), username)
	if err != nil || taken {
		json.NewEncoder(w).Encode(result{Available: false, Reason: "taken"})
		return
	}

	json.NewEncoder(w).Encode(result{Available: true})
}

// Suggestions handles GET /api/username-suggestions?name=...
// Returns {"suggestions": ["user1", "user2", ...]} — up to 5 available candidates.
func (h *UsernameHandler) Suggestions(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))

	type result struct {
		Suggestions []string `json:"suggestions"`
	}

	w.Header().Set("Content-Type", "application/json")

	if name == "" {
		json.NewEncoder(w).Encode(result{Suggestions: []string{}})
		return
	}

	candidates := generateCandidates(name)
	var available []string
	for _, c := range candidates {
		if len(available) >= 5 {
			break
		}
		taken, err := h.isTaken(r.Context(), c)
		if err == nil && !taken {
			available = append(available, c)
		}
	}

	if available == nil {
		available = []string{}
	}
	json.NewEncoder(w).Encode(result{Suggestions: available})
}

// isTaken uses the bloom filter as a fast negative gate, then confirms with the DB.
func (h *UsernameHandler) isTaken(ctx context.Context, username string) (bool, error) {
	if h.bloom != nil {
		might, err := h.bloom.MightExist(ctx, username)
		if err == nil && !might {
			return false, nil
		}
	}
	return h.userStore.IsUsernameTaken(ctx, username)
}

// generateCandidates derives username candidates from a display name.
func generateCandidates(displayName string) []string {
	base := slugify(displayName)
	if base == "" {
		return nil
	}

	parts := strings.Fields(slugify(displayName))

	var candidates []string
	seen := map[string]bool{}

	add := func(s string) {
		s = strings.ToLower(s)
		s = strings.Trim(s, "_.")
		if len(s) >= 3 && len(s) <= 30 && usernameRegex.MatchString(s) && !seen[s] {
			seen[s] = true
			candidates = append(candidates, s)
		}
	}

	first := ""
	last := ""
	if len(parts) > 0 {
		first = parts[0]
	}
	if len(parts) > 1 {
		last = parts[len(parts)-1]
	}

	// Variants from name components
	if first != "" && last != "" {
		add(first + last)
		add(first + "_" + last)
		add(first + "." + last)
		add(string([]rune(first)[0:1]) + last)
		add(first + string([]rune(last)[0:1]))
	} else if first != "" {
		add(first)
	}
	add(base)

	// Numbered variants
	for _, suffix := range numberedSuffixes(8) {
		if len(candidates) >= 20 {
			break
		}
		if first != "" && last != "" {
			add(first + last + suffix)
			add(first + "_" + last + suffix)
		} else if first != "" {
			add(first + suffix)
		}
	}

	return candidates
}

func numberedSuffixes(n int) []string {
	out := make([]string, n)
	for i := range out {
		// mix of small numbers and random 2-digit numbers for variety
		if i < 4 {
			out[i] = fmt.Sprintf("%d", i+1)
		} else {
			out[i] = fmt.Sprintf("%d", rand.IntN(90)+10)
		}
	}
	return out
}

// slugify converts a display name to a safe lowercase ASCII slug.
func slugify(s string) string {
	// NFKD-normalize to break accented characters into base + combining marks
	s = norm.NFKD.String(s)

	var b strings.Builder
	prev := '_'
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prev = r
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
			prev = r + 32
		case unicode.IsSpace(r) || r == '-' || r == '_' || r == '.':
			if prev != '_' && prev != '.' {
				b.WriteRune('_')
			}
			prev = '_'
		// skip combining marks and other non-ASCII
		}
	}
	return strings.Trim(b.String(), "_.")
}
