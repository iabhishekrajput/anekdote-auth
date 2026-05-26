package idgen

import (
	"strings"
	"testing"
	"time"
)

// ulidBodyLen is the length of the Crockford base32 ULID body (26 chars).
const ulidBodyLen = 26

func TestNewUserID(t *testing.T) {
	id := NewUserID()
	assertID(t, id, PrefixUser)
}

func TestNewOrgID(t *testing.T) {
	id := NewOrgID()
	assertID(t, id, PrefixOrg)
}

func TestNewClientID(t *testing.T) {
	id := NewClientID()
	assertID(t, id, PrefixClient)
}

func TestNewRequestID(t *testing.T) {
	id := NewRequestID()
	assertID(t, id, PrefixRequest)
}

func TestNewAuditID(t *testing.T) {
	id := NewAuditID()
	assertID(t, id, PrefixAudit)
}

func TestUniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		id := NewUserID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate ID generated at iteration %d: %s", i, id)
		}
		seen[id] = struct{}{}
	}
}

func TestLexicographicOrder(t *testing.T) {
	// ULID's timestamp prefix guarantees cross-millisecond ordering. Within the
	// same millisecond, rand.Reader entropy produces no ordering guarantee.
	// We verify cross-ms ordering by bracketing a sleep with ID generation.
	earlier := NewUserID()
	time.Sleep(2 * time.Millisecond)
	later := NewUserID()

	if earlier >= later {
		t.Errorf("ID generated before sleep %q >= ID generated after sleep %q — cross-millisecond order violated", earlier, later)
	}
}

func TestPrefix(t *testing.T) {
	cases := []struct {
		id   string
		want string
	}{
		{NewUserID(), PrefixUser},
		{NewOrgID(), PrefixOrg},
		{NewClientID(), PrefixClient},
		{NewRequestID(), PrefixRequest},
		{NewAuditID(), PrefixAudit},
		{"", ""},
		{"nounderscore", ""},
		{"_leading", ""},
	}
	for _, tc := range cases {
		if got := Prefix(tc.id); got != tc.want {
			t.Errorf("Prefix(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

func TestLowercase(t *testing.T) {
	for i := 0; i < 50; i++ {
		id := NewUserID()
		if id != strings.ToLower(id) {
			t.Errorf("ID contains uppercase: %s", id)
		}
	}
}

func TestIDsFromDifferentGeneratorsDoNotSharePrefixes(t *testing.T) {
	if Prefix(NewUserID()) == Prefix(NewOrgID()) {
		t.Error("user and org IDs share the same prefix")
	}
	if Prefix(NewClientID()) == Prefix(NewAuditID()) {
		t.Error("client and audit IDs share the same prefix")
	}
}

// assertID checks prefix, separator, body length, and character set.
func assertID(t *testing.T, id, wantPrefix string) {
	t.Helper()

	wantFull := wantPrefix + "_"
	if !strings.HasPrefix(id, wantFull) {
		t.Errorf("id %q does not start with %q", id, wantFull)
	}

	body := strings.TrimPrefix(id, wantFull)
	if len(body) != ulidBodyLen {
		t.Errorf("id %q: body length = %d, want %d", id, len(body), ulidBodyLen)
	}

	const crockfordLower = "0123456789abcdefghjkmnpqrstvwxyz"
	for _, ch := range body {
		if !strings.ContainsRune(crockfordLower, ch) {
			t.Errorf("id %q: body contains invalid character %q", id, ch)
		}
	}
}
