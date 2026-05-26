package idgen

import (
	"crypto/rand"
	"strings"

	"github.com/oklog/ulid/v2"
)

const (
	PrefixUser    = "usr"
	PrefixOrg     = "org"
	PrefixClient  = "cli"
	PrefixRequest = "req"
	PrefixAudit   = "log"
)

func new(prefix string) string {
	id := ulid.MustNew(ulid.Now(), rand.Reader)
	return prefix + "_" + strings.ToLower(id.String())
}

// Prefix returns the type prefix of an ID (e.g. "usr" for "usr_01...").
// Returns "" for IDs with no recognizable prefix.
func Prefix(id string) string {
	if idx := strings.Index(id, "_"); idx > 0 {
		return id[:idx]
	}
	return ""
}

func NewUserID() string    { return new(PrefixUser) }
func NewOrgID() string     { return new(PrefixOrg) }
func NewClientID() string  { return new(PrefixClient) }
func NewRequestID() string { return new(PrefixRequest) }
func NewAuditID() string   { return new(PrefixAudit) }
