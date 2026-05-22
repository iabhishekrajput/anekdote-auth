package postgres

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// PageCursor is an opaque continuation token for cursor-based pagination.
// It encodes the last record's (created_at, id) so the next query can use
// a WHERE clause instead of OFFSET.
type PageCursor struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

// EncodeCursor encodes a (created_at, id) pair as a URL-safe base64 string.
func EncodeCursor(t time.Time, id uuid.UUID) string {
	raw := t.UTC().Format(time.RFC3339Nano) + "|" + id.String()
	return base64.URLEncoding.EncodeToString([]byte(raw))
}

// DecodeCursor parses a cursor encoded by EncodeCursor.
// Returns (nil, nil) for an empty string (first page).
func DecodeCursor(s string) (*PageCursor, error) {
	if s == "" {
		return nil, nil
	}
	raw, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid cursor")
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid cursor format")
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return nil, errors.New("invalid cursor timestamp")
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return nil, errors.New("invalid cursor id")
	}
	return &PageCursor{CreatedAt: t, ID: id}, nil
}
