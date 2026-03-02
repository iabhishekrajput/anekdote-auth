package redis

import (
	"context"
	"time"

	v9 "github.com/redis/go-redis/v9"
)

type RevocationStore struct {
	client *v9.Client
}

func NewRevocationStore(client *v9.Client) *RevocationStore {
	return &RevocationStore{client: client}
}

// RevokeJTI adds a token's JTI to the blocklist in Redis for the remainder of its TTL.
func (s *RevocationStore) RevokeJTI(ctx context.Context, jti string, duration time.Duration) error {
	key := "revoked_jti:" + jti
	return s.client.Set(ctx, key, "revoked", duration).Err()
}

// IsRevoked checks if a JTI is currently in the blocklist.
func (s *RevocationStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	key := "revoked_jti:" + jti
	val, err := s.client.Get(ctx, key).Result()
	if err == v9.Nil {
		return false, nil // Not revoked
	} else if err != nil {
		return false, err // Redis error
	}
	return val == "revoked", nil
}
