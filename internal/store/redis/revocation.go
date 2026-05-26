package redis

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
)

type RevocationStore struct {
	client *redis.Client
}

func NewRevocationStore(client *redis.Client) *RevocationStore {
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
	if err == redis.Nil {
		return false, nil // Not revoked
	} else if err != nil {
		return false, err // Redis error
	}
	return val == "revoked", nil
}

// StoreNonce persists the OIDC nonce tied to an authorization code.
// TTL should match the code's own expiry (typically 10 minutes).
func (s *RevocationStore) StoreNonce(ctx context.Context, code, nonce string, ttl time.Duration) error {
	return s.client.Set(ctx, "oidc_nonce:"+code, nonce, ttl).Err()
}

// ConsumeNonce retrieves and atomically deletes the nonce for a code (one-time read).
// Returns ("", nil) when no nonce exists for the code.
func (s *RevocationStore) ConsumeNonce(ctx context.Context, code string) (string, error) {
	nonce, err := s.client.GetDel(ctx, "oidc_nonce:"+code).Result()
	if err == redis.Nil {
		return "", nil
	}
	return nonce, err
}
