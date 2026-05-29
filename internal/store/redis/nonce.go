package redis

import (
	"context"
	"time"

	goredis "github.com/go-redis/redis/v8"
)

// NonceStore persists one-time OIDC nonce bindings by authorization code.
type NonceStore struct {
	client *goredis.Client
}

func NewNonceStore(client *goredis.Client) *NonceStore {
	return &NonceStore{client: client}
}

// StoreNonce persists the OIDC nonce tied to an authorization code.
func (s *NonceStore) StoreNonce(ctx context.Context, code, nonce string, ttl time.Duration) error {
	return s.client.Set(ctx, "oidc_nonce:"+code, nonce, ttl).Err()
}

// ConsumeNonce retrieves and atomically deletes the nonce for a code.
func (s *NonceStore) ConsumeNonce(ctx context.Context, code string) (string, error) {
	nonce, err := s.client.GetDel(ctx, "oidc_nonce:"+code).Result()
	if err == goredis.Nil {
		return "", nil
	}
	return nonce, err
}
