package redis

import (
	oredis "github.com/go-oauth2/redis/v4"
	"github.com/go-redis/redis/v8"
)

func NewTokenStore(client *redis.Client) *oredis.TokenStore {
	return oredis.NewRedisStore(client.Options(), "token:")
}
