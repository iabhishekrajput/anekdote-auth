package redis

import (
	"context"
	"log/slog"

	"github.com/go-redis/redis/v8"
)

// InitRedis initializes the go-redis client
func InitRedis(dsn string) (*redis.Client, error) {
	opt, err := redis.ParseURL(dsn)
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(opt)

	// Ping to verify connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	slog.Info("Connected to Redis successfully")
	return client, nil
}
