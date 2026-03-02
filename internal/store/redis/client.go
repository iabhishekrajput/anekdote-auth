package redis

import (
	"context"
	"log/slog"

	v9 "github.com/redis/go-redis/v9"
)

// InitRedis initializes the go-redis client
func InitRedis(dsn string) (*v9.Client, error) {
	opt, err := v9.ParseURL(dsn)
	if err != nil {
		return nil, err
	}

	client := v9.NewClient(opt)

	// Ping to verify connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	slog.Info("Connected to Redis successfully")
	return client, nil
}
