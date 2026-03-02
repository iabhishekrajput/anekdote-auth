package session

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// CreateResetToken generates a short-lived token for password recovery
func (s *Store) CreateResetToken(ctx context.Context, userID uuid.UUID) (string, error) {
	resetToken := uuid.New().String()
	key := "reset_token:" + resetToken

	// Reset tokens expire in 15 minutes for security
	err := s.client.Set(ctx, key, userID.String(), 15*time.Minute).Err()
	if err != nil {
		return "", err
	}

	return resetToken, nil
}

// GetUserByResetToken retrieves the user ID from a valid reset token
func (s *Store) GetUserByResetToken(ctx context.Context, resetToken string) (uuid.UUID, error) {
	key := "reset_token:" + resetToken
	val, err := s.client.Get(ctx, key).Result()
	if err != nil {
		return uuid.Nil, err // Could be redis.Nil if expired
	}

	return uuid.Parse(val)
}

// DeleteResetToken invalidates a reset token after use
func (s *Store) DeleteResetToken(ctx context.Context, resetToken string) error {
	key := "reset_token:" + resetToken
	return s.client.Del(ctx, key).Err()
}
