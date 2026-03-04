package redis

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

const (
	sessionTTL = 24 * time.Hour
	otpTTL     = 15 * time.Minute
)

var ErrSessionNotFound = errors.New("session not found")

type SessionStore struct {
	client *redis.Client
}

func NewSessionStore(client *redis.Client) *SessionStore {
	return &SessionStore{client: client}
}

// Create generates a new session ID for a given userID and stores it in Redis
func (s *SessionStore) Create(ctx context.Context, userID uuid.UUID) (string, error) {
	sessionID := uuid.New().String()
	key := "session:" + sessionID

	err := s.client.Set(ctx, key, userID.String(), sessionTTL).Err()
	if err != nil {
		return "", err
	}

	return sessionID, nil
}

// Get retrieves the userID associated with a session ID
func (s *SessionStore) Get(ctx context.Context, sessionID string) (uuid.UUID, error) {
	key := "session:" + sessionID
	val, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return uuid.Nil, ErrSessionNotFound
		}
		return uuid.Nil, err
	}

	return uuid.Parse(val)
}

// Delete removes a session ID from Redis (Logout)
func (s *SessionStore) Delete(ctx context.Context, sessionID string) error {
	key := "session:" + sessionID
	return s.client.Del(ctx, key).Err()
}

// GetUserFromSession is a helper to extract the UUID from the request cookie
func (s *SessionStore) GetUserFromSession(r *http.Request) (uuid.UUID, error) {
	cookie, err := r.Cookie("auth_session")
	if err != nil {
		return uuid.Nil, err
	}
	return s.Get(context.Background(), cookie.Value)
}

// CreateOTP generates and stores a 6-digit OTP for the specified userID in Redis
func (s *SessionStore) CreateOTP(ctx context.Context, userID uuid.UUID, otp string) error {
	key := "otp:" + userID.String()
	return s.client.Set(ctx, key, otp, otpTTL).Err()
}

// VerifyOTP checks if the provided OTP matches what is stored in Redis
// Returns a bool indicating success.
func (s *SessionStore) VerifyOTP(ctx context.Context, userID uuid.UUID, submittedOTP string) (bool, error) {
	key := "otp:" + userID.String()
	val, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil // Code doesn't exist or expired
		}
		return false, err // Redis connection error
	}

	if val == submittedOTP {
		// Valid OTP, immediately consume it to prevent reuse
		s.client.Del(ctx, key)
		return true, nil
	}

	return false, nil
}

// IncrementFailedLogin tracks failed login attempts for an email and returns the new count
func (s *SessionStore) IncrementFailedLogin(ctx context.Context, email string) (int, error) {
	key := "failed_login:" + email
	count, err := s.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if count == 1 {
		s.client.Expire(ctx, key, 15*time.Minute)
	}
	return int(count), nil
}

// ResetFailedLogin clears the failed login attempts
func (s *SessionStore) ResetFailedLogin(ctx context.Context, email string) error {
	key := "failed_login:" + email
	return s.client.Del(ctx, key).Err()
}

// GetFailedLogin returns the current failed login count
func (s *SessionStore) GetFailedLogin(ctx context.Context, email string) (int, error) {
	key := "failed_login:" + email
	val, err := s.client.Get(ctx, key).Int()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, err
	}
	return val, nil
}

// CreateResetToken generates a short-lived token for password recovery
func (s *SessionStore) CreateResetToken(ctx context.Context, userID uuid.UUID) (string, error) {
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
func (s *SessionStore) GetUserByResetToken(ctx context.Context, resetToken string) (uuid.UUID, error) {
	key := "reset_token:" + resetToken
	val, err := s.client.Get(ctx, key).Result()
	if err != nil {
		return uuid.Nil, err // Could be redis.Nil if expired
	}

	return uuid.Parse(val)
}

// DeleteResetToken invalidates a reset token after use
func (s *SessionStore) DeleteResetToken(ctx context.Context, resetToken string) error {
	key := "reset_token:" + resetToken
	return s.client.Del(ctx, key).Err()
}
