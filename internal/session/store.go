package session

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	sessionTTL = 24 * time.Hour
	otpTTL     = 15 * time.Minute
)

var ErrSessionNotFound = errors.New("session not found")

type Store struct {
	client *redis.Client
}

func NewStore(client *redis.Client) *Store {
	return &Store{client: client}
}

// Create generates a new session ID for a given userID and stores it in Redis
func (s *Store) Create(ctx context.Context, userID uuid.UUID) (string, error) {
	sessionID := uuid.New().String()
	key := "session:" + sessionID

	err := s.client.Set(ctx, key, userID.String(), sessionTTL).Err()
	if err != nil {
		return "", err
	}

	return sessionID, nil
}

// Get retrieves the userID associated with a session ID
func (s *Store) Get(ctx context.Context, sessionID string) (uuid.UUID, error) {
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
func (s *Store) Delete(ctx context.Context, sessionID string) error {
	key := "session:" + sessionID
	return s.client.Del(ctx, key).Err()
}

// GetUserFromSession is a helper to extract the UUID from the request cookie
func (s *Store) GetUserFromSession(r *http.Request) (uuid.UUID, error) {
	cookie, err := r.Cookie("auth_session")
	if err != nil {
		return uuid.Nil, err
	}
	return s.Get(context.Background(), cookie.Value)
}

// CreateOTP generates and stores a 6-digit OTP for the specified userID in Redis
func (s *Store) CreateOTP(ctx context.Context, userID uuid.UUID, otp string) error {
	key := "otp:" + userID.String()
	return s.client.Set(ctx, key, otp, otpTTL).Err()
}

// VerifyOTP checks if the provided OTP matches what is stored in Redis
// Returns a bool indicating success.
func (s *Store) VerifyOTP(ctx context.Context, userID uuid.UUID, submittedOTP string) (bool, error) {
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
