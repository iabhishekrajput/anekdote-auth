package session

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const sessionTTL = 24 * time.Hour

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
