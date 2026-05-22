package redis

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/redis/redisutil"
)

const (
	sessionTTL       = 24 * time.Hour
	otpTTL           = 15 * time.Minute
	pendingInviteTTL = 30 * time.Minute
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

// CreateOTP stores a SHA-256 hash of the 6-digit OTP in Redis.
// The raw OTP is sent to the user via email; only the hash lives in Redis
// so a Redis read compromise cannot be used to bypass email verification.
func (s *SessionStore) CreateOTP(ctx context.Context, userID uuid.UUID, otp string) error {
	key := "otp:" + userID.String()
	return s.client.Set(ctx, key, redisutil.HashForStorage(otp), otpTTL).Err()
}

// VerifyOTP checks if the SHA-256 hash of submittedOTP matches what is stored in Redis.
// Consumes the OTP on success to prevent reuse.
func (s *SessionStore) VerifyOTP(ctx context.Context, userID uuid.UUID, submittedOTP string) (bool, error) {
	key := "otp:" + userID.String()
	stored, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil // code doesn't exist or expired
		}
		return false, err
	}

	if stored == redisutil.HashForStorage(submittedOTP) {
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

// CreateResetToken generates a short-lived password-reset token.
// The key stored in Redis is sha256(token) so that a SCAN of reset_token:* does not
// expose usable reset links — only the raw token, sent in the email, can look up the entry.
func (s *SessionStore) CreateResetToken(ctx context.Context, userID uuid.UUID) (string, error) {
	resetToken := uuid.New().String()
	key := "reset_token:" + redisutil.HashForStorage(resetToken)

	err := s.client.Set(ctx, key, userID.String(), 15*time.Minute).Err()
	if err != nil {
		return "", err
	}

	return resetToken, nil
}

// GetUserByResetToken retrieves the user ID from a valid reset token.
// The token parameter is the raw value from the email link; it is hashed before lookup.
func (s *SessionStore) GetUserByResetToken(ctx context.Context, resetToken string) (uuid.UUID, error) {
	key := "reset_token:" + redisutil.HashForStorage(resetToken)
	val, err := s.client.Get(ctx, key).Result()
	if err != nil {
		return uuid.Nil, err // redis.Nil means expired or not found
	}

	return uuid.Parse(val)
}

// DeleteResetToken invalidates a reset token after use.
func (s *SessionStore) DeleteResetToken(ctx context.Context, resetToken string) error {
	key := "reset_token:" + redisutil.HashForStorage(resetToken)
	return s.client.Del(ctx, key).Err()
}

// SetPendingInvite stores an invite token for the user awaiting OTP verification.
// Called by RegisterFunc when ?invite=<T> is present in the request.
func (s *SessionStore) SetPendingInvite(ctx context.Context, userID uuid.UUID, inviteToken string) error {
	key := "invite:pending:" + userID.String()
	return s.client.Set(ctx, key, inviteToken, pendingInviteTTL).Err()
}

// DeleteAllForUser scans all session keys and deletes any belonging to userID.
// Used by the admin panel when disabling an account to immediately revoke active sessions.
func (s *SessionStore) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	target := userID.String()
	var cursor uint64
	for {
		keys, next, err := s.client.Scan(ctx, cursor, "session:*", 100).Result()
		if err != nil {
			return err
		}
		for _, key := range keys {
			val, err := s.client.Get(ctx, key).Result()
			if err != nil {
				continue
			}
			if val == target {
				if delErr := s.client.Del(ctx, key).Err(); delErr != nil {
					slog.Warn("session: failed to delete session for user", "user_id", target, "key", key, "err", delErr)
				}
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return nil
}

// GetAndDeletePendingInvite reads and atomically deletes the pending invite token.
// Returns ("", nil) if no pending invite exists — not an error.
func (s *SessionStore) GetAndDeletePendingInvite(ctx context.Context, userID uuid.UUID) (string, error) {
	key := "invite:pending:" + userID.String()
	val, err := s.client.GetDel(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", nil
		}
		return "", err
	}
	return val, nil
}
