package redis

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

func setupTestRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to run miniredis: %v", err)
	}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return client, mr
}

func TestSessionStore_CreateAndGet(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()

	store := NewSessionStore(client)
	userID := uuid.New()

	sessionID, err := store.Create(context.Background(), userID)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if sessionID == "" {
		t.Error("expected non-empty session ID")
	}

	fetchedID, err := store.Get(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if fetchedID != userID {
		t.Errorf("expected %s, got %s", userID, fetchedID)
	}
}

func TestSessionStore_Delete(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()

	store := NewSessionStore(client)
	sessionID, _ := store.Create(context.Background(), uuid.New())

	err := store.Delete(context.Background(), sessionID)
	if err != nil {
		t.Errorf("Delete failed: %v", err)
	}

	_, err = store.Get(context.Background(), sessionID)
	if err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestSessionStore_GetUserFromSession(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()

	store := NewSessionStore(client)
	userID := uuid.New()
	sessionID, _ := store.Create(context.Background(), userID)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})

	fetchedID, err := store.GetUserFromSession(req)
	if err != nil {
		t.Errorf("GetUserFromSession failed: %v", err)
	}
	if fetchedID != userID {
		t.Errorf("expected UUID %s, got %s", userID, fetchedID)
	}
}

func TestSessionStore_OTP(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()

	store := NewSessionStore(client)
	userID := uuid.New()

	err := store.CreateOTP(context.Background(), userID, "123456")
	if err != nil {
		t.Fatalf("CreateOTP failed: %v", err)
	}

	valid, err := store.VerifyOTP(context.Background(), userID, "wrong")
	if err != nil {
		t.Errorf("verify returned error: %v", err)
	}
	if valid {
		t.Error("expected OTP to be invalid")
	}

	valid, _ = store.VerifyOTP(context.Background(), userID, "123456")
	if !valid {
		t.Error("expected OTP to be valid")
	}

	// OTP should be entirely consumed
	valid, _ = store.VerifyOTP(context.Background(), userID, "123456")
	if valid {
		t.Error("expected OTP to be invalid after being consumed")
	}
}

func TestSessionStore_FailedLogins(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()

	store := NewSessionStore(client)
	email := "test@example.com"

	count, _ := store.IncrementFailedLogin(context.Background(), email)
	if count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}

	store.IncrementFailedLogin(context.Background(), email)
	count, _ = store.GetFailedLogin(context.Background(), email)
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}

	store.ResetFailedLogin(context.Background(), email)
	count, _ = store.GetFailedLogin(context.Background(), email)
	if count != 0 {
		t.Errorf("expected count 0 after reset, got %d", count)
	}
}

func TestSessionStore_ResetTokens(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()

	store := NewSessionStore(client)
	userID := uuid.New()

	token, _ := store.CreateResetToken(context.Background(), userID)
	fetchedID, _ := store.GetUserByResetToken(context.Background(), token)

	if fetchedID != userID {
		t.Errorf("expected UUID %s, got %s", userID, fetchedID)
	}

	store.DeleteResetToken(context.Background(), token)
	_, err := store.GetUserByResetToken(context.Background(), token)
	if err == nil {
		t.Error("expected ErrSessionNotFound or redis.Nil after deletion")
	}
}

func TestRevocationStore(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()

	store := NewRevocationStore(client)
	jti := "test-jti-123"

	revoked, err := store.IsRevoked(context.Background(), jti)
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}
	if revoked {
		t.Error("expected jti not to be revoked initially")
	}

	store.RevokeJTI(context.Background(), jti, time.Hour)

	revoked, _ = store.IsRevoked(context.Background(), jti)
	if !revoked {
		t.Error("expected jti to be revoked")
	}
}

func TestTokenStore(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()

	store := NewTokenStore(client)
	if store == nil {
		t.Error("expected non-nil token store")
	}
}
