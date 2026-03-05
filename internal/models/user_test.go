package models_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/models"
)

func TestUserCreation(t *testing.T) {
	now := time.Now()
	uid := uuid.New()

	user := models.User{
		ID:           uid,
		Email:        "test@example.com",
		Name:         "Test User",
		PasswordHash: "hashed_password",
		IsVerified:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if user.ID != uid {
		t.Errorf("Expected ID %s, got %s", uid, user.ID)
	}
	if user.Email != "test@example.com" {
		t.Errorf("Expected Email 'test@example.com', got '%s'", user.Email)
	}
	if !user.IsVerified {
		t.Errorf("Expected user to be verified")
	}
}
