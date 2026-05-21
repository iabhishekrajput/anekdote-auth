package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID
	Email        string
	Name         string
	PasswordHash string
	IsVerified   bool
	IsAdmin      bool
	DisabledAt   *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
