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
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
