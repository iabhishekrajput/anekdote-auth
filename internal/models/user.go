package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID              uuid.UUID
	Email           string
	Name            string
	PasswordHash    string
	IsVerified      bool
	IsAdmin         bool
	AdminRole       string // "superadmin", "readonly", "org_admin" — only meaningful when IsAdmin is true
	PasswordChanged bool   // false until the user explicitly sets their own password
	DisabledAt      *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}
