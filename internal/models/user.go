package models

import "time"

type User struct {
	ID              string
	Email           string
	Name            string
	Username        string // optional; used for preferred_username OIDC claim
	PasswordHash    string
	IsVerified      bool
	IsAdmin         bool
	AdminRole       string // "superadmin", "readonly", "org_admin" — only meaningful when IsAdmin is true
	PasswordChanged bool   // false until the user explicitly sets their own password
	DisabledAt      *time.Time
	DeletedAt       *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}
