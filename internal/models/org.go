package models

import (
	"time"

	"github.com/google/uuid"
)

type Org struct {
	ID          uuid.UUID
	Slug        string
	DisplayName string
	OwnerID     uuid.UUID
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type OrgMembership struct {
	OrgID     uuid.UUID
	UserID    uuid.UUID
	Role      string // "owner" | "admin" | "member"
	InvitedBy *uuid.UUID
	JoinedAt  time.Time
	RemovedAt *time.Time
	// Display fields populated by joins (not stored in org_memberships)
	UserEmail string
}
