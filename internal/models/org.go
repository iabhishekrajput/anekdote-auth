package models

import "time"

type Org struct {
	ID          string
	Slug        string
	DisplayName string
	OwnerID     string
	DeletedAt   *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type OrgMembership struct {
	OrgID     string
	UserID    string
	Role      string // "owner" | "admin" | "viewer" | "member"
	InvitedBy *string
	JoinedAt  time.Time
	RemovedAt *time.Time
	// Display fields populated by joins (not stored in org_memberships)
	UserEmail string
}
