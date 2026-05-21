package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// AuditAction is a typed constant for admin audit log action names.
type AuditAction string

const (
	AuditActionDisableUser     AuditAction = "disable_user"
	AuditActionEnableUser      AuditAction = "enable_user"
	AuditActionDeleteClient    AuditAction = "delete_client"
	AuditActionRemoveOrgMember AuditAction = "remove_org_member"
	AuditActionPromoteAdmin    AuditAction = "promote_admin"
	AuditActionDemoteAdmin     AuditAction = "demote_admin"
)

// AuditLogEntry is a single row from admin_audit_log.
type AuditLogEntry struct {
	ID         uuid.UUID
	AdminID    *uuid.UUID
	Action     AuditAction
	TargetType string
	TargetID   string
	IPAddress  string
	UserAgent  string
	CreatedAt  time.Time
}

type AuditStore struct {
	db *sql.DB
}

func NewAuditStore(db *sql.DB) *AuditStore {
	return &AuditStore{db: db}
}

// Log inserts an audit entry. adminID may be zero-value (logged as NULL).
func (s *AuditStore) Log(ctx context.Context, adminID uuid.UUID, action AuditAction, targetType, targetID, ipAddr, ua string) error {
	var aid *uuid.UUID
	if adminID != (uuid.UUID{}) {
		aid = &adminID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_audit_log (admin_id, action, target_type, target_id, ip_address, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		aid, string(action), targetType, targetID, ipAddr, ua,
	)
	return err
}

// CountAudit returns the total number of audit log entries.
func (s *AuditStore) CountAudit(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_audit_log`).Scan(&count)
	return count, err
}

// ListAudit returns audit entries ordered by created_at DESC with limit/offset pagination.
func (s *AuditStore) ListAudit(ctx context.Context, limit, offset int) ([]*AuditLogEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, admin_id, action, target_type, target_id, ip_address, user_agent, created_at
		 FROM admin_audit_log ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*AuditLogEntry
	for rows.Next() {
		e := &AuditLogEntry{}
		var ipAddr, ua sql.NullString
		if err := rows.Scan(&e.ID, &e.AdminID, &e.Action, &e.TargetType, &e.TargetID, &ipAddr, &ua, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.IPAddress = ipAddr.String
		e.UserAgent = ua.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
