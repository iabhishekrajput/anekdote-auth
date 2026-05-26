package postgres

import (
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"time"
)

// AuditAction is a typed constant for admin audit log action names.
type AuditAction string

const (
	AuditActionDisableUser          AuditAction = "disable_user"
	AuditActionEnableUser           AuditAction = "enable_user"
	AuditActionDeleteClient         AuditAction = "delete_client"
	AuditActionRemoveOrgMember      AuditAction = "remove_org_member"
	AuditActionPromoteAdmin         AuditAction = "promote_admin"
	AuditActionDemoteAdmin          AuditAction = "demote_admin"
	AuditActionChangeAdminRole      AuditAction = "change_admin_role"
	AuditActionTransferOrgOwnership AuditAction = "transfer_org_ownership"
	AuditActionDeleteUser           AuditAction = "delete_user"
	AuditActionDeleteOrg            AuditAction = "delete_org"
	AuditActionGrantOrgClient       AuditAction = "grant_org_client"
	AuditActionRevokeOrgClient      AuditAction = "revoke_org_client"
)

// AuditLogEntry is a single row from admin_audit_log.
type AuditLogEntry struct {
	ID         string
	AdminID    *string
	Action     AuditAction
	TargetType string
	TargetID   string
	IPAddress  string
	UserAgent  string
	CreatedAt  time.Time
}

// AuditFilter holds optional filter parameters for audit log queries.
type AuditFilter struct {
	AdminID *string
	Action  string
	From    *time.Time
	To      *time.Time
}

type AuditStore struct {
	db *sql.DB
}

func NewAuditStore(db *sql.DB) *AuditStore {
	return &AuditStore{db: db}
}

// Log inserts an audit entry. adminID may be empty string (logged as NULL).
func (s *AuditStore) Log(ctx context.Context, adminID string, action AuditAction, targetType, targetID, ipAddr, ua string) error {
	var aid *string
	if adminID != "" {
		aid = &adminID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_audit_log (admin_id, action, target_type, target_id, ip_address, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		aid, string(action), targetType, targetID, ipAddr, ua,
	)
	return err
}

// buildFilterWhere constructs a WHERE clause and args slice for the given filter.
// The caller must already have consumed argN args before the returned args.
func buildFilterWhere(filter AuditFilter, startArgN int) (string, []any) {
	var clauses []string
	var args []any
	n := startArgN

	if filter.AdminID != nil {
		n++
		clauses = append(clauses, fmt.Sprintf("admin_id = $%d", n))
		args = append(args, filter.AdminID)
	}
	if filter.Action != "" {
		n++
		clauses = append(clauses, fmt.Sprintf("action = $%d", n))
		args = append(args, filter.Action)
	}
	if filter.From != nil {
		n++
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", n))
		args = append(args, filter.From)
	}
	if filter.To != nil {
		n++
		clauses = append(clauses, fmt.Sprintf("created_at <= $%d", n))
		args = append(args, filter.To)
	}

	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

// CountAuditFiltered returns the total number of audit log entries matching the filter.
func (s *AuditStore) CountAuditFiltered(ctx context.Context, filter AuditFilter) (int, error) {
	where, args := buildFilterWhere(filter, 0)
	q := "SELECT COUNT(*) FROM admin_audit_log " + where
	var count int
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&count)
	return count, err
}

// ListAuditCursor returns audit entries with cursor-based pagination and optional filtering.
// Returns items, next-page cursor (empty = last page), and total filtered count.
func (s *AuditStore) ListAuditCursor(ctx context.Context, limit int, cursor *PageCursor, filter AuditFilter) ([]*AuditLogEntry, string, int, error) {
	total, err := s.CountAuditFiltered(ctx, filter)
	if err != nil {
		return nil, "", 0, err
	}

	const selectCols = `SELECT id, admin_id, action, target_type, target_id, ip_address, user_agent, created_at
	         FROM admin_audit_log`

	var conditions []string
	var args []any

	// cursor predicate (must come first so arg numbers align)
	if cursor != nil {
		conditions = append(conditions,
			fmt.Sprintf("(created_at < $%d OR (created_at = $%d AND id < $%d))", 1, 1, 2))
		args = append(args, cursor.CreatedAt, cursor.ID)
	}

	// filter predicates
	filterWhere, filterArgs := buildFilterWhere(filter, len(args))
	if filterWhere != "" {
		// strip "WHERE " prefix and split into individual clauses
		inner := strings.TrimPrefix(filterWhere, "WHERE ")
		conditions = append(conditions, inner)
		args = append(args, filterArgs...)
	}

	q := selectCols
	if len(conditions) > 0 {
		q += " WHERE " + strings.Join(conditions, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d", len(args)+1)
	args = append(args, limit+1)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", total, err
	}
	defer rows.Close()

	var entries []*AuditLogEntry
	for rows.Next() {
		e := &AuditLogEntry{}
		var ipAddr, ua sql.NullString
		if err := rows.Scan(&e.ID, &e.AdminID, &e.Action, &e.TargetType, &e.TargetID, &ipAddr, &ua, &e.CreatedAt); err != nil {
			return nil, "", total, err
		}
		e.IPAddress = ipAddr.String
		e.UserAgent = ua.String
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", total, err
	}

	nextCursor := ""
	if len(entries) > limit {
		last := entries[limit-1]
		nextCursor = EncodeCursor(last.CreatedAt, last.ID)
		entries = entries[:limit]
	}
	return entries, nextCursor, total, nil
}

// ExportAuditCSV streams all audit entries matching filter as CSV rows to w.
func (s *AuditStore) ExportAuditCSV(ctx context.Context, filter AuditFilter, w io.Writer) error {
	where, args := buildFilterWhere(filter, 0)
	q := `SELECT id, admin_id, action, target_type, target_id, ip_address, user_agent, created_at
	      FROM admin_audit_log ` + where + ` ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "admin_id", "action", "target_type", "target_id", "ip_address", "user_agent", "created_at"})

	for rows.Next() {
		e := &AuditLogEntry{}
		var ipAddr, ua sql.NullString
		if err := rows.Scan(&e.ID, &e.AdminID, &e.Action, &e.TargetType, &e.TargetID, &ipAddr, &ua, &e.CreatedAt); err != nil {
			return err
		}
		adminIDStr := ""
		if e.AdminID != nil {
			adminIDStr = *e.AdminID
		}
		_ = cw.Write([]string{
			e.ID,
			adminIDStr,
			string(e.Action),
			e.TargetType,
			e.TargetID,
			ipAddr.String,
			ua.String,
			e.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	cw.Flush()
	return rows.Err()
}

// DeleteOlderThan removes audit entries created before cutoff. Returns the number deleted.
func (s *AuditStore) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM admin_audit_log WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
