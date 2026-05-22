package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/models"
)

var ErrInvalidRole = errors.New("role 'owner' cannot be set via UpdateMemberRole; use ownership transfer")
var ErrOwnerCannotBeRemoved = errors.New("org owner cannot be removed; transfer ownership first")

type OrgStore struct {
	db *sql.DB
}

func NewOrgStore(db *sql.DB) *OrgStore {
	return &OrgStore{db: db}
}

func (s *OrgStore) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return s.db.BeginTx(ctx, nil)
}

// CreateOrgWithOwner inserts org + owner membership atomically within the provided tx.
func (s *OrgStore) CreateOrgWithOwner(ctx context.Context, tx *sql.Tx, slug, displayName string, ownerID uuid.UUID) (*models.Org, error) {
	var org models.Org
	err := tx.QueryRowContext(ctx,
		`INSERT INTO organizations (slug, display_name, owner_id)
		 VALUES ($1, $2, $3)
		 RETURNING id, slug, display_name, owner_id, created_at, updated_at`,
		slug, displayName, ownerID,
	).Scan(&org.ID, &org.Slug, &org.DisplayName, &org.OwnerID, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert organization: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO org_memberships (org_id, user_id, role) VALUES ($1, $2, 'owner')`,
		org.ID, ownerID,
	)
	if err != nil {
		return nil, fmt.Errorf("insert owner membership: %w", err)
	}

	return &org, nil
}

func (s *OrgStore) GetOrgBySlug(ctx context.Context, slug string) (*models.Org, error) {
	var org models.Org
	err := s.db.QueryRowContext(ctx,
		`SELECT id, slug, display_name, owner_id, created_at, updated_at
		 FROM organizations WHERE slug = $1`,
		slug,
	).Scan(&org.ID, &org.Slug, &org.DisplayName, &org.OwnerID, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &org, nil
}

func (s *OrgStore) GetOrgByID(ctx context.Context, id uuid.UUID) (*models.Org, error) {
	var org models.Org
	err := s.db.QueryRowContext(ctx,
		`SELECT id, slug, display_name, owner_id, created_at, updated_at
		 FROM organizations WHERE id = $1`,
		id,
	).Scan(&org.ID, &org.Slug, &org.DisplayName, &org.OwnerID, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &org, nil
}

// GetMembership returns the user's active role or ("", nil) for no membership.
func (s *OrgStore) GetMembership(ctx context.Context, orgID, userID uuid.UUID) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx,
		`SELECT role FROM org_memberships
		 WHERE org_id = $1 AND user_id = $2 AND removed_at IS NULL`,
		orgID, userID,
	).Scan(&role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return role, nil
}

// ListOrgsForUser returns active memberships with org details.
func (s *OrgStore) ListOrgsForUser(ctx context.Context, userID uuid.UUID) ([]*models.OrgMembership, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT m.org_id, m.user_id, m.role, m.invited_by, m.joined_at,
		        o.slug, o.display_name, o.owner_id
		 FROM org_memberships m
		 JOIN organizations o ON o.id = m.org_id
		 WHERE m.user_id = $1 AND m.removed_at IS NULL
		 ORDER BY m.joined_at`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var memberships []*models.OrgMembership
	for rows.Next() {
		var m models.OrgMembership
		// We embed org fields into OrgMembership.UserEmail field reuse — for list view
		// we use a dedicated struct; reuse OrgMembership for simplicity here.
		var orgSlug, orgDisplayName string
		var orgOwnerID uuid.UUID
		if err := rows.Scan(&m.OrgID, &m.UserID, &m.Role, &m.InvitedBy, &m.JoinedAt,
			&orgSlug, &orgDisplayName, &orgOwnerID); err != nil {
			return nil, err
		}
		// Store org display name in UserEmail field (display-only; no extra struct)
		// This is overloaded but avoids a separate type for the list view.
		m.UserEmail = orgDisplayName + "|" + orgSlug
		memberships = append(memberships, &m)
	}
	return memberships, rows.Err()
}

// ListOrgMemberships returns a typed list with full org info for /account/orgs list.
type OrgListItem struct {
	Org         models.Org
	Role        string
	MemberCount int
}

func (s *OrgStore) ListOrgsForUserFull(ctx context.Context, userID uuid.UUID) ([]OrgListItem, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT o.id, o.slug, o.display_name, o.owner_id, o.created_at, o.updated_at,
		        m.role,
		        (SELECT COUNT(*) FROM org_memberships m2 WHERE m2.org_id = o.id AND m2.removed_at IS NULL) AS member_count
		 FROM org_memberships m
		 JOIN organizations o ON o.id = m.org_id
		 WHERE m.user_id = $1 AND m.removed_at IS NULL
		 ORDER BY m.joined_at`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []OrgListItem
	for rows.Next() {
		var item OrgListItem
		if err := rows.Scan(
			&item.Org.ID, &item.Org.Slug, &item.Org.DisplayName, &item.Org.OwnerID,
			&item.Org.CreatedAt, &item.Org.UpdatedAt,
			&item.Role, &item.MemberCount,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListMembers returns active members for an org (removed_at IS NULL).
func (s *OrgStore) ListMembers(ctx context.Context, orgID uuid.UUID) ([]*models.OrgMembership, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT m.org_id, m.user_id, m.role, m.invited_by, m.joined_at, u.email
		 FROM org_memberships m
		 JOIN users u ON u.id = m.user_id
		 WHERE m.org_id = $1 AND m.removed_at IS NULL
		 ORDER BY m.joined_at`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []*models.OrgMembership
	for rows.Next() {
		var m models.OrgMembership
		if err := rows.Scan(&m.OrgID, &m.UserID, &m.Role, &m.InvitedBy, &m.JoinedAt, &m.UserEmail); err != nil {
			return nil, err
		}
		members = append(members, &m)
	}
	return members, rows.Err()
}

// AddMember upserts — clears removed_at AND updates role on conflict.
func (s *OrgStore) AddMember(ctx context.Context, orgID, userID uuid.UUID, role string, invitedBy *uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO org_memberships (org_id, user_id, role, invited_by)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (org_id, user_id) DO UPDATE
		   SET removed_at = NULL,
		       role       = EXCLUDED.role,
		       joined_at  = NOW(),
		       invited_by = EXCLUDED.invited_by`,
		orgID, userID, role, invitedBy,
	)
	return err
}

// RemoveMember soft-deletes. Rejects if user is the org owner.
func (s *OrgStore) RemoveMember(ctx context.Context, orgID, userID uuid.UUID) error {
	// Check ownership using organizations.owner_id (source of truth)
	var ownerID uuid.UUID
	err := s.db.QueryRowContext(ctx,
		`SELECT owner_id FROM organizations WHERE id = $1`, orgID,
	).Scan(&ownerID)
	if err != nil {
		return fmt.Errorf("lookup org owner: %w", err)
	}
	if ownerID == userID {
		return ErrOwnerCannotBeRemoved
	}

	_, err = s.db.ExecContext(ctx,
		`UPDATE org_memberships SET removed_at = NOW()
		 WHERE org_id = $1 AND user_id = $2 AND removed_at IS NULL`,
		orgID, userID,
	)
	return err
}

// UpdateMemberRole changes role. Rejects 'owner' — use ownership transfer path.
func (s *OrgStore) UpdateMemberRole(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	if role == "owner" {
		return ErrInvalidRole
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE org_memberships SET role = $3
		 WHERE org_id = $1 AND user_id = $2 AND removed_at IS NULL`,
		orgID, userID, role,
	)
	return err
}

// CountClients returns the number of OAuth2 clients registered to an org.
func (s *OrgStore) CountClients(ctx context.Context, orgID uuid.UUID) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM oauth2_clients WHERE org_id = $1`, orgID,
	).Scan(&count)
	return count, err
}

// AdminOrgItem is used by the admin panel for the org list view.
type AdminOrgItem struct {
	Org         models.Org
	MemberCount int
	ClientCount int
}

// ListAllCursor returns orgs with member and client counts using cursor-based pagination.
// Returns items, next-page cursor (empty = last page), and total count.
func (s *OrgStore) ListAllCursor(ctx context.Context, limit int, cursor *PageCursor) ([]AdminOrgItem, string, int, error) {
	total, err := s.CountAll(ctx)
	if err != nil {
		return nil, "", 0, err
	}

	const selectCols = `SELECT o.id, o.slug, o.display_name, o.owner_id, o.created_at, o.updated_at,
		        (SELECT COUNT(*) FROM org_memberships m WHERE m.org_id = o.id AND m.removed_at IS NULL) AS member_count,
		        (SELECT COUNT(*) FROM oauth2_clients c WHERE c.org_id = o.id) AS client_count
		 FROM organizations o`

	var rows *sql.Rows
	if cursor == nil {
		rows, err = s.db.QueryContext(ctx,
			selectCols+` ORDER BY o.created_at DESC, o.id DESC LIMIT $1`,
			limit+1,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			selectCols+` WHERE o.created_at < $1 OR (o.created_at = $1 AND o.id::text < $2)
			 ORDER BY o.created_at DESC, o.id DESC LIMIT $3`,
			cursor.CreatedAt, cursor.ID.String(), limit+1,
		)
	}
	if err != nil {
		return nil, "", total, err
	}
	defer rows.Close()

	var items []AdminOrgItem
	for rows.Next() {
		var item AdminOrgItem
		if err := rows.Scan(
			&item.Org.ID, &item.Org.Slug, &item.Org.DisplayName, &item.Org.OwnerID,
			&item.Org.CreatedAt, &item.Org.UpdatedAt,
			&item.MemberCount, &item.ClientCount,
		); err != nil {
			return nil, "", total, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, "", total, err
	}

	nextCursor := ""
	if len(items) > limit {
		last := items[limit-1]
		nextCursor = EncodeCursor(last.Org.CreatedAt, last.Org.ID)
		items = items[:limit]
	}
	return items, nextCursor, total, nil
}

// CountAll returns the total number of orgs.
func (s *OrgStore) CountAll(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM organizations`).Scan(&count)
	return count, err
}
