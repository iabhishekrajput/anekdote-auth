package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/models"
)

var (
	ErrUserNotFound = errors.New("user not found")
	ErrLastAdmin    = errors.New("cannot remove the last admin")
)

var validAdminRoles = map[string]bool{
	"superadmin": true,
	"readonly":   true,
	"org_admin":  true,
}

type UserStore struct {
	db *sql.DB
}

func NewUserStore(db *sql.DB) *UserStore {
	return &UserStore{db: db}
}

func (s *UserStore) GetByEmail(email string) (*models.User, error) {
	u := &models.User{}
	var adminRole sql.NullString
	err := s.db.QueryRow(`
		SELECT id, email, name, password_hash, is_verified, is_admin, admin_role, password_changed, disabled_at, deleted_at, created_at, updated_at
		FROM users WHERE email = $1 AND deleted_at IS NULL`, email).
		Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.IsVerified, &u.IsAdmin, &adminRole, &u.PasswordChanged, &u.DisabledAt, &u.DeletedAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	u.AdminRole = adminRole.String
	return u, nil
}

func (s *UserStore) GetByID(id uuid.UUID) (*models.User, error) {
	u := &models.User{}
	var adminRole sql.NullString
	err := s.db.QueryRow(`
		SELECT id, email, name, password_hash, is_verified, is_admin, admin_role, password_changed, disabled_at, deleted_at, created_at, updated_at
		FROM users WHERE id = $1 AND deleted_at IS NULL`, id).
		Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.IsVerified, &u.IsAdmin, &adminRole, &u.PasswordChanged, &u.DisabledAt, &u.DeletedAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	u.AdminRole = adminRole.String
	return u, nil
}

// SetAdmin sets the is_admin flag for a user. Demoting the last admin returns ErrLastAdmin.
// Uses SELECT FOR UPDATE inside a transaction to prevent TOCTOU races.
func (s *UserStore) SetAdmin(ctx context.Context, id uuid.UUID, admin bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if !admin {
		var count int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users WHERE is_admin = true FOR UPDATE`).Scan(&count); err != nil {
			return err
		}
		if count <= 1 {
			return ErrLastAdmin
		}
	}

	var adminRole interface{}
	if admin {
		adminRole = "superadmin"
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET is_admin = $1, admin_role = $2, updated_at = NOW() WHERE id = $3`, admin, adminRole, id); err != nil {
		return err
	}
	return tx.Commit()
}

// SetAdminRole updates the admin_role column. Only valid roles are accepted.
func (s *UserStore) SetAdminRole(ctx context.Context, id uuid.UUID, role string) error {
	if !validAdminRoles[role] {
		return errors.New("invalid admin role: must be superadmin, readonly, or org_admin")
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET admin_role = $1, updated_at = NOW() WHERE id = $2`, role, id)
	return err
}

// CountAdmins returns the number of admin users.
func (s *UserStore) CountAdmins(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE is_admin = true`).Scan(&count)
	return count, err
}

// UserListItem is used by the admin panel for list views.
type UserListItem struct {
	ID         uuid.UUID
	Email      string
	Name       string
	IsVerified bool
	DisabledAt *time.Time
	CreatedAt  time.Time
}

// ListAllCursor returns up to limit users using cursor-based pagination.
// cursor may be nil for the first page. Returns the items, a next-page cursor
// (empty string if no more pages), and the total count.
func (s *UserStore) ListAllCursor(ctx context.Context, limit int, cursor *PageCursor) ([]*UserListItem, string, int, error) {
	total, err := s.CountAll(ctx)
	if err != nil {
		return nil, "", 0, err
	}

	var rows *sql.Rows
	if cursor == nil {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, email, name, is_verified, disabled_at, created_at
			 FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC, id DESC LIMIT $1`,
			limit+1,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, email, name, is_verified, disabled_at, created_at
			 FROM users
			 WHERE deleted_at IS NULL AND (created_at < $1 OR (created_at = $1 AND id::text < $2))
			 ORDER BY created_at DESC, id DESC LIMIT $3`,
			cursor.CreatedAt, cursor.ID.String(), limit+1,
		)
	}
	if err != nil {
		return nil, "", total, err
	}
	defer rows.Close()

	var users []*UserListItem
	for rows.Next() {
		u := &UserListItem{}
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.IsVerified, &u.DisabledAt, &u.CreatedAt); err != nil {
			return nil, "", total, err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, "", total, err
	}

	nextCursor := ""
	if len(users) > limit {
		last := users[limit-1]
		nextCursor = EncodeCursor(last.CreatedAt, last.ID)
		users = users[:limit]
	}
	return users, nextCursor, total, nil
}

// CountAll returns the total number of non-deleted users.
func (s *UserStore) CountAll(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE deleted_at IS NULL`).Scan(&count)
	return count, err
}

var ErrUserOwnsOrg = errors.New("user owns one or more organizations; transfer ownership before deleting")

// DeleteUser soft-deletes a user by anonymizing their email/name and setting deleted_at.
// Fails if the user still owns any non-deleted organizations.
// Uses SELECT FOR UPDATE to prevent concurrent double-delete races.
func (s *UserStore) DeleteUser(ctx context.Context, id uuid.UUID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Lock the user row.
	var currentDeletedAt *time.Time
	if err := tx.QueryRowContext(ctx,
		`SELECT deleted_at FROM users WHERE id = $1 FOR UPDATE`, id,
	).Scan(&currentDeletedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return err
	}
	if currentDeletedAt != nil {
		return ErrUserNotFound
	}

	// Reject if user still owns orgs.
	var ownedOrgs int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM organizations WHERE owner_id = $1 AND deleted_at IS NULL`, id,
	).Scan(&ownedOrgs); err != nil {
		return err
	}
	if ownedOrgs > 0 {
		return ErrUserOwnsOrg
	}

	// Anonymize and soft-delete.
	_, err = tx.ExecContext(ctx,
		`UPDATE users SET
			deleted_at = NOW(),
			email      = 'deleted-' || id::text || '@deleted.invalid',
			name       = '[deleted]',
			password_hash = '',
			updated_at = NOW()
		 WHERE id = $1`, id,
	)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// SetDisabled sets or clears disabled_at for a user.
func (s *UserStore) SetDisabled(ctx context.Context, id uuid.UUID, disabled bool) error {
	var err error
	if disabled {
		_, err = s.db.ExecContext(ctx,
			`UPDATE users SET disabled_at = NOW(), updated_at = NOW() WHERE id = $1`, id)
	} else {
		_, err = s.db.ExecContext(ctx,
			`UPDATE users SET disabled_at = NULL, updated_at = NOW() WHERE id = $1`, id)
	}
	return err
}

func (s *UserStore) Create(email, name, passwordHash string) (*models.User, error) {
	u := &models.User{}
	err := s.db.QueryRow(`
		INSERT INTO users (email, name, password_hash, password_changed)
		VALUES ($1, $2, $3, TRUE)
		RETURNING id, email, name, password_hash, is_verified, created_at, updated_at`,
		email, name, passwordHash).
		Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.IsVerified, &u.CreatedAt, &u.UpdatedAt)

	if err != nil {
		return nil, err
	}
	u.PasswordChanged = true
	return u, nil
}

func (s *UserStore) UpdateName(id uuid.UUID, newName string) error {
	_, err := s.db.Exec(`UPDATE users SET name = $1, updated_at = NOW() WHERE id = $2`, newName, id)
	return err
}

func (s *UserStore) UpdatePassword(id uuid.UUID, newHash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash = $1, password_changed = TRUE, updated_at = NOW() WHERE id = $2`, newHash, id)
	return err
}

func (s *UserStore) UpdateVerified(id uuid.UUID) error {
	_, err := s.db.Exec(`UPDATE users SET is_verified = TRUE, updated_at = NOW() WHERE id = $1`, id)
	return err
}

// ListOrgAdmins returns the emails of active owners and admins in the given org.
func (s *UserStore) ListOrgAdmins(ctx context.Context, orgID uuid.UUID) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT u.email FROM users u
		 JOIN org_memberships m ON m.user_id = u.id
		 WHERE m.org_id = $1 AND m.role IN ('owner', 'admin')
		   AND m.removed_at IS NULL
		   AND u.disabled_at IS NULL AND u.deleted_at IS NULL`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var emails []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, err
		}
		emails = append(emails, email)
	}
	return emails, rows.Err()
}
