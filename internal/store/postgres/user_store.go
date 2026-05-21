package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/models"
)

var (
	ErrUserNotFound = errors.New("user not found")
	ErrLastAdmin    = errors.New("cannot remove the last admin")
)

type UserStore struct {
	db *sql.DB
}

func NewUserStore(db *sql.DB) *UserStore {
	return &UserStore{db: db}
}

func (s *UserStore) GetByEmail(email string) (*models.User, error) {
	u := &models.User{}
	err := s.db.QueryRow(`
		SELECT id, email, name, password_hash, is_verified, is_admin, disabled_at, created_at, updated_at
		FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.IsVerified, &u.IsAdmin, &u.DisabledAt, &u.CreatedAt, &u.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return u, nil
}

func (s *UserStore) GetByID(id uuid.UUID) (*models.User, error) {
	u := &models.User{}
	err := s.db.QueryRow(`
		SELECT id, email, name, password_hash, is_verified, is_admin, disabled_at, created_at, updated_at
		FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.IsVerified, &u.IsAdmin, &u.DisabledAt, &u.CreatedAt, &u.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
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

	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET is_admin = $1, updated_at = NOW() WHERE id = $2`, admin, id); err != nil {
		return err
	}
	return tx.Commit()
}

// CountAdmins returns the number of admin users.
func (s *UserStore) CountAdmins(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE is_admin = true`).Scan(&count)
	return count, err
}

// SeedAdminEmails sets is_admin=true for every user whose email is in the list.
// Returns the number of rows updated. Safe to call multiple times — idempotent UPDATE.
func (s *UserStore) SeedAdminEmails(ctx context.Context, emails []string) (int, error) {
	if len(emails) == 0 {
		return 0, nil
	}
	placeholders := make([]string, len(emails))
	args := make([]any, len(emails))
	for i, e := range emails {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = e
	}
	query := fmt.Sprintf(
		`UPDATE users SET is_admin = true, updated_at = NOW() WHERE email IN (%s)`,
		strings.Join(placeholders, ","),
	)
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
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

// ListAll returns all users ordered by creation date, newest first.
func (s *UserStore) ListAll(ctx context.Context, limit, offset int) ([]*UserListItem, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, email, name, is_verified, disabled_at, created_at
		 FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*UserListItem
	for rows.Next() {
		u := &UserListItem{}
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.IsVerified, &u.DisabledAt, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// CountAll returns the total number of users.
func (s *UserStore) CountAll(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
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
		INSERT INTO users (email, name, password_hash) 
		VALUES ($1, $2, $3) 
		RETURNING id, email, name, password_hash, is_verified, created_at, updated_at`,
		email, name, passwordHash).
		Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.IsVerified, &u.CreatedAt, &u.UpdatedAt)

	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *UserStore) UpdateName(id uuid.UUID, newName string) error {
	_, err := s.db.Exec(`UPDATE users SET name = $1, updated_at = NOW() WHERE id = $2`, newName, id)
	return err
}

func (s *UserStore) UpdatePassword(id uuid.UUID, newHash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`, newHash, id)
	return err
}

func (s *UserStore) UpdateVerified(id uuid.UUID) error {
	_, err := s.db.Exec(`UPDATE users SET is_verified = TRUE, updated_at = NOW() WHERE id = $1`, id)
	return err
}
