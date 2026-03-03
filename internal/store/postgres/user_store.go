package postgres

import (
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/models"
)

var ErrUserNotFound = errors.New("user not found")

type UserStore struct {
	db *sql.DB
}

func NewUserStore(db *sql.DB) *UserStore {
	return &UserStore{db: db}
}

func (s *UserStore) GetByEmail(email string) (*models.User, error) {
	u := &models.User{}
	err := s.db.QueryRow(`
		SELECT id, email, name, password_hash, is_verified, created_at, updated_at 
		FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.IsVerified, &u.CreatedAt, &u.UpdatedAt)

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
		SELECT id, email, name, password_hash, is_verified, created_at, updated_at 
		FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.IsVerified, &u.CreatedAt, &u.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return u, nil
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
