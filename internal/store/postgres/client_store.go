package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
)

// ClientStore implements oauth2.ClientStore interface using PostgreSQL
type ClientStore struct {
	db *sql.DB
}

// NewClientStore creates a new PostgreSQL backed client store
func NewClientStore(db *sql.DB) *ClientStore {
	return &ClientStore{db: db}
}

// GetByID retrieves a client by its ID
func (s *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	var (
		secret string
		domain string
		public bool
	)
	err := s.db.QueryRowContext(ctx, "SELECT secret, domain, public FROM oauth2_clients WHERE id = $1", id).Scan(&secret, &domain, &public)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // oauth2 framework expects nil, nil when client is not found
		}
		return nil, err
	}

	return &models.Client{
		ID:     id,
		Secret: secret,
		Domain: domain,
		Public: public,
	}, nil
}
