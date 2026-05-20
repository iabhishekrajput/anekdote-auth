package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/google/uuid"
)

// OrgClientInfo wraps the library's ClientInfo and adds OrgID.
// GetByID wraps ALL clients — existing clients with no org_id get OrgID=nil,
// so the type assertion in JWTGenerator always succeeds; nil is the safe fallback.
type OrgClientInfo struct {
	oauth2.ClientInfo
	OrgID *uuid.UUID
}

// ClientStore implements oauth2.ClientStore interface using PostgreSQL
type ClientStore struct {
	db *sql.DB
}

// NewClientStore creates a new PostgreSQL backed client store
func NewClientStore(db *sql.DB) *ClientStore {
	return &ClientStore{db: db}
}

// GetByID retrieves a client by its ID, always wrapped in OrgClientInfo.
func (s *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	var (
		secret string
		domain string
		public bool
		orgID  *uuid.UUID
	)
	err := s.db.QueryRowContext(ctx,
		"SELECT secret, domain, public, org_id FROM oauth2_clients WHERE id = $1", id,
	).Scan(&secret, &domain, &public, &orgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	base := &models.Client{
		ID:     id,
		Secret: secret,
		Domain: domain,
		Public: public,
	}
	return &OrgClientInfo{ClientInfo: base, OrgID: orgID}, nil
}
