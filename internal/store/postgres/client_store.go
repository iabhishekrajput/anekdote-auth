package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// ErrClientNotFound is returned when a client does not exist or does not belong to the given org.
var ErrClientNotFound = errors.New("client not found or not in org")

// OrgClientInfo wraps the library's ClientInfo and adds OrgID.
// GetByID wraps ALL clients — existing clients with no org_id get OrgID=nil,
// so the type assertion in JWTGenerator always succeeds; nil is the safe fallback.
type OrgClientInfo struct {
	oauth2.ClientInfo
	OrgID *uuid.UUID
}

// VerifyPassword implements oauth2.ClientPasswordVerifier, delegating to the
// inner ClientInfo if it also implements the interface. This allows go-oauth2's
// manager to use bcrypt comparison instead of plaintext equality.
func (c *OrgClientInfo) VerifyPassword(plain string) bool {
	if cp, ok := c.ClientInfo.(oauth2.ClientPasswordVerifier); ok {
		return cp.VerifyPassword(plain)
	}
	return plain == ""
}

// HashedClient is an oauth2.ClientInfo whose secret column stores a bcrypt hash.
// GetSecret returns "" so go-oauth2 never uses the raw hash for equality checks;
// VerifyPassword is the authorised comparison path.
type HashedClient struct {
	id     string
	domain string
	public bool
	hash   string
}

func (c *HashedClient) GetID() string     { return c.id }
func (c *HashedClient) GetSecret() string { return "" }
func (c *HashedClient) GetDomain() string { return c.domain }
func (c *HashedClient) IsPublic() bool    { return c.public }
func (c *HashedClient) GetUserID() string { return "" }
func (c *HashedClient) VerifyPassword(plain string) bool {
	if c.hash == "" {
		return plain == ""
	}
	return bcrypt.CompareHashAndPassword([]byte(c.hash), []byte(plain)) == nil
}

// OrgClient is a row from oauth2_clients scoped to an org.
type OrgClient struct {
	ID        string
	Name      string
	Domain    string
	Public    bool
	CreatedAt time.Time
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

	return &OrgClientInfo{ClientInfo: &HashedClient{
		id:     id,
		domain: domain,
		public: public,
		hash:   secret,
	}, OrgID: orgID}, nil
}

// ListOrgClients returns all clients belonging to the given org, newest first.
func (s *ClientStore) ListOrgClients(ctx context.Context, orgID uuid.UUID) ([]*OrgClient, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, domain, public, created_at FROM oauth2_clients WHERE org_id = $1 ORDER BY created_at DESC",
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []*OrgClient
	for rows.Next() {
		c := &OrgClient{}
		if err := rows.Scan(&c.ID, &c.Name, &c.Domain, &c.Public, &c.CreatedAt); err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

// CreateOrgClient registers a new OAuth2 client scoped to the given org.
// For confidential clients it returns the plaintext secret; for public clients it returns "".
func (s *ClientStore) CreateOrgClient(ctx context.Context, orgID uuid.UUID, name, redirectURI string, public bool) (clientID, plainSecret string, err error) {
	clientID = uuid.New().String()
	var storedSecret string
	if !public {
		plainSecret = generateClientSecret()
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
		if hashErr != nil {
			return "", "", hashErr
		}
		storedSecret = string(hash)
	}
	_, err = s.db.ExecContext(ctx,
		"INSERT INTO oauth2_clients (id, name, secret, domain, public, org_id) VALUES ($1,$2,$3,$4,$5,$6)",
		clientID, name, storedSecret, redirectURI, public, orgID,
	)
	if err != nil {
		return "", "", err
	}
	return clientID, plainSecret, nil
}

// DeleteOrgClient removes a client that belongs to the given org.
// Returns ErrClientNotFound if no matching row exists.
func (s *ClientStore) DeleteOrgClient(ctx context.Context, clientID string, orgID uuid.UUID) error {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM oauth2_clients WHERE id = $1 AND org_id = $2",
		clientID, orgID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrClientNotFound
	}
	return nil
}

// RotateOrgClientSecret generates and stores a new secret for a confidential org client.
// Uses SELECT FOR UPDATE to prevent races. The secret is only returned after a successful commit.
func (s *ClientStore) RotateOrgClientSecret(ctx context.Context, clientID string, orgID uuid.UUID) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var isPublic bool
	err = tx.QueryRowContext(ctx,
		"SELECT public FROM oauth2_clients WHERE id = $1 AND org_id = $2 FOR UPDATE",
		clientID, orgID,
	).Scan(&isPublic)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrClientNotFound
	}
	if err != nil {
		return "", err
	}
	if isPublic {
		return "", errors.New("cannot rotate secret for a public client")
	}

	newSecret := generateClientSecret()
	hash, hashErr := bcrypt.GenerateFromPassword([]byte(newSecret), bcrypt.DefaultCost)
	if hashErr != nil {
		return "", hashErr
	}
	if _, err = tx.ExecContext(ctx,
		"UPDATE oauth2_clients SET secret = $1 WHERE id = $2 AND org_id = $3",
		string(hash), clientID, orgID,
	); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return newSecret, nil
}

// AdminClientItem is used by the admin panel for the client list view.
type AdminClientItem struct {
	ID        string
	Name      string
	Domain    string
	Public    bool
	OrgSlug   string
	OrgName   string
	CreatedAt time.Time
}

// ListAll returns OAuth2 clients across all orgs, newest first, with pagination.
func (s *ClientStore) ListAll(ctx context.Context, limit, offset int) ([]*AdminClientItem, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT c.id, c.name, c.domain, c.public, c.created_at,
		        COALESCE(o.slug, '') AS org_slug, COALESCE(o.display_name, '') AS org_name
		 FROM oauth2_clients c
		 LEFT JOIN organizations o ON o.id = c.org_id
		 ORDER BY c.created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []*AdminClientItem
	for rows.Next() {
		c := &AdminClientItem{}
		if err := rows.Scan(&c.ID, &c.Name, &c.Domain, &c.Public, &c.CreatedAt, &c.OrgSlug, &c.OrgName); err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

// CountAll returns the total number of OAuth2 clients.
func (s *ClientStore) CountAll(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth2_clients`).Scan(&count)
	return count, err
}

// DeleteAny removes a client by ID regardless of org (admin-only operation).
func (s *ClientStore) DeleteAny(ctx context.Context, clientID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM oauth2_clients WHERE id = $1`, clientID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrClientNotFound
	}
	return nil
}

func generateClientSecret() string {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("crypto/rand unavailable: %v", err)
	}
	return "key_" + hex.EncodeToString(b)
}
