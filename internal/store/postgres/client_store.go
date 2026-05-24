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

// ErrGrantNotFound is returned when a client_org_grant row does not exist.
var ErrGrantNotFound = errors.New("grant not found")

// ErrGlobalClientUsesGrant is returned by DeleteOrgClient when the client is a
// multi-org client (org_id IS NULL). The caller should call RevokeOrgAccess instead.
var ErrGlobalClientUsesGrant = errors.New("client is multi-org; revoke grant instead of deleting")

// ErrGrantRequestNotPending is returned when an approve/deny arrives for a request
// that is no longer in 'pending' status (already resolved or consumed concurrently).
var ErrGrantRequestNotPending = errors.New("grant request is not pending")

// OrgGrantItem is a row from client_org_grants joined with client name info.
type OrgGrantItem struct {
	ClientID      string
	ClientName    string
	GrantedAt     time.Time
	GrantedByEmail string
}

// ClientGrantItem is a row from client_org_grants joined with org info.
type ClientGrantItem struct {
	OrgID       uuid.UUID
	OrgSlug     string
	OrgName     string
	GrantedAt   time.Time
}

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

// GetName returns the human-readable client name, delegating to the inner ClientInfo.
func (c *OrgClientInfo) GetName() string {
	type namer interface{ GetName() string }
	if n, ok := c.ClientInfo.(namer); ok {
		return n.GetName()
	}
	return ""
}

// HashedClient is an oauth2.ClientInfo whose secret column stores a bcrypt hash.
// GetSecret returns "" so go-oauth2 never uses the raw hash for equality checks;
// VerifyPassword is the authorised comparison path.
type HashedClient struct {
	id     string
	name   string
	domain string
	public bool
	hash   string
}

func (c *HashedClient) GetID() string     { return c.id }
func (c *HashedClient) GetName() string   { return c.name }
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

// OrgClient is a row from oauth2_clients visible to an org (owned or granted).
type OrgClient struct {
	ID        string
	Name      string
	Domain    string
	Public    bool
	CreatedAt time.Time
	IsGlobal  bool // true when org_id IS NULL (multi-org client)
	IsOwner   bool // true when owner_org_id = queried org
	// Populated for multi-org clients where IsOwner=true (loaded by handler).
	ConnectedOrgs   []*ClientGrantItem
	PendingRequests []*GrantRequest
}

// GrantRequest is a row from client_access_requests.
type GrantRequest struct {
	ID              uuid.UUID
	ClientID        string
	ClientName      string
	RequesterOrgID  uuid.UUID
	RequesterOrgSlug string
	RequesterOrgName string
	OwnerOrgID      uuid.UUID
	RequestedBy     *uuid.UUID
	Status          string
	RequestedAt     time.Time
	ResolvedAt      *time.Time
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
		name   string
		secret string
		domain string
		public bool
		orgID  *uuid.UUID
	)
	err := s.db.QueryRowContext(ctx,
		"SELECT name, secret, domain, public, org_id FROM oauth2_clients WHERE id = $1", id,
	).Scan(&name, &secret, &domain, &public, &orgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &OrgClientInfo{ClientInfo: &HashedClient{
		id:     id,
		name:   name,
		domain: domain,
		public: public,
		hash:   secret,
	}, OrgID: orgID}, nil
}

// ListOrgClients returns all clients visible to an org: owned single-org clients plus
// multi-org clients that have a grant for this org. Newest first.
func (s *ClientStore) ListOrgClients(ctx context.Context, orgID uuid.UUID) ([]*OrgClient, error) {
	const q = `
		SELECT c.id, c.name, c.domain, c.public, c.created_at,
		       (c.org_id IS NULL)        AS is_global,
		       (c.owner_org_id = $1)     AS is_owner
		FROM oauth2_clients c WHERE c.org_id = $1
		UNION
		SELECT c.id, c.name, c.domain, c.public, c.created_at,
		       true                      AS is_global,
		       (c.owner_org_id = $1)     AS is_owner
		FROM oauth2_clients c
		JOIN client_org_grants g ON g.client_id = c.id AND g.org_id = $1
		WHERE c.org_id IS NULL
		ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []*OrgClient
	for rows.Next() {
		c := &OrgClient{}
		if err := rows.Scan(&c.ID, &c.Name, &c.Domain, &c.Public, &c.CreatedAt, &c.IsGlobal, &c.IsOwner); err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

// CreateOrgClient registers a new OAuth2 client scoped to the given org.
// When multiOrg=true the client has org_id=NULL (accessible across orgs); the owner org is
// set via owner_org_id and an auto-grant row is created so the owner can use its own client.
// When multiOrg=false org_id=orgID (single-org, existing behaviour).
// For confidential clients it returns the plaintext secret; for public clients it returns "".
func (s *ClientStore) CreateOrgClient(ctx context.Context, orgID uuid.UUID, name, redirectURI string, public, multiOrg bool) (clientID, plainSecret string, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()

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

	var orgIDVal *uuid.UUID
	if !multiOrg {
		orgIDVal = &orgID
	}

	if _, err = tx.ExecContext(ctx,
		`INSERT INTO oauth2_clients (id, name, secret, domain, public, org_id, owner_org_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		clientID, name, storedSecret, redirectURI, public, orgIDVal, orgID,
	); err != nil {
		return "", "", err
	}

	// Auto-grant the owner org so it can use its own multi-org client without an approval step.
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO client_org_grants (client_id, org_id, granted_by, granted_at)
		 VALUES ($1, $2, $2, NOW())
		 ON CONFLICT (client_id, org_id) DO NOTHING`,
		clientID, orgID,
	); err != nil {
		return "", "", err
	}

	if err = tx.Commit(); err != nil {
		return "", "", err
	}
	return clientID, plainSecret, nil
}

// DeleteOrgClient removes a single-org client owned by orgID.
// Returns ErrGlobalClientUsesGrant when the client is a multi-org client (org_id IS NULL)
// and the org has a grant — the caller should call RevokeOrgAccess instead.
// Returns ErrClientNotFound when the client does not belong to this org at all.
func (s *ClientStore) DeleteOrgClient(ctx context.Context, clientID string, orgID uuid.UUID) error {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM oauth2_clients WHERE id = $1 AND org_id = $2",
		clientID, orgID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		return nil
	}

	// Not a direct-org client — check if it's a multi-org client with a grant for this org.
	isGlobal, err := s.IsGlobalClient(ctx, clientID)
	if err != nil {
		return err
	}
	if isGlobal {
		ok, err := s.HasGrant(ctx, clientID, orgID)
		if err != nil {
			return err
		}
		if ok {
			return ErrGlobalClientUsesGrant
		}
	}
	return ErrClientNotFound
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
		`SELECT public FROM oauth2_clients
		 WHERE id = $1 AND (org_id = $2 OR owner_org_id = $2) FOR UPDATE`,
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
		`UPDATE oauth2_clients SET secret = $1 WHERE id = $2 AND (org_id = $3 OR owner_org_id = $3)`,
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

// ListAllCursor returns OAuth2 clients using cursor-based pagination.
// Returns items, next-page cursor (empty = last page), and total count.
func (s *ClientStore) ListAllCursor(ctx context.Context, limit int, cursor *PageCursor) ([]*AdminClientItem, string, int, error) {
	total, err := s.CountAll(ctx)
	if err != nil {
		return nil, "", 0, err
	}

	const selectCols = `SELECT c.id, c.name, c.domain, c.public, c.created_at,
		        COALESCE(o.slug, '') AS org_slug, COALESCE(o.display_name, '') AS org_name
		 FROM oauth2_clients c
		 LEFT JOIN organizations o ON o.id = c.org_id`

	var rows *sql.Rows
	if cursor == nil {
		rows, err = s.db.QueryContext(ctx,
			selectCols+` ORDER BY c.created_at DESC, c.id DESC LIMIT $1`,
			limit+1,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			selectCols+` WHERE c.created_at < $1 OR (c.created_at = $1 AND c.id < $2)
			 ORDER BY c.created_at DESC, c.id DESC LIMIT $3`,
			cursor.CreatedAt, cursor.ID.String(), limit+1,
		)
	}
	if err != nil {
		return nil, "", total, err
	}
	defer rows.Close()

	var clients []*AdminClientItem
	for rows.Next() {
		c := &AdminClientItem{}
		if err := rows.Scan(&c.ID, &c.Name, &c.Domain, &c.Public, &c.CreatedAt, &c.OrgSlug, &c.OrgName); err != nil {
			return nil, "", total, err
		}
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		return nil, "", total, err
	}

	nextCursor := ""
	if len(clients) > limit {
		last := clients[limit-1]
		// client ID is a string UUID — parse for cursor encoding
		if id, parseErr := uuid.Parse(last.ID); parseErr == nil {
			nextCursor = EncodeCursor(last.CreatedAt, id)
		}
		clients = clients[:limit]
	}
	return clients, nextCursor, total, nil
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

// GrantOrgAccess adds a grant allowing clientID to be used by users of orgID.
// Idempotent — if the grant already exists it is a no-op.
func (s *ClientStore) GrantOrgAccess(ctx context.Context, clientID string, orgID, grantedBy uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO client_org_grants (client_id, org_id, granted_by, granted_at)
		 VALUES ($1, $2, $3, NOW())
		 ON CONFLICT (client_id, org_id) DO NOTHING`,
		clientID, orgID, grantedBy,
	)
	return err
}

// RevokeOrgAccess removes a grant row. The caller is responsible for blocklisting
// outstanding JTIs via the redis token index (oauth:user-org-tokens:{userID}:{orgID}).
func (s *ClientStore) RevokeOrgAccess(ctx context.Context, clientID string, orgID uuid.UUID) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM client_org_grants WHERE client_id = $1 AND org_id = $2`,
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
		return ErrGrantNotFound
	}
	return nil
}

// ListOrgsGrantedClient returns all orgs that have granted access to clientID.
func (s *ClientStore) ListOrgsGrantedClient(ctx context.Context, clientID string) ([]*ClientGrantItem, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT g.org_id, o.slug, o.display_name, g.granted_at
		 FROM client_org_grants g
		 JOIN organizations o ON o.id = g.org_id AND o.deleted_at IS NULL
		 WHERE g.client_id = $1
		 ORDER BY g.granted_at DESC`,
		clientID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []*ClientGrantItem
	for rows.Next() {
		item := &ClientGrantItem{}
		if err := rows.Scan(&item.OrgID, &item.OrgSlug, &item.OrgName, &item.GrantedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListOrgGrantedClients returns all clients that have been granted access to orgID.
func (s *ClientStore) ListOrgGrantedClients(ctx context.Context, orgID uuid.UUID) ([]*OrgGrantItem, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT g.client_id, c.name, g.granted_at, COALESCE(u.email, '')
		 FROM client_org_grants g
		 JOIN oauth2_clients c ON c.id = g.client_id
		 LEFT JOIN users u ON u.id = g.granted_by AND u.deleted_at IS NULL
		 WHERE g.org_id = $1
		 ORDER BY g.granted_at DESC`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []*OrgGrantItem
	for rows.Next() {
		item := &OrgGrantItem{}
		if err := rows.Scan(&item.ClientID, &item.ClientName, &item.GrantedAt, &item.GrantedByEmail); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListUserEligibleOrgsForClient returns orgs where:
//  1. The client has a grant for the org (client_org_grants)
//  2. The user is an active member of the org
func (s *ClientStore) ListUserEligibleOrgsForClient(ctx context.Context, clientID string, userID uuid.UUID) ([]*ClientGrantItem, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT g.org_id, o.slug, o.display_name, g.granted_at
		 FROM client_org_grants g
		 JOIN organizations o ON o.id = g.org_id AND o.deleted_at IS NULL
		 JOIN org_memberships m ON m.org_id = g.org_id AND m.user_id = $2 AND m.removed_at IS NULL
		 WHERE g.client_id = $1
		 ORDER BY o.display_name ASC`,
		clientID, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []*ClientGrantItem
	for rows.Next() {
		item := &ClientGrantItem{}
		if err := rows.Scan(&item.OrgID, &item.OrgSlug, &item.OrgName, &item.GrantedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// IsGlobalClient returns true when the client has org_id IS NULL (multi-org client).
func (s *ClientStore) IsGlobalClient(ctx context.Context, clientID string) (bool, error) {
	var isGlobal bool
	err := s.db.QueryRowContext(ctx,
		`SELECT (org_id IS NULL) FROM oauth2_clients WHERE id = $1`,
		clientID,
	).Scan(&isGlobal)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrClientNotFound
	}
	return isGlobal, err
}

// HasGrant reports whether clientID has an active grant for orgID.
func (s *ClientStore) HasGrant(ctx context.Context, clientID string, orgID uuid.UUID) (bool, error) {
	var ok bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM client_org_grants WHERE client_id = $1 AND org_id = $2)`,
		clientID, orgID,
	).Scan(&ok)
	return ok, err
}

// GetClientOwnerOrgID returns the owner_org_id of a client. Returns nil when unset.
func (s *ClientStore) GetClientOwnerOrgID(ctx context.Context, clientID string) (*uuid.UUID, error) {
	var ownerOrgID *uuid.UUID
	err := s.db.QueryRowContext(ctx,
		`SELECT owner_org_id FROM oauth2_clients WHERE id = $1`,
		clientID,
	).Scan(&ownerOrgID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrClientNotFound
	}
	return ownerOrgID, err
}

// CreateGrantRequest inserts a pending client_access_requests row.
// Returns the new request. If a pending request already exists for this client+org pair,
// the conflict is ignored and nil,nil is returned (caller should redirect with "already pending").
func (s *ClientStore) CreateGrantRequest(ctx context.Context, clientID string, requesterOrgID, ownerOrgID, requestedBy uuid.UUID) (*GrantRequest, error) {
	gr := &GrantRequest{}
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO client_access_requests
		    (client_id, requester_org_id, owner_org_id, requested_by)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT DO NOTHING
		 RETURNING id, client_id, requester_org_id, owner_org_id, requested_by, status, requested_at`,
		clientID, requesterOrgID, ownerOrgID, requestedBy,
	).Scan(&gr.ID, &gr.ClientID, &gr.RequesterOrgID, &gr.OwnerOrgID, &gr.RequestedBy, &gr.Status, &gr.RequestedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return gr, nil
}

// GetGrantRequest fetches a single grant request by ID including client name and requester org info.
func (s *ClientStore) GetGrantRequest(ctx context.Context, requestID uuid.UUID) (*GrantRequest, error) {
	gr := &GrantRequest{}
	err := s.db.QueryRowContext(ctx,
		`SELECT r.id, r.client_id, COALESCE(c.name,''), r.requester_org_id,
		        COALESCE(ro.slug,''), COALESCE(ro.display_name,''),
		        r.owner_org_id, r.requested_by, r.status, r.requested_at
		 FROM client_access_requests r
		 LEFT JOIN oauth2_clients  c  ON c.id  = r.client_id
		 LEFT JOIN organizations   ro ON ro.id = r.requester_org_id
		 WHERE r.id = $1`,
		requestID,
	).Scan(&gr.ID, &gr.ClientID, &gr.ClientName,
		&gr.RequesterOrgID, &gr.RequesterOrgSlug, &gr.RequesterOrgName,
		&gr.OwnerOrgID, &gr.RequestedBy, &gr.Status, &gr.RequestedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrClientNotFound
	}
	return gr, err
}

// ListGrantRequestsForClient returns pending grant requests for a client (owner's view).
func (s *ClientStore) ListGrantRequestsForClient(ctx context.Context, clientID string) ([]*GrantRequest, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.id, r.client_id, COALESCE(c.name,''), r.requester_org_id,
		        COALESCE(ro.slug,''), COALESCE(ro.display_name,''),
		        r.owner_org_id, r.requested_by, r.status, r.requested_at
		 FROM client_access_requests r
		 LEFT JOIN oauth2_clients  c  ON c.id  = r.client_id
		 LEFT JOIN organizations   ro ON ro.id = r.requester_org_id
		 WHERE r.client_id = $1 AND r.status = 'pending'
		 ORDER BY r.requested_at DESC`,
		clientID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGrantRequests(rows)
}

// ListGrantRequestsForOrg returns pending grant requests made by an org (requester's view).
func (s *ClientStore) ListGrantRequestsForOrg(ctx context.Context, requesterOrgID uuid.UUID) ([]*GrantRequest, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.id, r.client_id, COALESCE(c.name,''), r.requester_org_id,
		        COALESCE(ro.slug,''), COALESCE(ro.display_name,''),
		        r.owner_org_id, r.requested_by, r.status, r.requested_at
		 FROM client_access_requests r
		 LEFT JOIN oauth2_clients  c  ON c.id  = r.client_id
		 LEFT JOIN organizations   ro ON ro.id = r.requester_org_id
		 WHERE r.requester_org_id = $1 AND r.status = 'pending'
		 ORDER BY r.requested_at DESC`,
		requesterOrgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGrantRequests(rows)
}

func scanGrantRequests(rows *sql.Rows) ([]*GrantRequest, error) {
	var results []*GrantRequest
	for rows.Next() {
		gr := &GrantRequest{}
		if err := rows.Scan(&gr.ID, &gr.ClientID, &gr.ClientName,
			&gr.RequesterOrgID, &gr.RequesterOrgSlug, &gr.RequesterOrgName,
			&gr.OwnerOrgID, &gr.RequestedBy, &gr.Status, &gr.RequestedAt); err != nil {
			return nil, err
		}
		results = append(results, gr)
	}
	return results, rows.Err()
}

// UpdateOrgClient updates the name and redirect URI of a client owned by ownerOrgID.
func (s *ClientStore) UpdateOrgClient(ctx context.Context, clientID string, ownerOrgID uuid.UUID, name, domain string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE oauth2_clients SET name = $1, domain = $2 WHERE id = $3 AND owner_org_id = $4`,
		name, domain, clientID, ownerOrgID,
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

// GetClientName returns the display name of a client by ID.
func (s *ClientStore) GetClientName(ctx context.Context, clientID string) (string, error) {
	var name string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM oauth2_clients WHERE id = $1`, clientID).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrClientNotFound
	}
	return name, err
}

// ListAllGrantRequestsForClient returns all grant requests for a client across all
// statuses (pending, approved, denied), newest first, limit 50.
func (s *ClientStore) ListAllGrantRequestsForClient(ctx context.Context, clientID string) ([]*GrantRequest, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.id, r.client_id, COALESCE(c.name,''), r.requester_org_id,
		        COALESCE(ro.slug,''), COALESCE(ro.display_name,''),
		        r.owner_org_id, r.requested_by, r.status, r.requested_at
		 FROM client_access_requests r
		 LEFT JOIN oauth2_clients  c  ON c.id  = r.client_id
		 LEFT JOIN organizations   ro ON ro.id = r.requester_org_id
		 WHERE r.client_id = $1
		 ORDER BY r.requested_at DESC
		 LIMIT 50`,
		clientID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGrantRequests(rows)
}

// AdminGrantRow is used by the admin grants panel.
type AdminGrantRow struct {
	ClientID       string
	ClientName     string
	OwnerOrgName   string
	GrantedOrgName string
	GrantedOrgID   uuid.UUID
	GrantedAt      time.Time
}

// ListAllClientOrgGrants returns all grant rows across all clients for the admin panel,
// with owner and granted org info. Returns rows, total count, and error.
func (s *ClientStore) ListAllClientOrgGrants(ctx context.Context, limit, offset int) ([]*AdminGrantRow, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM client_org_grants`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT g.client_id, c.name AS client_name,
		        co.display_name AS owner_org_name,
		        granted_org.display_name AS granted_org_name, g.org_id AS granted_org_id, g.granted_at
		   FROM client_org_grants g
		   JOIN oauth2_clients c ON c.id = g.client_id
		   JOIN organizations co ON co.id = c.owner_org_id
		   JOIN organizations granted_org ON granted_org.id = g.org_id
		  ORDER BY g.granted_at DESC
		  LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []*AdminGrantRow
	for rows.Next() {
		row := &AdminGrantRow{}
		if err := rows.Scan(&row.ClientID, &row.ClientName, &row.OwnerOrgName, &row.GrantedOrgName, &row.GrantedOrgID, &row.GrantedAt); err != nil {
			return nil, 0, err
		}
		results = append(results, row)
	}
	return results, total, rows.Err()
}

// ApproveGrantRequest atomically transitions a pending request to 'approved' and
// creates the client_org_grants row. Binds clientID and ownerOrgID in the WHERE clause
// to prevent cross-client request hijacking. Returns the updated request row so the
// handler can send notification email without an extra query.
func (s *ClientStore) ApproveGrantRequest(ctx context.Context, requestID uuid.UUID, clientID string, ownerOrgID, resolvedBy uuid.UUID) (*GrantRequest, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	gr := &GrantRequest{}
	err = tx.QueryRowContext(ctx,
		`UPDATE client_access_requests
		 SET status='approved', resolved_at=NOW(), resolved_by=$4
		 WHERE id=$1 AND client_id=$2 AND owner_org_id=$3 AND status='pending'
		 RETURNING id, client_id, requester_org_id, owner_org_id, requested_by, status, requested_at`,
		requestID, clientID, ownerOrgID, resolvedBy,
	).Scan(&gr.ID, &gr.ClientID, &gr.RequesterOrgID, &gr.OwnerOrgID, &gr.RequestedBy, &gr.Status, &gr.RequestedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrGrantRequestNotPending
	}
	if err != nil {
		return nil, err
	}

	if _, err = tx.ExecContext(ctx,
		`INSERT INTO client_org_grants (client_id, org_id, granted_by, granted_at)
		 VALUES ($1, $2, $3, NOW())
		 ON CONFLICT (client_id, org_id) DO NOTHING`,
		gr.ClientID, gr.RequesterOrgID, resolvedBy,
	); err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return gr, nil
}

// DenyGrantRequest transitions a pending request to 'denied'. Binds clientID and ownerOrgID
// to prevent cross-client request hijacking. Returns the updated request row for notification email.
func (s *ClientStore) DenyGrantRequest(ctx context.Context, requestID uuid.UUID, clientID string, ownerOrgID, resolvedBy uuid.UUID) (*GrantRequest, error) {
	gr := &GrantRequest{}
	err := s.db.QueryRowContext(ctx,
		`UPDATE client_access_requests
		 SET status='denied', resolved_at=NOW(), resolved_by=$4
		 WHERE id=$1 AND client_id=$2 AND owner_org_id=$3 AND status='pending'
		 RETURNING id, client_id, requester_org_id, owner_org_id, requested_by, status, requested_at`,
		requestID, clientID, ownerOrgID, resolvedBy,
	).Scan(&gr.ID, &gr.ClientID, &gr.RequesterOrgID, &gr.OwnerOrgID, &gr.RequestedBy, &gr.Status, &gr.RequestedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrGrantRequestNotPending
	}
	if err != nil {
		return nil, err
	}
	return gr, nil
}

func generateClientSecret() string {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("crypto/rand unavailable: %v", err)
	}
	return "key_" + hex.EncodeToString(b)
}
