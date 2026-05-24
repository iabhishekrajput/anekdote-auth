-- +goose Up
ALTER TABLE users ADD COLUMN deleted_at TIMESTAMPTZ;
ALTER TABLE organizations ADD COLUMN deleted_at TIMESTAMPTZ;

CREATE INDEX idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX idx_orgs_deleted_at  ON organizations(deleted_at) WHERE deleted_at IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_orgs_deleted_at;
DROP INDEX IF EXISTS idx_users_deleted_at;
ALTER TABLE organizations DROP COLUMN deleted_at;
ALTER TABLE users DROP COLUMN deleted_at;
