-- +goose Up
ALTER TABLE oauth2_clients
  ADD COLUMN owner_org_id UUID REFERENCES organizations(id) ON DELETE SET NULL;
UPDATE oauth2_clients SET owner_org_id = org_id WHERE org_id IS NOT NULL;
CREATE INDEX idx_oauth2_clients_owner_org ON oauth2_clients(owner_org_id);
CREATE INDEX idx_oauth2_clients_org_id ON oauth2_clients(org_id);

-- +goose Down
DROP INDEX IF EXISTS idx_oauth2_clients_owner_org;
DROP INDEX IF EXISTS idx_oauth2_clients_org_id;
ALTER TABLE oauth2_clients DROP COLUMN IF EXISTS owner_org_id;
