-- +goose Up
-- +goose StatementBegin
ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE RESTRICT;
CREATE INDEX IF NOT EXISTS idx_clients_org ON oauth2_clients(org_id) WHERE org_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_clients_org;
ALTER TABLE oauth2_clients DROP COLUMN IF EXISTS org_id;
-- +goose StatementEnd
