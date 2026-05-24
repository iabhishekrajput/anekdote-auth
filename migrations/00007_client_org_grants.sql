-- +goose Up
CREATE TABLE client_org_grants (
    client_id  TEXT        NOT NULL REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    org_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    granted_by UUID        REFERENCES users(id) ON DELETE SET NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, org_id)
);

CREATE INDEX idx_client_org_grants_org ON client_org_grants(org_id);

-- +goose Down
DROP INDEX IF EXISTS idx_client_org_grants_org;
DROP TABLE IF EXISTS client_org_grants;
