-- +goose Up
-- +goose StatementBegin

CREATE TABLE oauth2_clients (
    id           TEXT         PRIMARY KEY,
    secret       VARCHAR(255) NOT NULL,
    domain       VARCHAR(255) NOT NULL,
    public       BOOLEAN      NOT NULL DEFAULT FALSE,
    name         VARCHAR(255) NOT NULL DEFAULT '',
    user_id      TEXT         REFERENCES users(id) ON DELETE SET NULL,
    org_id       TEXT         REFERENCES organizations(id) ON DELETE RESTRICT,
    owner_org_id TEXT         REFERENCES organizations(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_clients_domain           ON oauth2_clients(domain);
CREATE INDEX idx_clients_org              ON oauth2_clients(org_id) WHERE org_id IS NOT NULL;
CREATE INDEX idx_oauth2_clients_org_id    ON oauth2_clients(org_id);
CREATE INDEX idx_oauth2_clients_owner_org ON oauth2_clients(owner_org_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_oauth2_clients_owner_org;
DROP INDEX IF EXISTS idx_oauth2_clients_org_id;
DROP INDEX IF EXISTS idx_clients_org;
DROP INDEX IF EXISTS idx_clients_domain;
DROP TABLE IF EXISTS oauth2_clients;

-- +goose StatementEnd
