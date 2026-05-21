-- +goose Up
-- +goose StatementBegin

-- org_id is declared without a FK here; the constraint is added in 00003_organizations.sql
-- after the organizations table is created.
CREATE TABLE oauth2_clients (
    id         VARCHAR(255) PRIMARY KEY,
    secret     VARCHAR(255) NOT NULL,
    domain     VARCHAR(255) NOT NULL,
    public     BOOLEAN      NOT NULL DEFAULT FALSE,
    name       VARCHAR(255) NOT NULL DEFAULT '',
    user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    org_id     UUID,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_clients_domain ON oauth2_clients(domain);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_clients_domain;
DROP TABLE IF EXISTS oauth2_clients;

-- +goose StatementEnd
