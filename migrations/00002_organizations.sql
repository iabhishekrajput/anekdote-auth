-- +goose Up
-- +goose StatementBegin

CREATE TABLE organizations (
    id           TEXT         PRIMARY KEY,
    slug         VARCHAR(63)  NOT NULL
                     CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
    display_name VARCHAR(255) NOT NULL,
    owner_id     TEXT         NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    deleted_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_orgs_slug ON organizations(slug) WHERE deleted_at IS NULL;
CREATE INDEX idx_orgs_deleted_at ON organizations(deleted_at) WHERE deleted_at IS NOT NULL;

CREATE TRIGGER set_timestamp_organizations
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS set_timestamp_organizations ON organizations;
DROP INDEX IF EXISTS idx_orgs_deleted_at;
DROP INDEX IF EXISTS idx_orgs_slug;
DROP TABLE IF EXISTS organizations;

-- +goose StatementEnd
