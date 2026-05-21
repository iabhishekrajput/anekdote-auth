-- +goose Up
-- +goose StatementBegin

CREATE TABLE organizations (
    id           UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    slug         VARCHAR(63)  UNIQUE NOT NULL
                     CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
    display_name VARCHAR(255) NOT NULL,
    owner_id     UUID         NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_orgs_slug ON organizations(slug);

CREATE TRIGGER set_timestamp_organizations
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();

-- Wire the org_id FK on oauth2_clients now that organizations exists.
ALTER TABLE oauth2_clients
    ADD CONSTRAINT oauth2_clients_org_id_fkey
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;

CREATE INDEX idx_clients_org ON oauth2_clients(org_id) WHERE org_id IS NOT NULL;

CREATE TABLE org_memberships (
    org_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       VARCHAR(32) NOT NULL DEFAULT 'member'
                   CHECK (role IN ('owner', 'admin', 'member')),
    invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    removed_at TIMESTAMPTZ,
    PRIMARY KEY (org_id, user_id)
);

CREATE INDEX idx_memberships_user ON org_memberships(user_id);
CREATE INDEX idx_memberships_org  ON org_memberships(org_id) WHERE removed_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_memberships_org;
DROP INDEX IF EXISTS idx_memberships_user;
DROP TABLE IF EXISTS org_memberships;

DROP INDEX IF EXISTS idx_clients_org;
ALTER TABLE oauth2_clients DROP CONSTRAINT IF EXISTS oauth2_clients_org_id_fkey;

DROP TRIGGER IF EXISTS set_timestamp_organizations ON organizations;
DROP INDEX IF EXISTS idx_orgs_slug;
DROP TABLE IF EXISTS organizations;

-- +goose StatementEnd
