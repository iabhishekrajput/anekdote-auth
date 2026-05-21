-- +goose Up
-- +goose StatementBegin

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- USERS
CREATE TABLE users (
    id            UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name          VARCHAR(255) NOT NULL,
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_verified   BOOLEAN      NOT NULL DEFAULT FALSE,
    is_admin      BOOLEAN      NOT NULL DEFAULT FALSE,
    disabled_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);

CREATE OR REPLACE FUNCTION trigger_set_timestamp() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_timestamp_users
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();

-- OAUTH2 CLIENTS
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

-- ORGANIZATIONS
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

-- Add org FK to clients (after organizations table exists)
ALTER TABLE oauth2_clients
    ADD CONSTRAINT oauth2_clients_org_id_fkey
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;

CREATE INDEX idx_clients_org ON oauth2_clients(org_id) WHERE org_id IS NOT NULL;

-- ORG MEMBERSHIPS
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

-- ADMIN AUDIT LOG
CREATE TABLE admin_audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    action      TEXT        NOT NULL,
    target_type TEXT        NOT NULL,
    target_id   TEXT        NOT NULL,
    ip_address  TEXT,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX admin_audit_log_created_at_idx ON admin_audit_log(created_at DESC);

-- DEV SEED CLIENTS (bcrypt-hashed secret, cost 10)
-- Plaintext: key_rvRkTEdD31RNtMIk3O6esP26oeCUXYs5BHmQ5E84q4AYdgWG
INSERT INTO oauth2_clients (id, secret, domain, public)
VALUES
    ('724ed9d9-63d2-4f85-81c7-00c19926fb10',
     '$2a$10$xwlmG4tmxeF84DwO2PbTMubC7vxv0VuoxKf0CvJuICKg6/TrXRp/y',
     'http://localhost:8080/callback',
     FALSE),
    ('33738764-9d6b-4067-a987-8d87a060b689',
     '',
     'http://localhost:8080/callback',
     TRUE)
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM oauth2_clients
WHERE id IN (
    '724ed9d9-63d2-4f85-81c7-00c19926fb10',
    '33738764-9d6b-4067-a987-8d87a060b689'
);

DROP TABLE IF EXISTS admin_audit_log;
DROP TABLE IF EXISTS org_memberships;

DROP INDEX IF EXISTS idx_clients_org;
ALTER TABLE oauth2_clients DROP CONSTRAINT IF EXISTS oauth2_clients_org_id_fkey;
ALTER TABLE oauth2_clients DROP COLUMN IF EXISTS org_id;

DROP TABLE IF EXISTS oauth2_clients;
DROP TRIGGER IF EXISTS set_timestamp_organizations ON organizations;
DROP TABLE IF EXISTS organizations;
DROP TRIGGER IF EXISTS set_timestamp_users ON users;
DROP TABLE IF EXISTS users;
DROP FUNCTION IF EXISTS trigger_set_timestamp();
DROP EXTENSION IF EXISTS "uuid-ossp";

-- +goose StatementEnd
