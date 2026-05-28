-- +goose Up
-- +goose StatementBegin

CREATE FUNCTION trigger_set_timestamp() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE users (
    id               TEXT         PRIMARY KEY,
    name             VARCHAR(255) NOT NULL,
    username         VARCHAR(255) NOT NULL,
    email            VARCHAR(255) NOT NULL,
    password_hash    VARCHAR(255) NOT NULL,
    is_verified      BOOLEAN      NOT NULL DEFAULT FALSE,
    is_admin         BOOLEAN      NOT NULL DEFAULT FALSE,
    admin_role       TEXT,
    password_changed BOOLEAN      NOT NULL DEFAULT FALSE,
    disabled_at      TIMESTAMPTZ,
    deleted_at       TIMESTAMPTZ,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX uq_idx_users_username ON users(username) WHERE username IS NOT NULL;
CREATE UNIQUE INDEX uq_idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE INDEX idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NOT NULL;

CREATE TRIGGER set_timestamp_users
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS set_timestamp_users ON users;
DROP INDEX IF EXISTS idx_users_deleted_at;
DROP INDEX IF EXISTS uq_idx_users_email;
DROP INDEX IF EXISTS uq_idx_users_username;
DROP TABLE IF EXISTS users;
DROP FUNCTION IF EXISTS trigger_set_timestamp() CASCADE;

-- +goose StatementEnd
