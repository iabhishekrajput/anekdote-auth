-- +goose Up
-- +goose StatementBegin

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id                UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name              VARCHAR(255) NOT NULL,
    email             VARCHAR(255) UNIQUE NOT NULL,
    password_hash     VARCHAR(255) NOT NULL,
    is_verified       BOOLEAN      NOT NULL DEFAULT FALSE,
    is_admin          BOOLEAN      NOT NULL DEFAULT FALSE,
    admin_role        TEXT,
    password_changed  BOOLEAN      NOT NULL DEFAULT FALSE,
    disabled_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE FUNCTION trigger_set_timestamp() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_timestamp_users
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS set_timestamp_users ON users;
DROP FUNCTION IF EXISTS trigger_set_timestamp();
DROP TABLE IF EXISTS users;
-- Careful in shared DBs — only drop if this is the sole tenant.
DROP EXTENSION IF EXISTS "uuid-ossp";

-- +goose StatementEnd
