-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- USERS TABLE
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
-- OAUTH2 CLIENTS TABLE
CREATE TABLE IF NOT EXISTS oauth2_clients (
    id VARCHAR(255) PRIMARY KEY,
    secret VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    public BOOLEAN NOT NULL DEFAULT FALSE,
    user_id UUID REFERENCES users(id) ON DELETE
    SET NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
-- INDEXES
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_clients_domain ON oauth2_clients(domain);
-- TRIGGER FOR UPDATED_AT
CREATE OR REPLACE FUNCTION trigger_set_timestamp() RETURNS TRIGGER AS $$ BEGIN NEW.updated_at = NOW();
RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE TRIGGER set_timestamp_users BEFORE
UPDATE ON users FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS set_timestamp_users ON users;
DROP FUNCTION IF EXISTS trigger_set_timestamp();
DROP INDEX IF EXISTS idx_clients_domain;
DROP INDEX IF EXISTS idx_users_email;
DROP TABLE IF EXISTS oauth2_clients;
DROP TABLE IF EXISTS users;
-- DROP EXTENSION IF EXISTS "uuid-ossp"; -- careful dropping this in shared dbs, but safe here typically
-- +goose StatementEnd