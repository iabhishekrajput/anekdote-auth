-- +goose Up
-- +goose StatementBegin

-- Service accounts are oauth2_clients rows where org_id IS NOT NULL.
-- They use the client_credentials grant type and receive org_id in the JWT,
-- enabling headless/CI access to the Management API without a browser session.
--
-- The oauth2_clients.org_id column already exists (added in 00003).
-- This migration adds a partial index to make service account lookups fast
-- and documents the pattern for future migrations.

CREATE INDEX IF NOT EXISTS idx_clients_service_account
    ON oauth2_clients(org_id)
    WHERE org_id IS NOT NULL AND public = FALSE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_clients_service_account;

-- +goose StatementEnd
