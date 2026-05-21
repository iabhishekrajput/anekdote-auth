-- +goose Up
-- +goose StatementBegin
ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS name VARCHAR(255) NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE oauth2_clients DROP COLUMN IF EXISTS name;
-- +goose StatementEnd
