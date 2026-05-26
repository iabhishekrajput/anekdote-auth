-- +goose Up
CREATE TABLE client_claim_definitions (
    id         UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    client_id  TEXT        NOT NULL REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    key        TEXT        NOT NULL,
    value_type TEXT        NOT NULL CHECK (value_type IN ('string', 'number', 'boolean')),
    value      TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_client_claim_key UNIQUE (client_id, key)
);

CREATE INDEX idx_client_claim_definitions_client_id ON client_claim_definitions (client_id);

-- +goose Down
DROP TABLE IF EXISTS client_claim_definitions;
