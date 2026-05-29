-- +goose Up
-- +goose StatementBegin

ALTER TABLE client_claim_definitions
  DROP CONSTRAINT IF EXISTS chk_claim_source_kind;

ALTER TABLE client_claim_definitions
  ADD CONSTRAINT chk_claim_source_kind CHECK (source_kind IN ('static', 'user_attribute', 'expression')),
  ADD CONSTRAINT chk_claim_payload_size CHECK (octet_length(key) + octet_length(value) <= 4096);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE client_claim_definitions
  DROP CONSTRAINT IF EXISTS chk_claim_payload_size,
  DROP CONSTRAINT IF EXISTS chk_claim_source_kind;

ALTER TABLE client_claim_definitions
  ADD CONSTRAINT chk_claim_source_kind CHECK (source_kind = 'static');

-- +goose StatementEnd
