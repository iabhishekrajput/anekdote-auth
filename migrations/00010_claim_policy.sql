-- +goose Up
-- +goose StatementBegin

ALTER TABLE client_claim_definitions
  ADD COLUMN scope_gate   TEXT          NULL,
  ADD COLUMN destinations TEXT NOT NULL DEFAULT 'token',
  ADD COLUMN source_kind  TEXT NOT NULL DEFAULT 'static';

ALTER TABLE client_claim_definitions
  ADD CONSTRAINT chk_claim_destinations CHECK (destinations IN (
    'access_token', 'id_token', 'token', 'userinfo',
    'access_token,id_token', 'access_token,userinfo', 'id_token,userinfo',
    'token,userinfo', 'access_token,id_token,userinfo'
  )),
  ADD CONSTRAINT chk_claim_source_kind CHECK (source_kind = 'static');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE client_claim_definitions
  DROP CONSTRAINT IF EXISTS chk_claim_destinations,
  DROP CONSTRAINT IF EXISTS chk_claim_source_kind,
  DROP COLUMN IF EXISTS scope_gate,
  DROP COLUMN IF EXISTS destinations,
  DROP COLUMN IF EXISTS source_kind;

-- +goose StatementEnd
