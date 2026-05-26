-- +goose Up
-- +goose StatementBegin

CREATE TABLE admin_audit_log (
    id          TEXT        PRIMARY KEY,
    admin_id    TEXT        REFERENCES users(id) ON DELETE SET NULL,
    action      TEXT        NOT NULL,
    target_type TEXT        NOT NULL,
    target_id   TEXT        NOT NULL,
    ip_address  TEXT,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX admin_audit_log_created_at_idx ON admin_audit_log(created_at DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS admin_audit_log_created_at_idx;
DROP TABLE IF EXISTS admin_audit_log;

-- +goose StatementEnd
