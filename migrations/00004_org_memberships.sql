-- +goose Up
-- +goose StatementBegin

CREATE TABLE org_memberships (
    org_id     TEXT        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       VARCHAR(32) NOT NULL DEFAULT 'member'
                   CHECK (role IN ('owner', 'admin', 'viewer', 'member')),
    invited_by TEXT        REFERENCES users(id) ON DELETE SET NULL,
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    removed_at TIMESTAMPTZ,
    PRIMARY KEY (org_id, user_id)
);

CREATE INDEX idx_memberships_user ON org_memberships(user_id);
CREATE INDEX idx_memberships_org  ON org_memberships(org_id) WHERE removed_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_memberships_org;
DROP INDEX IF EXISTS idx_memberships_user;
DROP TABLE IF EXISTS org_memberships;

-- +goose StatementEnd
