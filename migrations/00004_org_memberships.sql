-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS org_memberships (
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       VARCHAR(32) NOT NULL DEFAULT 'member'
                CHECK (role IN ('owner', 'admin', 'member')),
    invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
    joined_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    removed_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON org_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_org ON org_memberships(org_id) WHERE removed_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_memberships_org;
DROP INDEX IF EXISTS idx_memberships_user;
DROP TABLE IF EXISTS org_memberships;
-- +goose StatementEnd
