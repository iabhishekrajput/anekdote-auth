-- +goose Up
CREATE TABLE client_access_requests (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id        TEXT        NOT NULL REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    requester_org_id UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    owner_org_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    requested_by     UUID        REFERENCES users(id) ON DELETE SET NULL,
    status           TEXT        NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending','approved','denied')),
    requested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at      TIMESTAMPTZ,
    resolved_by      UUID        REFERENCES users(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX idx_car_pending_unique ON client_access_requests(client_id, requester_org_id) WHERE status = 'pending';
CREATE INDEX idx_car_client   ON client_access_requests(client_id)         WHERE status = 'pending';
CREATE INDEX idx_car_requester ON client_access_requests(requester_org_id) WHERE status = 'pending';
CREATE INDEX idx_car_owner    ON client_access_requests(owner_org_id)      WHERE status = 'pending';

-- +goose Down
DROP TABLE IF EXISTS client_access_requests;
