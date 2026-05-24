-- +goose Up
-- Non-partial index to support full-history queries (all statuses) on client_access_requests.
-- Existing partial indexes only cover status='pending'.
CREATE INDEX idx_car_client_all ON client_access_requests(client_id, requested_at DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_car_client_all;
