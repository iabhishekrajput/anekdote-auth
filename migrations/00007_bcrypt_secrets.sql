-- +goose Up
-- +goose StatementBegin
-- Hash the existing dev seed client secret with bcrypt (cost 10).
-- Original plaintext: key_rvRkTEdD31RNtMIk3O6esP26oeCUXYs5BHmQ5E84q4AYdgWG
UPDATE oauth2_clients
SET secret = '$2a$10$xwlmG4tmxeF84DwO2PbTMubC7vxv0VuoxKf0CvJuICKg6/TrXRp/y'
WHERE id = '724ed9d9-63d2-4f85-81c7-00c19926fb10';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
UPDATE oauth2_clients
SET secret = 'key_rvRkTEdD31RNtMIk3O6esP26oeCUXYs5BHmQ5E84q4AYdgWG'
WHERE id = '724ed9d9-63d2-4f85-81c7-00c19926fb10';
-- +goose StatementEnd
