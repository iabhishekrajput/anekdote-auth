-- +goose Up
-- +goose StatementBegin

-- Dev OAuth2 clients for local development. Safe to keep in production (they're
-- scoped to localhost callbacks) but you can roll this back if you want a clean slate.
--
-- Confidential client secret (bcrypt cost 10):
--   Plaintext: key_rvRkTEdD31RNtMIk3O6esP26oeCUXYs5BHmQ5E84q4AYdgWG
INSERT INTO oauth2_clients (id, secret, domain, public)
VALUES
    ('724ed9d9-63d2-4f85-81c7-00c19926fb10',
     '$2a$10$xwlmG4tmxeF84DwO2PbTMubC7vxv0VuoxKf0CvJuICKg6/TrXRp/y',
     'http://localhost:8080/callback',
     FALSE),
    ('33738764-9d6b-4067-a987-8d87a060b689',
     '',
     'http://localhost:8080/callback',
     TRUE)
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM oauth2_clients
WHERE id IN (
    '724ed9d9-63d2-4f85-81c7-00c19926fb10',
    '33738764-9d6b-4067-a987-8d87a060b689'
);

-- +goose StatementEnd
