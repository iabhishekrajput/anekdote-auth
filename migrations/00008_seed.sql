-- +goose Up
-- +goose StatementBegin

-- ============================================================
-- BOOTSTRAP ADMIN — remove this after first-time setup.
-- ============================================================
-- Use this account to log in and promote your real account:
--
--   Email:    admin@localhost
--   Password: ChangeMe1!
--
-- After logging in:
--   1. Register your real account at /register
--   2. Promote it at /admin/users/:id/promote
--   3. Log out and delete this bootstrap account either via:
--        make migrate-down    (rolls back this file only)
--      or via the admin panel: /admin/users → disable/delete
-- ============================================================
INSERT INTO users (id, name, email, password_hash, is_verified, is_admin, admin_role)
VALUES (
    'usr_00000000000000000000000000',
    'Bootstrap Admin',
    'admin@localhost',
    '$2a$10$D3I1bda1qzOdR0NSxJLXHu.tM1tDQyLna5szEEs0Dx.LMcCfAObOS',
    TRUE,
    TRUE,
    'superadmin'
) ON CONFLICT (email) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM users WHERE email = 'admin@localhost';

-- +goose StatementEnd
