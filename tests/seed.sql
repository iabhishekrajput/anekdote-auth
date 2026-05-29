-- E2E test seed data. Run once before Playwright tests start.
-- All credentials are fake and for testing only — never use in production.
-- Password: TestPassword1!  |  Client secret: e2e-test-client-secret

-- Seeded test user (pre-verified, active)
INSERT INTO users (id, name, email, username, password_hash, is_verified)
VALUES (
  '00000000-0000-0000-0000-000000000001',
  'E2E Test User',
  'e2e-seed@example.com',
  'e2e-seed',
  '$2a$10$xdqIDPmqso2V.LJ8gAfzvuiHbNRcJMyES6FjyIv/nIJmmKWXgCAPS',
  TRUE
) ON CONFLICT (id) DO NOTHING;

-- Seeded org owned by the test user
INSERT INTO organizations (id, slug, display_name, owner_id)
VALUES (
  '00000000-0000-0000-0000-000000000002',
  'e2e-test-org',
  'E2E Test Org',
  '00000000-0000-0000-0000-000000000001'
) ON CONFLICT (id) DO NOTHING;

-- Membership: test user is owner of the org
INSERT INTO org_memberships (org_id, user_id, role)
VALUES (
  '00000000-0000-0000-0000-000000000002',
  '00000000-0000-0000-0000-000000000001',
  'owner'
) ON CONFLICT DO NOTHING;

-- Second seeded user — member of e2e-test-org (for role change / remove tests)
INSERT INTO users (id, name, email, username, password_hash, is_verified)
VALUES (
  '00000000-0000-0000-0000-000000000003',
  'E2E Member User',
  'e2e-member@example.com',
  'e2e-member',
  '$2a$10$xdqIDPmqso2V.LJ8gAfzvuiHbNRcJMyES6FjyIv/nIJmmKWXgCAPS',
  TRUE
) ON CONFLICT (id) DO NOTHING;

-- Membership: second user is a member of the test org
INSERT INTO org_memberships (org_id, user_id, role)
VALUES (
  '00000000-0000-0000-0000-000000000002',
  '00000000-0000-0000-0000-000000000003',
  'member'
) ON CONFLICT DO NOTHING;

-- OAuth2 client for consent flow tests
-- client_id: e2e-test-client  |  secret: e2e-test-client-secret  |  redirect: http://localhost:9999/callback
-- owner_org_id mirrors what CreateOrgClient always sets (the owning org); the
-- claims page resolves ownership via owner_org_id, not org_id.
INSERT INTO oauth2_clients (id, secret, domain, public, name, user_id, org_id, owner_org_id)
VALUES (
  'e2e-test-client',
  '$2a$10$3bhKQyoj/oPVxog903yZ.ONOilhh/SPCe1dHW.tGe5FEOnUh45OKe',
  'http://localhost:9999/callback',
  FALSE,
  'E2E Test Client',
  '00000000-0000-0000-0000-000000000001',
  '00000000-0000-0000-0000-000000000002',
  '00000000-0000-0000-0000-000000000002'
) ON CONFLICT (id) DO UPDATE
  SET org_id = EXCLUDED.org_id, owner_org_id = EXCLUDED.owner_org_id;

-- Reset custom claims so the claims E2E test starts from a clean slate. Each run
-- of claims.spec.ts adds a row; without this, repeated runs accumulate toward the
-- 20-claim-per-client cap and eventually fail the suite.
DELETE FROM client_claim_definitions WHERE client_id = 'e2e-test-client';
