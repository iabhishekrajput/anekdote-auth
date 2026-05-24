# TODOS

## Deferred from multi-org OAuth2 grant plan (2026-05-24)

- [x] **Client-initiated org access requests (phase 2)** — Implemented in previous session (CreateGrantRequest, ApproveGrantRequest, DenyGrantRequest, email template, routes).
- [x] **Superadmin grant management UI** — Admin panel `/admin/grants` view with revoke action and optional reason field. Implemented 2026-05-25.
- [x] **Notification emails on grant/revoke** — Emails sent on approve, deny, revoke (user + admin), and secret rotation. Implemented 2026-05-25.
- [ ] **Per-org scopes** — Allow different allowed scopes per `(client_id, org_id)` pair. Requires schema changes.
- [ ] **Client registration self-service** — Allow developers to register OAuth2 clients without admin involvement.

## Added 2026-05-24

- [x] **Edit OAuth2 client details** — `GET/POST /account/orgs/:slug/clients/:clientID/edit` allows updating name and redirect URI. Implemented 2026-05-25.
- [x] **Email notifications for all key events** — Grant approved/denied, grant revoked (user + admin with reason), secret rotated. Implemented 2026-05-25.
- [x] **Pending grant requests UI screen** — `/account/orgs/:slug/clients/:clientID/requests` shows full history (all statuses, limit 50) with approve/deny for pending items. Implemented 2026-05-25.
