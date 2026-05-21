# TODOS

Deferred items from the autoplan review pipeline (2026-05-21).
These are genuine gaps, not taste decisions — each has a clear "why now is wrong" note.

---

## Auth & Security

### Audit log for admin actions
Admin actions (disable user, delete client, remove org member) have no audit trail. There is no record of who did what or when.
**When:** Before production use at scale. A single-tenant or trusted-team deployment can defer this, but any multi-admin deployment needs it.
**Shape:** Postgres `admin_audit_log` table: `admin_id`, `action`, `target_type`, `target_id`, `created_at`.

### DB-backed admin roles (replace ADMIN_EMAILS)
`ADMIN_EMAILS` env var is correct for the current stage but doesn't scale — it requires a deploy to add/remove admins and can't support role gradations (e.g., read-only admin vs. full admin).
**When:** When the admin team grows beyond 1-2 people or when role gradations are needed.
**Shape:** `user_roles` table or a `role` column on users; `RequireAdmin` checks DB instead of env.

---

## OAuth2

### Integration test for userAuthorizeHandler "return nil" contract
The `"", nil` return from `userAuthorizeHandler` stops go-oauth2 from overwriting a custom-rendered response. This contract is not tested — a go-oauth2 library upgrade could silently break the denial page.
**When:** Before upgrading go-oauth2. Consider adding a narrow integration test that verifies the response body when a non-member hits /authorize.

---

## Admin UX

### Pagination on admin list pages
`/admin/users`, `/admin/clients`, `/admin/orgs` load all rows. Fine for small deployments; will degrade at thousands of records.
**When:** When any list grows past ~500 rows.
**Shape:** Cursor-based pagination; the page/pageSize wiring already exists in `UserList`.
