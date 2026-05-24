<!-- /autoplan restore point: /Users/abhishek/.gstack/projects/iabhishekrajput-anekdote-auth/main-autoplan-restore-20260524-094041.md -->

# Plan: Multi-org OAuth2 client grants + Footer

Branch: `main` | Date: 2026-05-24

## Problem

Two independent tasks:

### 1. Multi-org OAuth2 client access
Currently every `oauth2_client` is scoped to exactly one `org_id`. A real-world SaaS application (e.g. a CRM) needs to integrate once as an OAuth2 client and serve users from multiple customer orgs — today it must create one client per org, which is unscalable.

**Goal**: Allow a single OAuth2 application (client) to be granted access to multiple organizations. When a user from any of those orgs authenticates, they get an org-scoped token for the org they're a member of.

### 2. Footer on all pages
No footer exists on any page. Need a consistent footer across `BaseLayout` (auth pages), `AccountLayout` (settings/orgs), and `AdminLayout` (admin panel).

---

## Proposed Solution

### Multi-org: Client-org grant table

**New table**: `client_org_grants(client_id TEXT, org_id UUID, granted_by UUID, granted_at TIMESTAMPTZ)` — org owners can explicitly grant their org to an OAuth2 client. PK: `(client_id, org_id)`. FKs: `client_id → oauth2_clients(id) ON DELETE CASCADE`, `org_id → organizations(id) ON DELETE CASCADE`, `granted_by → users(id) ON DELETE SET NULL`.

**Authorization flow change**: At `/authorize` in `userAuthorizeHandler` (oauth2.go):
1. Fetch the client — if `OrgClientInfo.OrgID != nil` (legacy single-org client), behave exactly as today
2. If `OrgClientInfo.OrgID == nil`: query `client_org_grants` for all orgs this client has been granted access to, intersect with the user's active memberships
   - 0 matches → `OAuthAccessDeniedPage` (with "no org has granted this application" copy)
   - 1 match → auto-resolve, no picker (transparent to user)
   - N matches → render `ConsentPage` with org-picker (org shown first, before scopes)
3. Return `"{userUUID}|{selectedOrgID}"` — the `|`-encoded UserID carries the selected org through to the JWT generator

**JWT generator change** (`jwt_generator.go`): Split `data.UserID` on `|`. Use part[0] as `sub`, part[1] as the `org_id` for claims injection (overrides `OrgClientInfo.OrgID`). Re-query `GetMembership(orgID, userID)` at token time to validate user is still a member (defends against org tampering + membership-revocation-after-consent).

**Revocation on grant removal**: `RevokeOrgAccess` must iterate `oauth:user-org-tokens:{userID}:{orgID}` Redis set and blocklist each JTI via `RevocationStore.RevokeJTI` (mirrors existing revocation pattern).

**Who can grant/revoke**: Org owners only (not admins — keeps privilege scope narrow).

**UI surfaces**:
- Inline in `/account/orgs/:slug` settings page: "External access" section (owner-only, below existing sections). Shows list of clients granted access; revoke button per row using `data-confirm` pattern; empty state if none.
- New `OrgGrantItem` struct: `{ClientID, ClientName, GrantedAt, GrantedByEmail}`
- On org-picker consent form: list of orgs with `slug` + `display_name` + user's role badge; radio-style selection; org shown BEFORE scope list; `<input type="hidden" name="selected_org_id">` is server-validated against `client_org_grants` + membership (POST body cannot be trusted)

### Footer

`Footer()` component in `components.templ`. Content: `© 2026 anekdote` — no framework branding on auth pages (trust-sensitive context). Placed below `<main>` in all three layouts with `class="mt-8 pb-6 text-center text-xs text-zinc-500"`. In `BaseLayout` (centered layout), use `class="absolute bottom-6 left-0 right-0 text-center text-xs text-zinc-500"` to avoid competing with centered card.

---

## Scope

### In scope
- Migration: `client_org_grants` table (with FKs + cascade)
- `ClientStore`: `GrantOrgAccess`, `RevokeOrgAccess` (with JTI cleanup), `ListClientOrgGrants`, `ListOrgsGrantedClient`
- `ClientStore`: new `OrgGrantItem` type
- `/authorize` handler: multi-org resolution + org-picker rendering
- `ConsentPage` template: add `eligibleOrgs []OrgOption` + `selectedOrgID string` params; org picker before scopes
- `OAuthAccessDeniedPage`: add "no org has granted this app" variant
- JWT generator: split UserID on `|`, validate org at token time
- Account UI: External Access section on org settings page (owner-only)
- Footer: `components.templ` + 3 layouts
- Audit: `AuditActionGrantOrgClient`, `AuditActionRevokeOrgClient` constants
- Update "You can revoke access anytime from Settings" copy in `ConsentPageBody`

### Out of scope (deferred to TODOS.md)
- Client-initiated org access requests ("request access" flow) — phase 2
- Superadmin UI for managing grants
- Notification emails when a client is granted/revoked
- Per-org scopes

---

## Files expected to change
- `migrations/00007_client_org_grants.sql` (new)
- `internal/store/postgres/client_store.go` — grant/revoke/list methods
- `internal/handlers/oauth2.go` — multi-org resolution at `/authorize`
- `web/ui/consent.templ` — org-picker step (conditional)
- `web/ui/orgs.templ` — external access section
- `web/ui/components.templ` — Footer component
- `web/ui/layout.templ` — BaseLayout + AccountLayout footer
- `web/ui/admin.templ` — AdminLayout footer
- Tests: `client_store_test.go` (new), `oauth2_test.go` (new or extend)
