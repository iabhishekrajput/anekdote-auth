<!-- /autoplan restore point: /Users/abhishek/.gstack/projects/iabhishekrajput-anekdote-auth/main-autoplan-restore-20260524-235530.md -->

# Plan: OAuth2 Client Polish — Edit, Notifications, Request History, Grants Admin

Branch: `main` | Date: 2026-05-24

## Context

The multi-org OAuth2 grant feature shipped (migration 00008/00009, `client_access_requests`
table, approve/deny flows, email notification for inbound requests). Four remaining
TODOS form a natural cohesive set:

1. Clients are **immutable** after registration — name, redirect URI cannot be changed.
2. Grant events (approved, denied, revoked) and secret rotations happen **silently** — no emails.
3. The **pending request history** is only visible inline on the client card; no dedicated page
   for filtering past/approved/denied requests.
4. Superadmin has no **grant management view** in the admin panel — `/admin/clients` shows the
   client list but not which orgs are connected.

Per-org scopes and client registration self-service are explicitly out of scope (complex schema
changes that warrant their own plan).

---

## Problem

### A — Edit OAuth2 Client Details

`CreateOrgClient` sets `name`, `domain` (redirect URI), and `public`/`multiOrg` at creation.
There is no `UpdateOrgClient` store method or UI form. Org owners/admins cannot correct a
typo in the client name or change the redirect URI without admin intervention.

Multi-org toggle: changing from single-org (`org_id = orgID`) to multi-org (`org_id = NULL`)
after creation requires a migration-like schema change. This is forward-locked — once a client
is registered as single-org, the toggle cannot be changed via self-service. The UI checkbox
is disabled post-registration with a tooltip explaining why.

### B — Email Notifications for Key Events

Currently only `SendClientGrantRequest` exists (inbound request email). Missing:
- **Grant approved**: requester org gets email when owner org approves their request.
- **Grant denied**: requester org gets email when owner org denies their request.
- **Grant revoked**: the org whose access was revoked gets email.
- **Client secret rotated**: client owner org gets email (security event).

Member role changed and org deleted are out of scope — these are user-facing events on
different surfaces, not directly related to OAuth2 clients.

### C — Pending Grant Requests UI Page

`GET /account/orgs/:slug/clients/:clientID/requests` — dedicated page with full request
history (pending, approved, denied), with basic status filtering. The inline card on
`/account/orgs/:slug/clients` continues to show only pending requests; the new page is
linked from a "View all requests" link.

### D — Superadmin Grant Management UI

`GET /admin/grants` — lists all `client_org_grants` rows with client name, owner org name,
granted org name, granted_at. Paginated, searchable by client name. Allows superadmin to
revoke any grant via `POST /admin/grants/:clientID/:orgID/revoke`.

---

## Design

### A — Edit Client Form

**Route:** `GET /account/orgs/:slug/clients/:clientID/edit` — renders an edit form.
**Submit:** `POST /account/orgs/:slug/clients/:clientID/edit`

**Fields:**
- Name (text input, required, 3-64 chars)
- Redirect URI (text input, required, must start with `https://` or `http://localhost`)
- Multi-org availability: **disabled** checkbox showing current setting with note "This
  setting cannot be changed after registration."

**Success:** redirects to `/account/orgs/:slug/clients` with flash "Client updated."
**Guard:** actor must be owner or admin of `:slug`; client must be owned by this org
  (`owner_org_id = org.ID`).

**Store method:** `UpdateOrgClient(ctx, clientID string, orgID uuid.UUID, name, redirectURI string) error`

```sql
UPDATE oauth2_clients
   SET name = $1, domain = $2, updated_at = NOW()
 WHERE id = $3 AND (org_id = $4 OR owner_org_id = $4)
```

Returns `ErrClientNotFound` (0 rows affected) if client not owned by this org.

### B — Event Emails

**Grant approved** — sent to requester org's owners/admins after `ApproveGrantRequest`.
**Grant denied** — sent to requester org's owners/admins after `DenyGrantRequest`.
**Grant revoked** — sent to the org that lost access after `RevokeOrgAccess` (when called from org UI, not admin panel).
**Secret rotated** — sent to client owner org's owners/admins after `RotateOrgClientSecret`.

Email spec:
- Approve email: "Your request to access `<ClientName>` was approved. You can now use it in your OAuth2 flows."
- Deny email: "Your request to access `<ClientName>` was denied by the client owner."
- Revoke email: "Your org's access to `<ClientName>` has been removed."
- Secret rotated email: "The secret for your OAuth2 client `<ClientName>` was rotated on `<date>`. If you didn't do this, contact support."

**New mailer methods:**
- `SendGrantApproved(ctx, toEmails []string, clientName string) error`
- `SendGrantDenied(ctx, toEmails []string, clientName string) error`
- `SendGrantRevoked(ctx, toEmails []string, clientName string) error`
- `SendSecretRotated(ctx, toEmails []string, clientName string) error`

**New email templates:** `web/ui/email/grant_approved.templ`, `grant_denied.templ`,
`grant_revoked.templ`, `secret_rotated.templ`

**Sender integration:**
- `handlers/org.go:ApproveGrantRequest` — after `store.ApproveGrantRequest` succeeds, load
  requester org's owners/admins from `UserStore.ListOrgAdmins(ctx, requesterOrgID)`, send
  in goroutine (fire-and-forget, same pattern as `SendClientGrantRequest`).
- `handlers/org.go:DenyGrantRequest` — same pattern.
- `handlers/org.go:RevokeClientAccess` — after `store.RevokeOrgAccess` succeeds, load the
  revoked org's owners/admins, send `SendGrantRevoked` in goroutine.
- `handlers/org.go:RotateClientSecret` — after `store.RotateOrgClientSecret` succeeds, load
  owner org's owners/admins, send `SendSecretRotated` in goroutine.

**`UserStore.ListOrgAdmins(ctx, orgID uuid.UUID) ([]string, error)`** — returns email
addresses of all owners and admins in the org:
```sql
SELECT u.email FROM users u
JOIN org_members m ON m.user_id = u.id
WHERE m.org_id = $1 AND m.role IN ('owner', 'admin')
  AND u.disabled_at IS NULL AND u.deleted_at IS NULL
```

### C — Request History Page

**Route:** `GET /account/orgs/:slug/clients/:clientID/requests`

Linked from the "Pending requests" subsection on the clients card with a "View history"
anchor. The page lists all `client_access_requests` rows for the client (not just pending).

**Store method:** `ListAllGrantRequestsForClient(ctx, clientID string) ([]*GrantRequest, error)`
```sql
SELECT id, client_id, requester_org_id, owner_org_id, requested_by, status,
       requested_at, resolved_at, resolved_by
  FROM client_access_requests
 WHERE client_id = $1
 ORDER BY requested_at DESC
```

Returns all statuses. Filtering by status is done in the template (no server-side
filter param needed for the MVP — the full list is paginated to 50 rows max).

**Guard:** actor must be owner or admin of `:slug` AND client must be owned by this org
(`owner_org_id = org.ID`). Requester orgs cannot see the full history (they can only
see their own outgoing requests on `OrgDetail`).

**Template:** `RequestHistoryPage` in `web/ui/orgs.templ`
- Status badge: green = approved, yellow = pending, red = denied
- Approve/Deny inline forms for pending rows (reuse existing form design from clients card)
- "Back to clients" breadcrumb

### D — Superadmin Grant Management

**Route:** `GET /admin/grants` — new handler `AdminHandler.GrantList`

**Store method:** `ListAllClientOrgGrants(ctx, offset, limit int) ([]*AdminGrantRow, error)`
```sql
SELECT g.client_id, c.name AS client_name, co.name AS owner_org_name,
       go_org.name AS granted_org_name, g.granted_at
  FROM client_org_grants g
  JOIN oauth2_clients c ON c.id = g.client_id
  JOIN organizations co ON co.id = c.owner_org_id
  JOIN organizations go_org ON go_org.id = g.org_id
 ORDER BY g.granted_at DESC
 LIMIT $1 OFFSET $2
```

`AdminGrantRow` struct:
```go
type AdminGrantRow struct {
    ClientID       string
    ClientName     string
    OwnerOrgName   string
    GrantedOrgName string
    GrantedAt      time.Time
}
```

**Revoke:** `POST /admin/grants/:clientID/:orgID/revoke` — calls existing `RevokeOrgAccess`.
Does NOT send revoke email (admin action, not org-initiated).

**Template:** new section in `web/ui/admin.templ`

---

## In Scope

### Store (`client_store.go`)
- `UpdateOrgClient(ctx, clientID string, orgID uuid.UUID, name, redirectURI string) error`
- `ListAllGrantRequestsForClient(ctx, clientID string) ([]*GrantRequest, error)` — all statuses
- `ListAllClientOrgGrants(ctx, offset, limit int) ([]*AdminGrantRow, error)` — admin view

### Store (`user_store.go`)
- `ListOrgAdmins(ctx, orgID uuid.UUID) ([]string, error)` — returns email addresses

### Handlers (`org.go`)
- New `EditClient` GET/POST handler
- Update `ApproveGrantRequest` to send `SendGrantApproved` goroutine
- Update `DenyGrantRequest` to send `SendGrantDenied` goroutine
- Update `RevokeClientAccess` to send `SendGrantRevoked` goroutine
- Update `RotateClientSecret` to send `SendSecretRotated` goroutine
- New `ClientRequestHistory` GET handler

### Handlers (`admin.go`)
- New `GrantList` GET handler
- New `RevokeGrant` POST handler (admin-only)

### Mailer (`mail.go`)
- `SendGrantApproved(ctx, toEmails []string, clientName string) error`
- `SendGrantDenied(ctx, toEmails []string, clientName string) error`
- `SendGrantRevoked(ctx, toEmails []string, clientName string) error`
- `SendSecretRotated(ctx, toEmails []string, clientName string) error`

### Email Templates (`web/ui/email/`)
- `grant_approved.templ`
- `grant_denied.templ`
- `grant_revoked.templ`
- `secret_rotated.templ`

### Templates (`web/ui/orgs.templ`)
- Edit client form page (`EditClientPage`, `EditClientBody`)
- Request history page (`RequestHistoryPage`, `RequestHistoryBody`)
- "View history" link on clients card pending requests subsection

### Templates (`web/ui/admin.templ`)
- `GrantListPage`, `GrantListBody` — grants table with revoke button

### Router (`router.go`)
- `GET  /account/orgs/:slug/clients/:clientID/edit` → `orgH.EditClient`
- `POST /account/orgs/:slug/clients/:clientID/edit` → `orgH.EditClient`
- `GET  /account/orgs/:slug/clients/:clientID/requests` → `orgH.ClientRequestHistory`
- `GET  /admin/grants` → `requireAdmin(adminH.GrantList)`
- `POST /admin/grants/:clientID/:orgID/revoke` → `requireSuperAdmin(adminH.RevokeGrant)`

---

## Out of Scope

- Per-org scopes (`client_org_grants.allowed_scopes`) — requires schema change, OIDC claims
  update, and consent UI changes; separate plan
- Client registration self-service (public client registration without admin) — requires
  trust model, developer identity verification; separate plan
- Member role changed / org deleted emails — different surface, lower priority
- Pagination UI on grant request history (just show last 50, link to full admin view)
- Search/filter on grant history page (status tabs: All / Pending / Approved / Denied)
- Email preferences / unsubscribe (not in scope for any email in this system yet)

---

## Files Expected to Change

- `internal/store/postgres/client_store.go` (3 new methods + 2 signature changes)
- `internal/store/postgres/user_store.go` (1 new method)
- `internal/handlers/org.go` (new handlers + email goroutines in 4 existing handlers)
- `internal/handlers/admin.go` (2 new handlers)
- `internal/mailer/mail.go` (4 new send methods)
- `internal/server/router.go` (5 new routes)
- `web/ui/orgs.templ` (edit form page, request history page, "view history" link)
- `web/ui/admin.templ` (grant list section)
- `web/ui/email/grant_approved.templ` (new)
- `web/ui/email/grant_denied.templ` (new)
- `web/ui/email/grant_revoked.templ` (new)
- `web/ui/email/secret_rotated.templ` (new)
- `migrations/00010_client_access_requests_index.sql` (new — non-partial index for history query)

---

## GSTACK REVIEW REPORT

### Phase 1 — CEO Review

#### Premise Challenge

| Premise | Status | Notes |
|---------|--------|-------|
| "Clients are immutable post-registration" | Valid | No `UpdateOrgClient` exists in `client_store.go` |
| "Grant events happen silently" | Valid | `mail.go` has 5 `Send*` methods; none cover approve/deny/revoke/rotate |
| "Request history visible inline only" | Valid | `ListGrantRequestsForClient` returns pending only; no history query |
| "Admin has no grant view" | Valid | `/admin/clients` shows client list, no join to `client_org_grants` |
| "Multi-org toggle is forward-locked" | Reasonable | Changing `org_id` null-status requires migration; UI lock is correct |
| "Admin silent revoke is acceptable" | **USER RESOLVED** | User chose B: add notification email with optional reason field |
| "Template filtering is client-side" | Wrong | Go templates are server-side; plan updated to say "no filter UI, all rows rendered" |

#### CEO DUAL VOICES — CONSENSUS TABLE

```
CEO DUAL VOICES — CONSENSUS TABLE:
═══════════════════════════════════════════════════════════════════════
  Dimension                            Claude  Codex   Consensus
  ─────────────────────────────────────────── ─────── ──────────
  1. Premises valid?                    Partial Partial CONFIRMED PARTIAL
  2. Right problem to solve?            Accept  Accept  CONFIRMED (with caveats)
  3. Scope calibration correct?         Accept  Flag    DISAGREE
  4. Alternatives sufficiently explored?Flag   Flag    CONFIRMED gap
  5. Security risks covered?            Flag    Flag    CONFIRMED risks
  6. 6-month trajectory?               Flag    Flag    CONFIRMED concerns
═══════════════════════════════════════════════════════════════════════
```

#### NOT In Scope (deferred)

| Item | Reason |
|------|--------|
| Per-org scopes | Requires schema change + OIDC claims update + consent UI; separate plan. Strategic risk noted by both CEO voices. |
| Client registration self-service | Requires trust model + identity verification; separate plan |
| Member role changed / org deleted emails | Different surface, lower priority, separate plan |
| Webhook delivery for grant events | Future: notification preferences, DLQ, reliability |
| Multi-org toggle migration escape hatch | Added to TODOS: admin-only toggle post-registration, with re-approval |

#### Auto-Decided Additions (CEO)

1. `ListOrgAdmins` zero-admin guard: if slice is empty, caller skips send (P1)
2. Per-org scopes strategic note added to TODOS (P3)
3. Admin revoke notification scope added to plan per user choice in D1

#### Premise Gate

Passed by user. User chose: confirm premises with B (add admin notification for revoke).

---

### Phase 2 — Design Review

#### Design Scope: 4/10. Fields named but states, copy, and accessibility absent.

#### Design Findings (all auto-decided)

1. **Edit form: disabled multi-org checkbox → read-only label** (P5): replace checkbox with label text "Availability: Single-org only" or "Multi-org". No disabled fields.
2. **Edit form validation errors explicitly specified** (P1): name < 3 chars, name > 64 chars, bad URI scheme, generic server error.
3. **Request history column order explicit** (P5): `Requester Org | Requested | Status | Actions`.
4. **Empty states** (P1): request history "No requests yet. When other organizations request access, they'll appear here."; admin grants "No active grants."; admin flash after revoke "Access revoked for `<orgName>`."
5. **Post-edit redirect anchor** (P5): redirect to `/account/orgs/:slug/clients#client-{clientID}`.
6. **Secret rotated email: support link** (P3): `mailto:support@<appURL domain>` or leave as prose — use same app URL config.
7. **AdminGrantRow needs `GrantedOrgID uuid.UUID`** (P1 CRITICAL): revoke POST needs `:orgID`; struct must include it.
8. **No filter UI on request history** (P5): all rows rendered server-side, LIMIT 50 in query.
9. **SQL alias `granted_org` not `go_org`** (P5): cleaner in Go context.
10. **Accessibility baseline** (P1): `aria-label` on status badges, admin revoke button, edit form inputs.

---

### Phase 3 — Eng Review

#### Architecture (corrected SQL)

**`UpdateOrgClient` — corrected SQL:**
```sql
UPDATE oauth2_clients
   SET name = $1, domain = $2
 WHERE id = $3 AND owner_org_id = $4
```
No `updated_at` (column doesn't exist). Guard is `owner_org_id` only (not `OR org_id`).

**`ListAllClientOrgGrants` — corrected SQL:**
```sql
SELECT g.client_id, c.name AS client_name, co.display_name AS owner_org_name,
       granted_org.display_name AS granted_org_name, g.org_id AS granted_org_id, g.granted_at
  FROM client_org_grants g
  JOIN oauth2_clients c ON c.id = g.client_id
  JOIN organizations co ON co.id = c.owner_org_id
  JOIN organizations granted_org ON granted_org.id = g.org_id
 ORDER BY g.granted_at DESC
 LIMIT $1 OFFSET $2
```
Note: uses `display_name` (not `name`); alias `granted_org` (not `go_org`); includes `g.org_id`.

**`ApproveGrantRequest` — new signature (adds client_id + ownerOrgID binding, returns data for email):**
```go
ApproveGrantRequest(ctx context.Context, requestID uuid.UUID, clientID string, ownerOrgID, resolvedBy uuid.UUID) (*GrantRequest, error)
```
```sql
UPDATE client_access_requests
   SET status='approved', resolved_at=NOW(), resolved_by=$4
 WHERE id=$1 AND client_id=$2 AND owner_org_id=$3 AND status='pending'
 RETURNING id, client_id, requester_org_id, owner_org_id, requested_by, status, requested_at
```
Then INSERT into `client_org_grants` in same TX.

**`DenyGrantRequest` — new signature (same security fix + RETURNING for email):**
```go
DenyGrantRequest(ctx context.Context, requestID uuid.UUID, clientID string, ownerOrgID, resolvedBy uuid.UUID) (*GrantRequest, error)
```
```sql
UPDATE client_access_requests
   SET status='denied', resolved_at=NOW(), resolved_by=$4
 WHERE id=$1 AND client_id=$2 AND owner_org_id=$3 AND status='pending'
 RETURNING id, client_id, requester_org_id, owner_org_id, requested_by, status, requested_at
```
```go
n, err := res.RowsAffected()  // was ignoring error; fix this
if err != nil { return err }
```

**`ListOrgAdmins` — corrected SQL (table name fix + removed_at guard):**
```sql
SELECT u.email FROM users u
JOIN org_memberships m ON m.user_id = u.id
WHERE m.org_id = $1 AND m.role IN ('owner', 'admin')
  AND m.removed_at IS NULL
  AND u.disabled_at IS NULL AND u.deleted_at IS NULL
```

**`ListAllGrantRequestsForClient` — corrected SQL (history query with LIMIT and full shape):**
```sql
SELECT r.id, r.client_id, COALESCE(c.name,''), r.requester_org_id,
       COALESCE(ro.slug,''), COALESCE(ro.display_name,''),
       r.owner_org_id, r.requested_by, r.status, r.requested_at
  FROM client_access_requests r
  LEFT JOIN oauth2_clients c ON c.id = r.client_id
  LEFT JOIN organizations ro ON ro.id = r.requester_org_id
 WHERE r.client_id = $1
 ORDER BY r.requested_at DESC
 LIMIT 50
```
Scans into same `GrantRequest` struct as `ListGrantRequestsForClient`.

**`AdminGrantRow` struct:**
```go
type AdminGrantRow struct {
    ClientID       string
    ClientName     string
    OwnerOrgName   string
    GrantedOrgName string
    GrantedOrgID   uuid.UUID  // needed for revoke form action
    GrantedAt      time.Time
}
```

**`/admin/grants` access control:** Use `requireSuperAdmin` (not `requireAdmin`) — grant topology is sensitive.

**Admin `RevokeGrant` handler must do JTI blocklisting:** Mirror `RevokeClientAccess` Redis scan pattern:
```go
pattern := "oauth:user-org-tokens:*:" + revokedOrgID.String()
keys, _ := h.rdb.Keys(r.Context(), pattern).Result()
for _, key := range keys {
    jtis, _ := h.rdb.SMembers(r.Context(), key).Result()
    for _, jti := range jtis {
        _ = h.revocStore.RevokeJTI(r.Context(), jti, 2*time.Hour)
    }
}
```
Note: admin `RevokeGrant` handler needs `rdb` and `revocStore` — `AdminHandler` already has `rdb`. Add `revocStore *redis.RevocationStore` to `AdminHandler`.

#### ENG DUAL VOICES — CONSENSUS TABLE

```
ENG DUAL VOICES — CONSENSUS TABLE:
═══════════════════════════════════════════════════════════════════════
  Dimension                             Claude   Codex    Consensus
  ─────────────────────────────────────── ─────── ──────── ──────────
  1. Architecture sound?                  No      No       CONFIRMED NOT (fixes above)
  2. Test coverage sufficient?            No      No       CONFIRMED MISSING
  3. Performance risks?                   No      No       CONFIRMED gap (migration 00010)
  4. Security threats covered?            No      No       CONFIRMED CRITICAL (fixed)
  5. Error paths handled?                 Partial Partial  CONFIRMED gaps (fixed)
  6. Deployment risk?                     Accept  Accept   CONFIRMED (with fixes applied)
═══════════════════════════════════════════════════════════════════════
```

#### Migration 00010 (new)

```sql
-- +goose Up
CREATE INDEX idx_car_client_all ON client_access_requests(client_id, requested_at DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_car_client_all;
```

#### Test Coverage Gaps

| Path | Type | Verify |
|------|------|--------|
| `UpdateOrgClient` — non-owner org cannot edit multi-org client | Unit (store) | 0 rows affected → ErrClientNotFound |
| `UpdateOrgClient` — empty/invalid name and URI | Unit (handler) | Redirect with error |
| `ApproveGrantRequest` — concurrent double-approve | Unit (store) | Second call → ErrGrantRequestNotPending |
| `DenyGrantRequest` — requestID belongs to different client | Unit (store) | 0 rows → ErrGrantRequestNotPending |
| `ListAllGrantRequestsForClient` — non-owner org gets 403 from handler | Integration (handler) | 403 |
| `ListOrgAdmins` — org with no active admins | Unit (store) | Empty slice, no panic |
| Admin `RevokeGrant` — non-superadmin gets 403 | Integration (handler) | 403 |
| Admin `RevokeGrant` — JTI blocklisting fires | Integration (handler) | Redis KEYS + RevokeJTI called |
| `ClientRequestHistory` — non-owner org gets 403 | Integration (handler) | 403 |
| Edit client — redirect anchor includes client ID | Integration (handler) | Redirect includes `#client-{id}` |

#### Handler Signature Change: `OrgHandler`

`ApproveGrantRequest` and `DenyGrantRequest` handlers pass `clientID` and `org.ID` (the owner org from slug) to the store. These values are already in scope from the existing handler code; only the store call changes.

#### `AdminHandler` Change

Add `revocStore *redis.RevocationStore` field. Wire in `NewAdminHandler` and in `router.go` where `AdminHandler` is constructed.

---

## Decision Audit Trail

| # | Phase | Decision | Classification | Principle | Rationale | Rejected |
|---|-------|----------|----------------|-----------|-----------|---------|
| 1 | CEO | Admin revoke sends notification email (with optional reason) | USER CHOICE (D1) | User | User chose B at premise gate | Silent revoke |
| 2 | CEO | Per-org scopes remain deferred | Auto | P3 | Complex schema + consent changes; separate plan | Immediate |
| 3 | CEO | `ListOrgAdmins` zero-admin guard (skip send) | Mechanical | P1 | Empty recipient list should be a no-op not an error | Panic |
| 4 | Design | Multi-org toggle → read-only label (not disabled field) | Mechanical | P5 | Disabled fields confuse users; read-only text is clearer | Keep checkbox |
| 5 | Design | Edit form validation errors specified | Mechanical | P1 | Without these, implementer invents inconsistent strings | Leave vague |
| 6 | Design | Request history column order explicit | Mechanical | P5 | Prevents inconsistent table layouts | Leave to implementer |
| 7 | Design | Empty states added | Mechanical | P1 | Zero-row pages without empty state look broken | Ignore |
| 8 | Design | `AdminGrantRow` needs `GrantedOrgID` | Mechanical | P1 | Revoke route needs `:orgID` in URL | Extra query per row |
| 9 | Eng | Remove `updated_at` from UpdateOrgClient SQL | Mechanical | P1 | Column doesn't exist — runtime failure | Add migration |
| 10 | Eng | Fix `display_name` in ListAllClientOrgGrants | Mechanical | P1 | `organizations.name` doesn't exist — runtime failure | Ignore |
| 11 | Eng | Bind `client_id + owner_org_id` in Approve/Deny store methods | Mechanical | P1 (security) | Prevents request hijack across clients | Trust UUID |
| 12 | Eng | Return `*GrantRequest` from Approve/Deny for email data | Mechanical | P1 | Without RETURNING, handler needs extra query (race) | Pre-fetch |
| 13 | Eng | Fix `org_memberships` typo in ListOrgAdmins SQL | Mechanical | P1 | Wrong table name — compile error at runtime | Ignore |
| 14 | Eng | Admin RevokeGrant must do JTI blocklisting | Mechanical | P1 (security) | `RevokeOrgAccess` doc says caller is responsible | Accept JWT expiry |
| 15 | Eng | `/admin/grants` uses `requireSuperAdmin` | Mechanical | P1 | Grant topology is sensitive; readonly/org_admin shouldn't see | `requireAdmin` |
| 16 | Eng | `DenyGrantRequest` `RowsAffected()` error checked | Mechanical | P5 | Existing inconsistency; all other methods check it | Ignore |
| 17 | Eng | `ListAllGrantRequestsForClient` LIMIT 50 + index migration | Mechanical | P1 | Unbounded scan on partial-indexed table | Accept seq scan |
| 18 | Eng | History query matches GrantRequest struct scanner shape | Mechanical | P5 | Different scan shape = runtime panic | New struct |
| 19 | Eng | `UpdateOrgClient` WHERE uses `owner_org_id` only (not OR `org_id`) | Mechanical | P5 | Simpler, correct, no privilege confusion | Keep OR clause |

---

## Plan Status: APPROVED ✓

**Approved:** 2026-05-25 | **Reviewer:** /autoplan pipeline (3 phases, dual voices each)

### Cross-Phase Themes

**Theme: Wrong column names** — `updated_at` (doesn't exist on `oauth2_clients`) and `name` (should be `display_name` on `organizations`) flagged by Codex in Eng phase. Both are runtime failures. **Fixed in plan above.**

**Theme: Approve/Deny request hijack** — flagged by both Codex and Claude subagent in Eng phase. `DenyGrantRequest`/`ApproveGrantRequest` must bind `client_id` and `owner_org_id` in the WHERE clause. **Fixed in plan above.**

**Theme: JTI blocklisting gap** — Admin revoke must mirror `RevokeClientAccess` Redis scan. **Fixed in plan above.**

### Deferred to TODOS.md

- Per-org scopes (strategic risk acknowledged by both CEO voices)
- Multi-org toggle admin-only migration escape hatch
- Webhook/DLQ delivery for security events (secret rotated)
- Delivery observability / retry for failed emails
- Single-org direct-grant technical debt (`org_id != NULL` grants not enforced at authorize time)
