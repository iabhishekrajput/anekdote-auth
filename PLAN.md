<!-- /autoplan restore point: /Users/abhishek/.gstack/projects/iabhishekrajput-anekdote-auth/main-autoplan-restore-20260521-205946.md -->
# Plan: Implement TODOS.md — Audit Log, DB Admin Roles, OAuth2 Integration Test, Admin Pagination

Branch: main
Status: APPROVED — ready for implementation
Date: 2026-05-21

## Summary

Four items from TODOS.md implemented together. CEO review identified real design gaps in the audit log schema and DB admin roles bootstrapping — these are incorporated as required fixes before implementation. User confirmed: implement all 4.

## Scope (updated with CEO fixes)

### 1. Audit Log for Admin Actions

**Schema (corrected from CEO review):**
```sql
CREATE TABLE admin_audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id    UUID REFERENCES users(id) ON DELETE SET NULL,  -- nullable: admin_id=NULL if user deleted
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    ip_address  TEXT,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX admin_audit_log_created_at_idx ON admin_audit_log (created_at DESC);
```

**Action type constants (corrected from Eng Review):**
Define `type AuditAction string` with constants:
```go
const (
    AuditActionDisableUser     AuditAction = "disable_user"
    AuditActionEnableUser      AuditAction = "enable_user"
    AuditActionDeleteClient    AuditAction = "delete_client"
    AuditActionRemoveOrgMember AuditAction = "remove_org_member"
    AuditActionPromoteAdmin    AuditAction = "promote_admin"
    AuditActionDemoteAdmin     AuditAction = "demote_admin"
)
```

**AuditStore interface (corrected from Eng Review):**
```go
type AuditStore interface {
    Log(ctx context.Context, adminID uuid.UUID, action AuditAction, targetType, targetID string, ipAddr, ua string) error
    ListAudit(ctx context.Context, limit, offset int) ([]*AuditLogEntry, error)
    CountAudit(ctx context.Context) (int, error)
}
```

**Failure behavior (corrected from CEO review):**
- Audit writes are best-effort: log error to `slog.Error`, but never fail the admin action because of an audit write failure.
- No transaction coupling: admin action and audit log are independent writes.
- Audit goroutine must use `context.WithoutCancel(ctx)` — request context is cancelled after response is sent (Eng Review H3).

**Implementation:**
- Log in: `DisableUser`, `EnableUser`, `DeleteClient`, `RemoveOrgMember`, `PromoteAdmin`, `DemoteAdmin`
- New route: `GET /admin/audit` — paginated list, most recent first
- IP extracted via: check `X-Forwarded-For` header first, then `X-Real-IP`, then `r.RemoteAddr` (strip port)
- User-Agent from `r.Header.Get("User-Agent")`

### 2. DB-Backed Admin Roles (replace ADMIN_EMAILS)

**Required fixes from CEO review:**

**Bootstrapping (corrected):**
- On startup, `cmd/auth-server/main.go` calls `userStore.SeedAdminEmails(ctx, cfg.AdminEmails)` — sets `is_admin=true` for any user whose email is in ADMIN_EMAILS.
- If seed fails: log the error, fall back to checking ADMIN_EMAILS in middleware (not crash, not silent lockout).
- Once `is_admin` is set via the UI, ADMIN_EMAILS is no longer the source of truth. The env var is only used for seeding.

**Last admin invariant (corrected from Eng Review H1):**
- `userStore.SetAdmin(ctx, id, false)` must use a **transaction with `SELECT COUNT(*) FROM users WHERE is_admin=true FOR UPDATE`** — plain count-then-update is a TOCTOU race (two concurrent demotions each see count=2, both proceed, leaving 0 admins). The FOR UPDATE row-level lock serializes concurrent demotion requests.
- Return `ErrLastAdmin` sentinel if count ≤ 1.
- Admin detail page: demote button disabled if user is the only admin.

**GetByID must scan is_admin (corrected from Eng Review C1):**
- `GetByID` SELECT must explicitly list `is_admin` in the column list and `Scan` must include `&u.IsAdmin`.
- Without this fix, every call to `GetByID` returns `IsAdmin: false` regardless of DB state — `RequireAdmin`, `InjectAdminStatus`, and promote/demote are all silently broken.

**SeedAdminEmails fallback (corrected from Eng Review C2):**
- After seeding, middleware checks `user.IsAdmin` only (DB is source of truth).
- If `SeedAdminEmails` fails at startup: `main.go` stores `seedFailed bool = true`, passes it to `NewAdminHandler`. Middleware logic becomes: `user.IsAdmin || (seedFailed && isAdminEmail(cfg.AdminEmails, user.Email))`.
- This keeps ADMIN_EMAILS as a genuine fallback only when the DB seed couldn't run, not as a parallel check that makes the DB column irrelevant.

**Migration rollback:**
- `-- +goose Down`: `ALTER TABLE users DROP COLUMN IF EXISTS is_admin` — safe, loses is_admin state, ADMIN_EMAILS becomes source of truth again.

**Schema:**
```sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;
```

**Implementation:**
- `RequireAdmin`: check `user.IsAdmin` (already loads user via GetByID — one less env var check)
- `InjectAdminStatus`: check `user.IsAdmin`
- Admin UI: promote/demote button on user detail page, disabled for last admin

### 3. Integration Test for userAuthorizeHandler

**Scope (corrected from CEO review):**
- Only test the **org-denial path** (`return "", nil` after rendering OAuthAccessDeniedPage) — the consent-render path is already covered by `TestAuthorize_LoggedIn_Consent`.
- Mock setup: `oauth2_test.go` uses `setupOAuth2MockedHandler` with `sqlmock` expectations for `GetMembership`.

**Shape (corrected from Eng Review H5):**

Must use a new setup helper — `setupOAuth2MockedHandler` passes `orgStore=nil`, which causes `h.orgStore == nil` to short-circuit the org check, making the denial path structurally unreachable:

```go
func setupOAuth2HandlerWithOrgStore(t *testing.T, orgStore oauth2OrgStore) *OAuth2Handler { ... }

func TestAuthorize_OrgClient_NonMember_RendersAccessDenied(t *testing.T) {
    // 1. Create mock orgStore that returns ErrNoMembership for GetMembership
    // 2. Use setupOAuth2HandlerWithOrgStore(t, mockOrgStore)
    // 3. Seed session for user, client with OrgID set
    // 4. GET /authorize?client_id=...&response_type=code
    // Assert: status 200, body contains "Access denied", no Location header
}
```

### 4. Pagination on Admin List Pages

**Design note from CEO review:** TODOS specified cursor-based pagination; offset/limit is simpler and acceptable for the current scale (admin panel, unlikely to exceed 10k rows). Noted: replace with cursor pagination if any list hits 10k+ rows.

**Shape:**
- `ClientStore.ListAll(ctx, limit, offset int)` — already has this signature
- `OrgStore.ListAll(ctx, limit, offset int)` — add limit/offset
- `AdminClientList(csrfToken string, clients []*postgres.ClientListItem, page, total, pageSize int, errMsg, successMsg string)`
- `AdminOrgList(csrfToken string, orgs []*postgres.OrgListItem, page, total, pageSize int, errMsg, successMsg string)`
- Reuse same pagination nav component pattern as `adminUserListBody`

## Files Touched (estimate)

| File | Change |
|------|--------|
| `migrations/00009_admin_roles.sql` | NEW — is_admin column |
| `migrations/00010_audit_log.sql` | NEW — admin_audit_log table |
| `internal/config/config.go` | Modified — AdminEmails available for seeding |
| `internal/models/user.go` | Modified — IsAdmin bool |
| `internal/store/postgres/user_store.go` | Modified — IsAdmin in GetByID, SetAdmin, SeedAdminEmails, CountAdmins |
| `internal/middleware/auth.go` | Modified — check IsAdmin instead of ADMIN_EMAILS |
| `internal/handlers/admin.go` | Modified — audit log writes, pagination, promote/demote |
| `internal/store/postgres/client_store.go` | Modified — ListAll limit/offset |
| `internal/store/postgres/org_store.go` | Modified — ListAll limit/offset |
| `internal/store/postgres/audit_store.go` | NEW — AuditStore |
| `web/ui/admin.templ` | Modified — audit log page, promote/demote button |
| `web/ui/admin_clients.templ` | Modified — pagination |
| `web/ui/admin_orgs.templ` | Modified — pagination |
| `internal/server/router.go` | Modified — /admin/audit route + POST /admin/users/:id/promote + POST /admin/users/:id/demote |
| `cmd/auth-server/main.go` | Modified — SeedAdminEmails on startup |
| `internal/handlers/oauth2_test.go` | Modified — org-denial integration test |

## CEO Review Summary

| Item | Finding | Resolution |
|------|---------|------------|
| Audit log schema | Missing IP/UA fields; forensics-useless without them | Added `ip_address`, `user_agent` to schema |
| Audit write failure | Undefined — could fail action or silently succeed | Best-effort: log slog.Error, never fail the admin action |
| DB roles bootstrapping | Seed failure → zero admins, no error, panel inaccessible | Fallback to ADMIN_EMAILS if seed fails; log error |
| Last admin invariant | No protection against demoting the last admin | ErrLastAdmin sentinel + UI disable |
| Pagination design | Offset vs cursor — TODOS said cursor | Offset acceptable at current scale; cursor TODO for 10k+ |
| Item 3 scope overlap | Consent-render path already tested | Test only org-denial path |

## Decision Audit Trail

| # | Phase | Decision | Classification | Principle | Rationale | Rejected |
|---|-------|----------|----------------|-----------|-----------|---------|
| 1 | CEO | Implement all 4 vs. test only | User Challenge | User | CEO recommended test-only; user chose all 4 | Test only |
| 2 | CEO | Audit log schema: add IP/UA | Genuine Gap | P1 | Without IP/UA, audit log is forensics-useless | Skip fields |
| 3 | CEO | Audit write failure: best-effort | Genuine Gap | P5 | Explicit: log error, never fail the action | Transactional |
| 4 | CEO | DB roles bootstrapping: fallback to ADMIN_EMAILS | Genuine Gap | P1 | Seed failure must not lock out all admins | Crash on seed fail |
| 5 | CEO | Last admin invariant: ErrLastAdmin + UI disable | Genuine Gap | P1 | No recovery without direct DB access | No protection |
| 6 | CEO | Pagination: offset/limit at current scale | Taste | P5 | Admin panel unlikely to hit 10k rows anytime soon | Cursor now |
| 7 | CEO | OAuth2 test scope: org-denial only | Mechanical | P4 | Consent-render path already covered by existing test | Duplicate test |

---

## CEO Review (autoplan — 2026-05-21)

Mode: SELECTIVE EXPANSION | Claude subagent only (Codex unavailable)

### Step 0B: Existing Code Leverage Map

| Sub-problem | Existing code |
|---|---|
| Audit log writes | `admin.go` action handlers (DisableUser, EnableUser, DeleteClient, RemoveOrgMember) — just add `auditStore.Log(...)` call |
| Audit log UI | `adminUserListBody` pattern in `admin_users.templ` — reuse for audit log table |
| DB admin check | `RequireAdmin` + `InjectAdminStatus` in `auth.go` — already calls `GetByID`, just read `user.IsAdmin` |
| Admin seed | `cmd/auth-server/main.go` startup wiring — add `SeedAdminEmails` call after store init |
| Pagination | `UserList` in `admin.go` already paged (page/pageSize/offset); `adminUserListBody` has pagination nav — duplicate for clients/orgs |
| OAuth2 test | `setupOAuth2MockedHandler` in `oauth2_test.go`; `TestAuthorize_LoggedIn_Consent` as pattern |

### Step 0C: Dream State Delta

```
CURRENT (main) → THIS PLAN → 12-MONTH IDEAL
  No audit trail       +Admin audit log (IP, UA)   +Compliance-ready audit (export, retention)
  ADMIN_EMAILS env     +DB-backed is_admin          +Role gradations (read/write admin)
  "" nil untested      +Org-denial integration test +Full OAuth2 flow integration suite
  Unbound list pages   +50-row pagination           +Cursor pagination, search/filter
```

### Sections 1-10 Findings

#### Section 1: Architecture — OK with corrections

Clean extension of existing patterns:
- `AuditStore` joins `UserStore`, `OrgStore`, `ClientStore` in the store layer
- `SeedAdminEmails` runs at startup after store init — one new wiring line in `main.go`
- Pagination on ClientList/OrgList: template signature change only, same query pattern

Corrections already incorporated in plan:
- Bootstrapping fallback ✓
- Last admin invariant ✓
- Best-effort audit writes ✓

#### Section 2: Error & Rescue Map

| Error Scenario | Handler | User Sees | Verdict |
|---|---|---|---|
| Audit log write fails | `DisableUser` etc. | Admin action still succeeds, error logged | ✓ (best-effort) |
| SeedAdminEmails fails on startup | `main.go` | Log error, fall back to ADMIN_EMAILS | ✓ |
| SetAdmin demotes last admin | Admin UI | ErrLastAdmin → "Cannot demote the last admin" | ✓ |
| OrgStore.ListAll with limit/offset | `OrgList` | If DB error: same dbErr banner pattern | ✓ |

#### Section 3: Security — OK

CSRF: all new POST routes behind nosurf ✓
Privilege escalation: promote/demote is a POST behind `RequireAdmin` ✓
Last admin invariant protects against self-lockout ✓

#### Section 4: Performance

Audit log inserts are on admin cold paths (rare actions) — no performance concern ✓
Pagination reduces result set on list pages ✓
`SeedAdminEmails` runs once at startup, not per-request ✓

### NOT in scope (confirmed deferred to TODOS.md)

- Cursor-based pagination (replace offset/limit when any list hits 10k+ rows)
- Role gradations beyond is_admin (read-only admin, etc.)
- Audit log export / retention policy
- Full OAuth2 flow integration suite

### What Already Exists (leveraged)

- `adminUserListBody` pagination nav → reused for clients/orgs
- `UserStore.GetByID` → extended to return IsAdmin
- `RequireAdmin` + `InjectAdminStatus` → just read `user.IsAdmin` instead of ADMIN_EMAILS
- `setupOAuth2MockedHandler` test pattern → used for new OAuth2 test

### Error & Rescue Registry

| Error | Location | User Experience | Status |
|-------|----------|-----------------|--------|
| Audit write fails | Any admin action handler | Action succeeds; error in slog | ✓ best-effort |
| Seed fails on startup | main.go | Falls back to ADMIN_EMAILS; logs error | ✓ |
| Demote last admin | SetAdmin | ErrLastAdmin redirect | ✓ |
| OrgList DB error | OrgList handler | dbErr banner (same pattern as Dashboard) | ✓ |

### Failure Modes Registry

| Failure | Impact | Mitigation | Status |
|---------|--------|------------|--------|
| Seed race (2 servers start simultaneously) | Double-seed is_admin=true for same users | Idempotent UPDATE — no problem | ✓ |
| Admin demotes self while is_admin=true elsewhere | Panel still accessible via other admin | Last-admin check | ✓ |
| go-oauth2 upgrade changes "return nil" contract | Denial page overwritten | New integration test | ✓ |

### CEO Completion Summary

| Dimension | Score | Notes |
|-----------|-------|-------|
| Problem framing | 7/10 | Items are genuine gaps, timing is early |
| Premise validity | 7/10 | CEO fixes incorporated; bootstrapping resolved |
| Scope calibration | 6/10 | All 4 in one plan is ambitious; test is standalone |
| Security | 8/10 | Last-admin invariant, IP/UA audit fields |
| Test coverage | 7/10 | OAuth2 test is the key addition |
| 6-month trajectory | 8/10 | Solid with the corrections applied |

**Overall: APPROVED with CEO-required fixes incorporated into plan.**

**Phase 1 complete.** Claude subagent: 7 findings (5 genuine gaps, 1 taste, 1 scope overlap). Codex: unavailable [subagent-only]. Passing to Phase 2 (Design Review — UI scope detected).

---

---

## Design Review (autoplan — 2026-05-21)

Claude subagent only (Codex unavailable)

### Design Litmus Scorecard

| Dimension | Score | Notes |
|-----------|-------|-------|
| Information hierarchy | 5/10 | Audit log columns unspecified; promote/demote placed with disable/enable |
| Missing interaction states | 5/10 | No error state for /admin/audit; no disabled-button spec |
| User journey arc | 5/10 | /admin/audit has no nav link; audit rows don't link to entities |
| Specificity | 5/10 | Column names, copy, confirm text all unspecified |
| Consistency | 7/10 | Follows existing AdminLayout patterns; subtitle-count bug identified |

### Design Findings (auto-decided)

#### High (required before implementation)

**D1 — Audit log columns unspecified — FIX**
5-column table: Timestamp (monospace-xs, DESC) | Admin (email, linked) | Action (badge) | Target (display name, linked) | IP (monospace-xs, muted). User-Agent stored but not shown.

Action badge spec: `disable_user` → red | `enable_user` → emerald | `delete_client` → red | `remove_org_member` → amber | `promote_admin` → violet | `demote_admin` → amber.

**D2 — Promote/demote must be separate section — FIX**
"Account actions" (disable/enable) stays. New "Admin access" section below it with: `is_admin` badge in the profile key-value card + promote/demote form. `POST /admin/users/<id>/promote` and `POST /admin/users/<id>/demote` — two endpoints.

**D3 — No error state for /admin/audit — FIX**
`dbErr` amber banner identical to Dashboard: "Could not load audit log — data may be incomplete."

**D6 — /admin/audit missing nav link — FIX**
Add "Audit" nav item to `AdminLayout` in `admin.templ`. Order: Dashboard | Users | Clients | Orgs | Audit.

#### Medium (incorporate during implementation)

**D4 — Disabled demote button**: `opacity-40 cursor-not-allowed` + `title="Cannot remove the last admin"`

**D5 — Post-promote/demote redirect**: `?success=Admin+access+granted` / `?success=Admin+access+removed` → renders via existing `AlertContainer`

**D7 — Audit rows link to entities**: resolve `target_type+target_id` → display name + link to `/admin/users/<id>`, `/admin/clients/<id>`, or `/admin/orgs/<slug>`. If target deleted: raw ID in muted monospace + "(deleted)".

**D8 — Confirm text must include email**: `"Grant admin access to {email}? They will have full access to this admin panel."` and `"Remove admin access from {email}?"`

**D9 — Subtitle uses total not slice length**: after pagination, subtitle must use `intToStr(total)`, not `intToStr(len(slice))`.

**D10 — promote_admin / demote_admin must be audited**: these two new actions must be listed in `AuditStore.Log` call spec — currently the plan only lists disable/enable/delete/remove.

#### Low (auto-decided)

**D11 — User-Agent**: store in schema, do not display in audit table. ✓ confirmed.
**D12 — No filter/search** (TASTE): add TODOS note for "filter audit log by admin/date/action".
**D13 — CSRF in list templates**: pagination-only list templates don't need csrfToken unless an action is added at list level. Mechanical — obvious during implementation.

### Design Audit Trail

| # | Phase | Decision | Classification | Principle | Rationale | Rejected |
|---|-------|----------|----------------|-----------|-----------|---------|
| 8 | Design | Audit log columns | Genuine Gap | P1 | 5-column spec required; "same as users" is not a spec | Leave to implementer |
| 9 | Design | Promote/demote section placement | Genuine Gap | P1 | Mixing privilege escalation with disable/enable causes mis-click risk | Same section |
| 10 | Design | Error state for /admin/audit | Genuine Gap | P1 | Forensics tool showing empty table on DB error is misleading | Omit |
| 11 | Design | Nav link for /admin/audit | Genuine Gap | P1 | Unreachable without URL-typing is not shipped | No nav change |
| 12 | Design | Disabled demote button appearance | Genuine Gap | P5 | Explicit over invisible | Omit button |
| 13 | Design | Promote/demote redirect/success flow | Genuine Gap | P5 | Reuse existing ?success= pattern | Custom flash |
| 14 | Design | Audit rows entity links | Genuine Gap | P3 | Admin forensics requires 1-click to affected entity | Raw IDs only |
| 15 | Design | Confirm text specificity | Genuine Gap | P5 | Ambiguous dialogs cause wrong-target clicks | Generic confirm |
| 16 | Design | Subtitle total vs slice count | Genuine Gap | P5 | Showing page count as total is factually wrong | No change |
| 17 | Design | promote/demote in audit spec | Genuine Gap | P1 | Privilege changes are the most important audit events | Omit |
| 18 | Design | Filter/search on audit log | Taste | P3 | Low-volume v1 is fine without filtering | Implement now |
| 19 | Design | UA in table | Mechanical | — | Store it, don't show it | Display UA |

**Phase 2 complete.** Claude subagent: 13 findings (10 genuine gaps, 1 taste, 2 mechanical). Codex: unavailable. Passing to Phase 3 (Eng Review).

---

## Eng Review (autoplan — 2026-05-21)

Claude subagent only (Codex unavailable)

### Architecture Map (before → after)

```
BEFORE                          AFTER
─────────────────────────────   ──────────────────────────────────────
UserStore                        UserStore (+ IsAdmin field, SetAdmin,
  GetByID → models.User            SeedAdminEmails, CountAdmins)
  (no is_admin column)
                                 AuditStore (NEW)
                                   Log / ListAudit / CountAudit
RequireAdmin                     RequireAdmin → checks user.IsAdmin
  reads ADMIN_EMAILS env           (+ seedFailed bool fallback)
InjectAdminStatus                InjectAdminStatus → checks user.IsAdmin
  reads ADMIN_EMAILS env
                                 router.go (NEW routes)
admin.go handlers                  POST /admin/users/:id/promote
  no audit writes                  POST /admin/users/:id/demote
  no promote/demote                GET  /admin/audit
                                 admin.go
                                   audit writes (context.WithoutCancel)
                                   promote/demote handlers
```

### Test Coverage Map (before → after)

```
BEFORE                                 AFTER
─────────────────────────────────────  ──────────────────────────────────────
TestAuthorize_LoggedIn_Consent ✓       TestAuthorize_LoggedIn_Consent ✓ (unchanged)
(org-denial path) ✗                    TestAuthorize_OrgClient_NonMember_RendersAccessDenied ✓ (NEW)
SetAdmin/ErrLastAdmin ✗                (unit: ErrLastAdmin sentinel) ✓ (NEW)
AuditStore.Log ✗                       (handler: audit write called) ✓ (NEW)
```

### Findings

#### Critical — must fix, implementation blocked until resolved

**C1 — GetByID doesn't scan is_admin — FIX**
`user_store.go`'s `GetByID` SELECT column list and `Scan` call do not include `is_admin`. After the `ALTER TABLE` migration, the column exists in the DB but is never read into `models.User.IsAdmin`. Every downstream caller (`RequireAdmin`, `InjectAdminStatus`, promote/demote) gets `IsAdmin: false` regardless of DB state — **silently broken**.
Fix: add `is_admin` to SELECT list and `&u.IsAdmin` to Scan.

**C2 — SeedAdminEmails fallback is architecturally incoherent — FIX**
Plan says "check `user.IsAdmin`" AND "fall back to ADMIN_EMAILS if seed fails" — but if the middleware always checks ADMIN_EMAILS regardless of seed outcome, the `is_admin` DB column becomes irrelevant for seeded admins. The fallback must be conditional.
Fix: `main.go` captures `seedFailed bool`. Middleware: `user.IsAdmin || (seedFailed && isAdminEmail(cfg.AdminEmails, user.Email))` — ADMIN_EMAILS is only consulted when the DB seed definitively failed at startup.

#### High — required before shipping

**H1 — SetAdmin TOCTOU race — FIX**
`SetAdmin(false)` pattern of `SELECT COUNT(*)` then `UPDATE` is a race: two concurrent demotion requests can both read count=2, both proceed, leaving 0 admins.
Fix: wrap in a transaction with `SELECT COUNT(*) FROM users WHERE is_admin = true FOR UPDATE`, then conditionally `UPDATE users SET is_admin = $2 WHERE id = $1`.

**H2 — admin_id NOT NULL contradicts ON DELETE SET NULL — FIX**
Schema has `admin_id UUID NOT NULL REFERENCES users(id)` but ON DELETE SET NULL requires the column to be nullable — PostgreSQL rejects this at DDL time.
Fix: `admin_id UUID REFERENCES users(id) ON DELETE SET NULL` (no NOT NULL constraint). Already incorporated in scope above.

**H3 — Audit context cancelled after response — FIX**
HTTP handler audit writes use `go auditStore.Log(ctx, ...)`. The request context `ctx` is cancelled as soon as the HTTP response is sent — the goroutine's DB write is then immediately aborted.
Fix: `go auditStore.Log(context.WithoutCancel(ctx), ...)`. Already incorporated in scope above.

**H4 — Promote/demote routes missing from Files Touched — FIX**
`POST /admin/users/:id/promote` and `POST /admin/users/:id/demote` are new routes. `internal/server/router.go` was absent from the files list.
Fix: added to Files Touched. Already incorporated above.

**H5 — OAuth2 test helper passes orgStore=nil — FIX**
`setupOAuth2MockedHandler` wires `NewOAuth2Handler(..., nil)`. With `h.orgStore == nil`, the entire org membership check block is skipped — `TestAuthorize_OrgClient_NonMember_RendersAccessDenied` can never reach the denial path.
Fix: new `setupOAuth2HandlerWithOrgStore(t, orgStore)` helper. Already incorporated in scope above.

#### Medium — incorporate during implementation

**M1 — AuditAction is untyped string — FIX**
Callers writing `"disable_user"` bare strings will compile even with typos. Define `type AuditAction string` with named constants. Already incorporated in scope above.

**M2 — IP extraction misses reverse-proxy headers — FIX**
`r.RemoteAddr` returns the TCP peer IP — behind a load balancer this is the LB's IP. Check `X-Forwarded-For` (first element) then `X-Real-IP` then fall back to `r.RemoteAddr` (with port stripped). Already incorporated in scope above.

**M3 — Index on admin_audit_log(created_at DESC) — FIX**
`/admin/audit` orders by `created_at DESC` with limit/offset. Without an index this is a full table scan.
Fix: `CREATE INDEX admin_audit_log_created_at_idx ON admin_audit_log (created_at DESC)`. Already incorporated in schema above.

**M4 — AuditStore only specifies Log — FIX**
`/admin/audit` page needs `ListAudit(ctx, limit, offset)` and `CountAudit(ctx)` for pagination — equivalent to what UserStore provides for `/admin/users`. Plan only mentioned `Log`.
Fix: full interface specified in scope above.

**M5 — GetByID Scan is positional — ACCEPT**
If `SELECT *` is used and a new column is added between existing ones, positional scan breaks silently. Recommendation: use explicit column list in SELECT and matching Scan order.
Auto-decided: FIX — use named column list in SELECT to match Scan. Low effort, prevents future column-reorder bugs.

**M6 — SeedAdminEmails should log seed count — ACCEPT**
On startup, `SeedAdminEmails` should `slog.Info("admin seed complete", "seeded", n)` so operators know the seeding outcome without querying the DB.
Auto-decided: FIX — low effort, high operational value.

#### Low — accept as-is or note in TODOS

**L1 — AuditStore.Log should return error — FIX**
Even though callers ignore it (best-effort), returning `error` enables unit tests to assert the write was attempted and mock behavior. Auto-decided: FIX.

**L2 — SetAdmin return value — ACCEPT**
`SetAdmin(ctx, id, bool) error` is sufficient. Callers that need new state can call `GetByID` after. Low payoff. Auto-decided: SKIP.

**L3 — Audit log export in TODOS — NOTE**
CSV/JSON download for compliance (e.g., SOC 2 evidence) is a legitimate future feature. Auto-decided: add to TODOS.md note: "filter audit log by date/admin/action; export CSV."

### Eng Scorecard

| Dimension | Score | Notes |
|-----------|-------|-------|
| Data model correctness | 4→8/10 | C1/C2/H2 were silent failures; all fixed |
| Concurrency safety | 5→8/10 | H1 FOR UPDATE transaction; H3 WithoutCancel |
| Test coverage | 4→7/10 | H5 new helper enables the org-denial path |
| Interface completeness | 6→9/10 | M1 typed constants; M4 full AuditStore; M5 named SELECT |
| Observability | 5→8/10 | M2 proxy IP; M6 seed logging; L1 error return |
| Files touched accuracy | 6→9/10 | H4 router.go added |

**Overall: APPROVED with eng-required fixes incorporated into plan. Implementation can begin.**

### Eng Audit Trail

| # | Phase | Decision | Classification | Principle | Rationale | Rejected |
|---|-------|----------|----------------|-----------|-----------|---------|
| 20 | Eng | C1: GetByID scan is_admin | Genuine Gap | P1 | Silent wrong value in every admin check | Accept broken state |
| 21 | Eng | C2: Fallback is conditional on seedFailed | Genuine Gap | P1 | Unconditional dual-check makes DB column irrelevant | Always check ADMIN_EMAILS |
| 22 | Eng | H1: FOR UPDATE transaction in SetAdmin | Genuine Gap | P1 | TOCTOU race leaves 0 admins if concurrent demote | Count-then-update |
| 23 | Eng | H2: admin_id nullable for ON DELETE SET NULL | Genuine Gap | P1 | PostgreSQL rejects NOT NULL + ON DELETE SET NULL | Keep NOT NULL |
| 24 | Eng | H3: context.WithoutCancel for audit goroutine | Genuine Gap | P1 | Request ctx cancelled before goroutine DB write | Request ctx |
| 25 | Eng | H4: router.go in Files Touched | Mechanical | — | New routes need router wiring | Omit |
| 26 | Eng | H5: New OAuth2 test setup helper | Genuine Gap | P1 | orgStore=nil skips the code path under test | nil orgStore |
| 27 | Eng | M1: AuditAction typed constants | Genuine Gap | P5 | Bare strings compile with typos | Untyped strings |
| 28 | Eng | M2: X-Forwarded-For/X-Real-IP before RemoteAddr | Genuine Gap | P5 | Behind LB, RemoteAddr is the LB IP not client | RemoteAddr only |
| 29 | Eng | M3: Index on created_at DESC | Genuine Gap | P5 | Full table scan on every /admin/audit page load | No index |
| 30 | Eng | M4: Full AuditStore interface (List + Count) | Genuine Gap | P1 | Pagination requires CountAudit + ListAudit | Log only |
| 31 | Eng | M5: Named column SELECT in GetByID | Genuine Gap | P5 | SELECT * with positional Scan breaks on reorder | SELECT * |
| 32 | Eng | M6: Log seed count on startup | Taste | P5 | Operators need startup confirmation without DB query | Silent |
| 33 | Eng | L1: AuditStore.Log returns error | Taste | P5 | Enables unit-test assertion of write attempt | Void return |
| 34 | Eng | L2: SetAdmin return value | Taste | P5 | Callers can GetByID if needed; low payoff | Return user |
| 35 | Eng | L3: Audit export TODOS note | Taste | P3 | Out of scope now; worth tracking | Implement now |

**Phase 3 complete.** Claude subagent: 16 findings (10 genuine gaps, 4 taste, 2 mechanical). Codex: unavailable. Proceeding to Phase 4 (Final Approval Gate).

---

## Premises (confirmed)

1. Best-effort audit writes don't compromise audit log integrity at current scale — admin actions are rare, failures in audit writes are detectable via logs.
2. DB-backed admin roles are worth the bootstrap complexity given the fallback to ADMIN_EMAILS.
3. The `"", nil` contract test is justified preemptively.
4. Offset pagination is acceptable for this admin panel at current scale.

## Success Criteria

- [ ] `go test ./...` passes (all 14 packages)
- [ ] `make generate` succeeds
- [ ] `go build ./...` succeeds
- [ ] Admin actions logged in `admin_audit_log` (with IP from X-Forwarded-For/X-Real-IP, UA)
- [ ] `/admin/audit` shows paginated log (CountAudit + ListAudit)
- [ ] Admin promote/demote works; last-admin is protected via FOR UPDATE transaction
- [ ] ADMIN_EMAILS seeds is_admin on startup; seed failure falls back to ADMIN_EMAILS (conditional, not always-on)
- [ ] `GetByID` returns correct `IsAdmin` value (explicit SELECT + Scan)
- [ ] `TestAuthorize_OrgClient_NonMember_RendersAccessDenied` passes (using new orgStore helper)
- [ ] `/admin/clients` and `/admin/orgs` paginate at >50 rows
- [ ] Audit writes use `context.WithoutCancel` — not killed by response send
- [ ] `AuditAction` typed constants — no bare strings at call sites
