# TODOS — Deferred Scope

Items explicitly deferred during the autoplan review pipeline. Each entry notes which phase deferred it and why.

## Claim Policy Plane (feat/claim-policy-plane — shipped 2026-05-28)

### Hard Enterprise Blockers

| Item | Priority | Rationale |
|------|----------|-----------|
| **M2M service account path** — `client_credentials` grant with `org_id` binding for CI/CD | P0 | Schema + JWT injection shipped; missing: UI to create service account clients (mark `org_id` at creation), docs for the flow. Auth0 parity requires this for headless onboarding automation. |
| `PATCH /api/v1/clients/:id/claims/:key` — update a single claim without replace_all | P1 | `PUT` is destructive (replaces all claims); a `PATCH` endpoint is required to safely update one claim from CI without reading the full set first. |

### Deferred in Sprint

| Item | Deferred by | Rationale |
|------|-------------|-----------|
| Dynamic claims — computed from user attributes at token time | CEO | `source_kind` column exists; execution engine not built |
| Claim value expressions / scripting | CEO | Separate execution concern; no demand yet |
| Admin UI for browsing all clients with custom claims | CEO | Listing + filter view; deferred to avoid scope creep |
| Token invalidation on claim update | CEO | Aggressive; UI warns about stale tokens instead |
| Single-read architecture for `Token()` + `GenerateIDToken()` consistency | Eng | Sub-ms inconsistency window accepted for MVP |
| Redis cache for `GetCustomClaims` (60s TTL) | Eng | Premature at current scale; revisit at >1k token/sec |
| DB-level byte-size constraint on `client_claim_definitions` | Eng | Handler enforces 4KB; DB constraint adds defense-in-depth |
| Per-row inline validation errors in claims form | Design | Consistent with existing flash pattern; per-row highlighting deferred |
| Admin UI for listing all clients with non-empty claims | CEO | Useful for audit; deferred |
| JWT validation sub-codes (`token_expired`, `invalid_signature`, `unknown_kid`) | Eng | Management API returns generic "invalid token"; sub-codes improve DX for debugging |
| Username update in account settings | CEO | No UI to change username after registration; requires `UpdateUsername` store method + account form field |
| E2E tests for custom claims UI (`tests/tests/claims.spec.ts`) | Eng | Playwright tests covering destinations select and namespace rejection |

## Custom Claims v1 (feat/claims — shipped 2026-05-27)

| Item | Deferred by | Rationale |
|------|-------------|-----------|
| Admin UI for browsing all clients with custom claims | CEO | Listed above |
| Per-row inline validation errors in claims form | Design | Listed above |
| Admin UI for listing all clients with non-empty claims | CEO | Listed above |

## OIDC Nonce + Username (shipped 2026-05-27)

| Item | Deferred by | Rationale |
|------|-------------|-----------|
| Separate OIDC state store for nonce keys (`oidc_nonce:*`) | Eng | Currently co-located in `RevocationStore` as MVP pragmatism; JTI revocation and nonce binding are different domains |
| Username update in account settings | CEO | No UI to change username after registration; requires `UpdateUsername` store method + account form field |
| `preferred_username` claim in `/userinfo` endpoint | Eng | `/userinfo` returns scope-driven claims from the bearer token but does not re-derive `preferred_username` from the DB; consistent with token claims but worth auditing |

## Playwright Tests (tests added 2026-05-26)

| Item | Deferred by | Rationale |
|------|-------------|-----------|
| Admin promote/demote/delete user mutations | CEO | Too destructive for shared test env |
| Admin org delete (`/admin/orgs/:slug/delete`) | CEO | Destructive; deferred |
| Grant approval/denial flow | CEO | Requires multi-org setup |
| Explore apps (`/account/orgs/:slug/explore`) | CEO | UI-only listing; low value |
| Open-redirect security test (req= param) | CEO | Better as Go integration test |
| Negative org authorization tests | CEO | Requires additional seeded users |
| Invite token replay test | CEO | Separate concern |
| Cross-browser testing (Safari/Firefox) | CEO | Chromium-only infra |
| Mobile viewport testing | CEO | Deferred |
| E2E tests for custom claims UI | Eng | Add to `tests/tests/claims.spec.ts` |
