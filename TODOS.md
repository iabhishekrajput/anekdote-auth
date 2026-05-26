# TODOS — Deferred Scope

Items explicitly deferred during the autoplan review pipeline. Each entry notes which phase deferred it and why.

## Custom Claims (feat/claims — shipped 2026-05-27)

| Item | Deferred by | Rationale |
|------|-------------|-----------|
| Dynamic claims — computed from user attributes at token time | CEO | Requires `source_kind`/`scope_gate` columns on `client_claim_definitions`; schema supports it without breaking changes |
| Claim value expressions / scripting | CEO | Separate execution concern; no demand yet |
| Per-scope claim filtering (claims only injected when specific scope granted) | CEO | Requires `scope_gate` column; schema ready |
| Admin UI for browsing all clients with custom claims | CEO | Listing + filter view; deferred to avoid scope creep |
| Claim namespacing enforcement (Auth0-style `https://` prefix requirement) | CEO | UI currently shows recommendation text only; enforcement deferred |
| `/userinfo` endpoint custom claims injection | CEO | Requires architectural decision on claim destinations; access_token + id_token only for MVP |
| Management API (REST endpoint for programmatic claim management) | CEO | Programmatic access; deferred |
| Token invalidation on claim update | CEO | Aggressive; UI warns about stale tokens instead |
| Single-read architecture for `Token()` + `GenerateIDToken()` consistency | Eng | Sub-ms inconsistency window accepted for MVP; refactor when `GenerateIDToken` API allows passing pre-resolved claims |
| Redis cache for `GetCustomClaims` (60s TTL) | Eng | Premature at current scale; revisit when token throughput > ~1k/sec |
| DB-level byte-size constraint on `client_claim_definitions` | Eng | Handler enforces 4KB; DB constraint adds defense-in-depth; deferred |
| Per-row inline validation errors in claims form | Design | Consistent with existing flash pattern; per-row highlighting deferred |
| Admin UI for listing all clients with non-empty claims | CEO | Useful for audit; deferred |

## OIDC Nonce + Username (shipped 2026-05-27)

| Item | Deferred by | Rationale |
|------|-------------|-----------|
| Separate OIDC state store for nonce keys (`oidc_nonce:*`) | Eng | Currently co-located in `RevocationStore` as MVP pragmatism; JTI revocation and nonce binding are different domains |
| Nonce fail-closed integration test (ConsumeNonce error → 500) | Eng | Requires extracting `revocStore` to an interface or infrastructure-level error injection in miniredis; happy-path and no-nonce paths covered |
| Username update in account settings | CEO | No UI to change username after registration; requires `UpdateUsername` store method + account form field |
| Username uniqueness conflict feedback on registration | Design | Duplicate username currently surfaces as a generic server error; needs friendly inline message |
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
