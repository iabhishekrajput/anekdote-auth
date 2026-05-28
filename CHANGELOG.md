# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Management REST API** — `GET /api/v1/clients/:id/claims` and `PUT /api/v1/clients/:id/claims` for programmatic claim management. Bearer RS256 auth with `iss`, `aud`, `org_id` ownership, `jti` revocation (fail-closed), and `scope` word-boundary gating.
- **Custom claim `scope_gate`** — claim emission can be gated on a specific authorized scope; claims are silently omitted when the scope is absent.
- **Custom claim `destinations`** — per-claim control over which tokens receive the claim: `access_token`, `id_token`, `userinfo`, or comma-separated combinations.
- **Service accounts / M2M** — `client_credentials` grants now inject `org_id` into access tokens when the client belongs to an org, enabling headless CI/CD pipelines scoped to an organization.
- **`https://` namespace enforcement** — custom claim keys must carry an `https://` prefix; reserved OIDC names (`sub`, `iss`, `aud`, etc.) are blocked at the API and UI level.
- **`MANAGEMENT_AUDIENCE` config** — expected `aud` claim value for Management API tokens (default: `anekdote-auth-management`).

### Changed
- `/userinfo` now injects custom claims filtered by `destinations=userinfo`.
- Claims page Save button no longer expands to fill the flex row (layout fix in org and admin views).

### Fixed
- RFC 6750 §3.1 compliance: Management API and `/userinfo` emit realm-only `WWW-Authenticate` (no `error=` param) when no Authorization header is present; full `error=`/`error_description=` challenge only on bad/expired tokens.
- `server_error` from `/userinfo` custom-claims reader now returns HTTP 500 (was 401) per OIDC Core §5.3.
- Management API returns 403 (not 404) when a client is not found or ownership check fails, preventing client ID enumeration.
- `aud` claim in Management API token validation now accepts RFC 7519 single-element array form.
- `scope_gate` validated: single identifier, max 64 chars, no spaces allowed — rejects multi-word values that would silently suppress claims.
- CORS `Access-Control-Allow-Methods` now includes `PUT` for Management API callers.
- Added `Vary: Origin` response header to CORS middleware to prevent proxy mis-caching.
- 32 KB `MaxBytesReader` guard on `PUT /api/v1/clients/:id/claims` body before JSON decode.

### Security
- Management API token validation enforces `iss` claim must match the server's own URL.
- Management API scope check uses opaque error codes to avoid leaking scope names to callers.

---

## [2.1.0] — 2026-05-27

### Added
- **OIDC nonce support** — `nonce` claim included in `id_token` when provided by the relying party; stored in `RevocationStore` and validated on exchange to prevent replay attacks.
- **Username field** — users now have a `username` alongside their display name; exposed as `preferred_username` in `/userinfo`, `id_token`, and the OIDC discovery document.
- **Custom JWT claims v1** — per-client typed claim definitions (`string`, `number`, `boolean`) stored in `client_claim_definitions`; injected into access tokens and id_tokens at issuance time. Payload capped at 20 claims / ~4 KB per client.
- **Per-field registration errors** — registration form shows inline validation errors per field instead of a single flash message.

### Fixed
- `preferred_username` claim now appears in `/userinfo` responses.
- OIDC discovery document corrected to include all supported scopes and claims.
- `ON CONFLICT` predicate in email index migration matched to the actual partial index definition.

---

## [2.0.0] — 2026-05-21

### Added
- **UI component library** — reusable `PrimaryButton`, `SecondaryButton`, `InputField`, `AlertBanner`, and layout components across all pages.
- **Brand color system** — CSS `@theme` tokens for brand accent, semantic states, and reduced-motion support via Tailwind v4.
- **Redesigned auth pages** — login, register, forgot password, and reset password pages rebuilt with the new component library.
- **Redesigned consent page** — client trust badge showing app name, logo, and requested scopes.
- **Redesigned account and organization pages** — dashboard, org detail, member list, and invite flows.
- **Email template redesign** — verification and password-reset emails updated with brand accent color.
- **Loading spinners** — client-side form interactivity injected into all submit buttons; spinner hidden by default, revealed on submit.
- **Insecure `SESSION_SECRET` guard** — server refuses to start in `production` if `SESSION_SECRET` is a known-weak or default value.
- **Multi-org OAuth2 grants** — users can authorize clients scoped to a specific organization; grant records stored in `client_org_grants`.
- **Multi-org "Explore Apps" directory** — users see a listing of applications available within their organization.
- **Org transfer ownership and leave** — org owners can transfer ownership; members can leave an organization.
- **User and org soft-delete** — users and orgs are soft-deleted with active session revocation, not hard-deleted.
- **Playwright E2E test suite** — browser automation tests covering auth flows, org management, OIDC discovery, and revocation.
- **Production Docker Compose** — `docker-compose.prod.yml` with Cloudflare Tunnel integration for zero-config HTTPS.

### Changed
- **Entity IDs migrated from UUID to prefixed ULID** — all `users`, `orgs`, `clients`, and session IDs are now prefixed ULID strings (e.g., `usr_`, `org_`, `cli_`). **Breaking:** any consumer storing or comparing raw IDs must handle the new format.
- Tailwind CSS upgraded to v4; CSS build uses `@theme` directive.

### Fixed
- Org role dropdown no longer blocked by Content-Security-Policy.
- Account and org page content correctly centered within `AccountLayout`.
- Various multitenancy bugs in session and token lookup paths.

### Security
- Session secret strength enforced at startup in production mode.

---

## [1.0.11] — 2026-05-12

### Fixed
- OIDC discovery document now emits the configured `AppURL` as the issuer, not a hardcoded HTTP fallback.

### Added
- Health (`/health`) and readiness (`/ready`) probe endpoints.

---

## [1.0.8] — 2026-05-12

### Changed
- CI images published to GitHub Container Registry (`ghcr.io`) instead of Docker Hub.

### Added
- OCI image metadata labels and Cosign image signing in referrers mode.

---

## [1.0.0] — 2026-03-05

### Added
- Initial release.
- Core OAuth2 server: Authorization Code flow with PKCE, Client Credentials, token refresh, and revocation (`/token`, `/revoke`).
- OIDC layer: `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/userinfo`, RS256 JWTs with standard claims.
- Identity management: user registration, login, logout, email verification, forgot/reset password.
- Organization management: create org, invite members, role management (owner / admin / member).
- Admin panel: user listing, org listing, client registration, audit log, role promotion/demotion.
- Session management: Redis-backed browser sessions (24h TTL).
- Rate limiting: Redis fixed-window rate limiter per route (`global`: 100/min, `auth`: 10/min).
- Security headers: HSTS, CSP, X-Frame-Options, X-XSS-Protection.
- CSRF protection via `nosurf` (exempt: `/token`, `/revoke`, `/userinfo`).
- GoReleaser automated releases; multi-platform Docker images.
- GitHub Actions: test, coverage, CodeQL, and release workflows.

[Unreleased]: https://github.com/iabhishekrajput/anekdote-auth/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/iabhishekrajput/anekdote-auth/compare/v2.0.13...v2.1.0
[2.0.0]: https://github.com/iabhishekrajput/anekdote-auth/compare/v1.0.11...v2.0.0
[1.0.11]: https://github.com/iabhishekrajput/anekdote-auth/compare/v1.0.8...v1.0.11
[1.0.8]: https://github.com/iabhishekrajput/anekdote-auth/compare/v1.0.0...v1.0.8
[1.0.0]: https://github.com/iabhishekrajput/anekdote-auth/releases/tag/v1.0.0
