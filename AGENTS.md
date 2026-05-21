# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Commands

### One-time setup

```bash
npm install               # Required before css-build (Tailwind CLI)
make generate-certs       # RSA-2048 key pair → certs/{private,public}.pem
make postgres-up redis-up mailpit-up   # Datastores via docker-compose
make migrate-up           # Apply Goose migrations
```

### Running the application

```bash
make run                  # Runs with SMTP_INSECURE_SKIP_VERIFY=true
```

### Building

```bash
make generate             # templ codegen — required after editing any .templ file
make css-build            # Tailwind → web/static/app.css
make build                # Cross-builds bin/auth-server (host) + bin/linux_amd64/auth-server
```

### Testing

```bash
go test ./...                          # All tests
go test ./internal/handlers/...        # One package
go test -run TestName ./internal/...   # Single test by name
go test -race ./...                    # Race detector (matches `make audit`)
```

### Quality control

```bash
make tidy     # go mod tidy + verify + vendor + fmt
make audit    # tidy-diff + vet + staticcheck + tests with -race
```

`staticcheck` is declared as a Go tool dependency in `go.mod` (`tool honnef.co/go/tools/cmd/staticcheck`) and invoked via `go tool staticcheck ./...` — no separate install required.

### Database migrations

```bash
make migrate-up     # Apply pending migrations
make migrate-down   # Roll back last migration
```

Migrations are **not** auto-applied at startup — they run via the goose CLI. `make install-goose` installs goose if missing.

---

## Architecture

### Entry point and wiring

`cmd/auth-server/main.go` wires everything together in dependency order:
1. Config (`internal/config`) — env vars with defaults; see `Load()` for the full list.
2. Datastores — Postgres (`internal/store/postgres`) + Redis (`internal/store/redis`).
3. Crypto keys — RSA key pair loaded from disk (`internal/crypto`).
4. OAuth2 server — `internal/auth.BuildServer` wraps `go-oauth2/oauth2`.
5. Mailer — `internal/mailer` wraps `wneessen/go-mail`.
6. Handlers — each receives only the stores/services it needs.
7. Router — `internal/server.NewRouter` using `julienschmidt/httprouter`.
8. CSRF middleware — `justinas/nosurf` wraps the router (exempts `/token`, `/revoke`).

### Store layer

Two storage backends, both under `internal/store/`:

- **`postgres/`** — persistent storage: `UserStore` (users, is_admin), `ClientStore` (OAuth2 clients), `OrgStore` (organizations + memberships), `AuditStore` (admin_audit_log).
- **`redis/`** — ephemeral storage:
  - `SessionStore` — browser sessions (24h TTL), keyed by UUID session ID.
  - `TokenStore` — wraps `go-oauth2/redis` with extra user→token index and revocation checks.
  - `RevocationStore` — JWT blocklist by `jti` (max 72h TTL).

### OAuth2 / OIDC

`internal/auth/` contains two pieces:
- `server.go` — configures the `go-oauth2` manager: maps Postgres client store, Redis token store, custom JWT generator, PKCE support.
- `jwt_generator.go` — implements `oauth2.AccessGenerate`; produces RS256 JWTs with standard OIDC claims (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `scope`) and opaque refresh tokens.

The `kid` header in JWTs maps to the JWKS endpoint (`/.well-known/jwks.json`) for verification by resource servers.

### Handler structure

Each handler in `internal/handlers/` handles one domain:
- `IdentityHandler` — register, login, logout, email verification, forgot/reset password.
- `OAuth2Handler` — `/authorize`, `/token`, `/revoke`; the `userAuthorizeHandler` intercepts to check for an active session and renders consent.
- `DiscoveryHandler` — JWKS and OpenID configuration endpoints (`discovery.go` + `oidc_discovery.go`).
- `AccountHandler` — session-protected `/account` dashboard.
- `AdminHandler` — `/admin/*` routes: user management (disable/enable/promote/demote), OAuth2 client management, org management, and the paginated audit log.

### UI layer

HTML templates use [Templ](https://templ.guide): source files are `web/ui/*.templ`; generated Go files are `*_templ.go`. **Always run `make generate` after editing `.templ` files.** Email-specific templates live in `web/ui/email/`. CSS is Tailwind, built to `web/static/app.css`.

`web/static/` is served at `/static/*filepath` via `http.Dir("web/static")` (`internal/server/router.go:83`) — i.e., the directory is read **from disk at runtime**, not embedded. Any deployment artifact (container image, tarball) must ship `web/static/` alongside the binary.

### Middleware

`internal/middleware/` provides:
- `SecurityHeadersMiddleware` — HSTS, CSP, X-Frame-Options, etc.
- `RateLimitMiddleware` — token bucket via Redis, per-route (`global`: 100/min, `auth`: 10/min).
- `RequireAuth` — redirects to `/login?req=<original_url>` if no valid session; injects `userID` via `types.UserContextKey`.
- `RedirectIfAuthenticated` — bounces logged-in users away from login/register pages.
- `RequireAdmin` — checks `user.IsAdmin` (DB-backed); redirects non-admins to `/`.
- `InjectAdminStatus` — injects `isAdmin bool` into context for nav rendering on auth'd pages.

### Key patterns

- All handlers accept `httprouter.Handle` (not `http.HandlerFunc`); middleware uses a `Chain` helper.
- Context values for request-scoped data are in `internal/types/context.go`.
- CSRF tokens are injected into templates via `nosurf.Token(r)`.
- Migrations are SQL files in `migrations/` managed by [Goose](https://github.com/pressly/goose); applied separately, not at startup.
- The `vendor/` directory is committed; use `make tidy` to update it. Builds use `-mod=vendor` implicitly.
- Go 1.26.0 (see `go.mod`); release builds set `CGO_ENABLED=0` (see `.goreleaser.yaml`).
