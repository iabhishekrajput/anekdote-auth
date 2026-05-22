# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### One-time setup

```bash
cp .env.example .env      # Copy and fill in local values; loaded automatically on startup
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
8. CSRF middleware — `justinas/nosurf` wraps the router (exempts `/token`, `/revoke`, `/userinfo`).

### Store layer

Two storage backends, both under `internal/store/`:

- **`postgres/`** — persistent storage: `UserStore` (users table), `ClientStore` (OAuth2 clients).
- **`redis/`** — ephemeral storage:
  - `SessionStore` — browser sessions (24h TTL), keyed by UUID session ID.
  - `TokenStore` — wraps `go-oauth2/redis` with extra user→token index and revocation checks.
  - `RevocationStore` — JWT blocklist by `jti` (max 72h TTL).

### OAuth2 / OIDC

`internal/auth/` contains two pieces:
- `server.go` — configures the `go-oauth2` manager: maps Postgres client store, Redis token store, custom JWT generator, PKCE support. Returns `(*server.Server, *JWTGenerator)` — the same generator is reused for both access tokens and id_tokens.
- `jwt_generator.go` — implements `oauth2.AccessGenerate`; produces RS256 JWTs with standard OIDC claims (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `scope`) plus scope-driven claims (`email`/`email_verified` for `email` scope; `name`/`updated_at` for `profile` scope) and opaque refresh tokens. Also exposes `GenerateIDToken` for id_token generation (OIDC Core §3.1.3.3; includes `at_hash`).

The `kid` header in JWTs maps to the JWKS endpoint (`/.well-known/jwks.json`) for verification by resource servers.

### Handler structure

Each handler in `internal/handlers/` handles one domain:
- `IdentityHandler` — register, login, logout, email verification, forgot/reset password.
- `OAuth2Handler` — `/authorize`, `/token`, `/revoke`; the `userAuthorizeHandler` intercepts to check for an active session and renders consent. `/token` injects `id_token` into the response when `openid` scope is present (user grants only; not client_credentials) via a `responseCapture` wrapper.
- `DiscoveryHandler` — JWKS and OpenID configuration endpoints (`discovery.go` + `oidc_discovery.go`).
- `AccountHandler` — session-protected `/account` dashboard.
- `UserInfoHandler` — `GET /userinfo` and `POST /userinfo`; bearer JWT auth (not cookie session), kid-based RS256 verification, revocation check (fail closed), scope-driven claims per OIDC Core §5.3.

### UI layer

HTML templates use [Templ](https://templ.guide): source files are `web/ui/*.templ`; generated Go files are `*_templ.go`. **Always run `make generate` after editing `.templ` files.** Email-specific templates live in `web/ui/email/`. CSS is Tailwind, built to `web/static/app.css`.

`web/static/` is served at `/static/*filepath` via `http.Dir("web/static")` (`internal/server/router.go:83`) — i.e., the directory is read **from disk at runtime**, not embedded. Any deployment artifact (container image, tarball) must ship `web/static/` alongside the binary.

### Middleware

`internal/middleware/` provides:
- `SecurityHeadersMiddleware` — HSTS, CSP, X-Frame-Options, etc.
- `RateLimitMiddleware` — token bucket via Redis, per-route (`global`: 100/min, `auth`: 10/min).
- `RequireAuth` — redirects to `/login?req=<original_url>` if no valid session; injects `userID` via `types.UserContextKey`.
- `RedirectIfAuthenticated` — bounces logged-in users away from login/register pages.

### Key patterns

- All handlers accept `httprouter.Handle` (not `http.HandlerFunc`); middleware uses a `Chain` helper.
- Context values for request-scoped data are in `internal/types/context.go`.
- CSRF tokens are injected into templates via `nosurf.Token(r)`.
- Migrations are SQL files in `migrations/` managed by [Goose](https://github.com/pressly/goose); applied separately, not at startup.
- The `vendor/` directory is committed; use `make tidy` to update it. Builds use `-mod=vendor` implicitly.
- Go 1.26.0 (see `go.mod`); release builds set `CGO_ENABLED=0` (see `.goreleaser.yaml`).
- `/userinfo` does **not** use `RequireAuth` middleware (which requires a cookie session) — it does its own bearer auth from the `Authorization: Bearer` header. CSRF-exempt alongside `/token` and `/revoke`.

---

## gstack

Use the `/browse` skill from gstack for all web browsing. Never use `mcp__claude-in-chrome__*` tools.

Available gstack skills:
`/office-hours`, `/plan-ceo-review`, `/plan-eng-review`, `/plan-design-review`, `/design-consultation`, `/design-shotgun`, `/design-html`, `/review`, `/ship`, `/land-and-deploy`, `/canary`, `/benchmark`, `/browse`, `/connect-chrome`, `/qa`, `/qa-only`, `/design-review`, `/setup-browser-cookies`, `/setup-deploy`, `/setup-gbrain`, `/retro`, `/investigate`, `/document-release`, `/document-generate`, `/codex`, `/cso`, `/autoplan`, `/plan-devex-review`, `/devex-review`, `/careful`, `/freeze`, `/guard`, `/unfreeze`, `/gstack-upgrade`, `/learn`

## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool. When in doubt, invoke the skill.

Key routing rules:
- Product ideas/brainstorming → invoke /office-hours
- Strategy/scope → invoke /plan-ceo-review
- Architecture → invoke /plan-eng-review
- Design system/plan review → invoke /design-consultation or /plan-design-review
- Full review pipeline → invoke /autoplan
- Bugs/errors → invoke /investigate
- QA/testing site behavior → invoke /qa or /qa-only
- Code review/diff check → invoke /review
- Visual polish → invoke /design-review
- Ship/deploy/PR → invoke /ship or /land-and-deploy
- Save progress → invoke /context-save
- Resume context → invoke /context-restore

## GBrain Configuration (configured by /setup-gbrain)
- Mode: local-stdio
- Engine: pglite
- Config file: ~/.gbrain/config.json (mode 0600)
- Setup date: 2026-05-22
- MCP registered: yes (user scope)
- Artifacts sync: full (https://github.com/iabhishekrajput/gstack-artifacts-abhishek)
- Current repo policy: read-write

## GBrain Search Guidance (configured by /sync-gbrain)
<!-- gstack-gbrain-search-guidance:start -->

GBrain is set up and synced on this machine. The agent should prefer gbrain
over Grep when the question is semantic or when you don't know the exact
identifier yet. Two indexed corpora available via the `gbrain` CLI:
- This repo's code (registered as `gstack-code-anekdote-auth` source).
- `~/.gstack/` curated memory (registered as `gstack-artifacts-abhishek` source via
  the existing federation pipeline).

Prefer gbrain when:
- "Where is X handled?" / semantic intent, no exact string yet:
    `gbrain search "<terms>"` or `gbrain query "<question>"`
- "Where is symbol Y defined?" / symbol-based code questions:
    `gbrain code-def <symbol>` or `gbrain code-refs <symbol>`
- "What calls Y?" / "What does Y depend on?":
    `gbrain code-callers <symbol>` / `gbrain code-callees <symbol>`
- "What did we decide last time?" / past plans, retros, learnings:
    `gbrain search "<terms>" --source gstack-artifacts-abhishek`

Grep is still right for known exact strings, regex, multiline patterns, and
file globs. The brain auto-syncs incrementally on every gstack skill start.
Run `/sync-gbrain` to force-refresh, `/sync-gbrain --full` for full reindex.

<!-- gstack-gbrain-search-guidance:end -->
