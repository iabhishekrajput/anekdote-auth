[![CI](https://github.com/iabhishekrajput/anekdote-auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/iabhishekrajput/anekdote-auth/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/iabhishekrajput/anekdote-auth?include_prereleases&display_name=release&logo=github&label=Release&cacheSeconds=3600)](https://github.com/iabhishekrajput/anekdote-auth/releases/latest)
[![Image](https://img.shields.io/badge/ghcr.io-anekdote--auth-2496ed?logo=docker&logoColor=white)](https://github.com/iabhishekrajput/anekdote-auth/pkgs/container/anekdote-auth)
[![CodeQL Advanced](https://github.com/iabhishekrajput/anekdote-auth/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/iabhishekrajput/anekdote-auth/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/iabhishekrajput/anekdote-auth)](https://goreportcard.com/report/github.com/iabhishekrajput/anekdote-auth)
[![Go Coverage](https://github.com/iabhishekrajput/anekdote-auth/wiki/coverage.svg)](https://raw.githack.com/wiki/iabhishekrajput/anekdote-auth/coverage.html)

# Anekdote Auth

Anekdote Auth is a self-hosted OAuth 2.0 and OpenID Connect authorization server for teams and multi-tenant SaaS products. It provides the identity, consent, token, organization, and admin workflows needed to let downstream applications delegate authentication to a central service while retaining control of users, clients, sessions, and audit data.

The server is written in Go, stores durable identity data in PostgreSQL, uses Redis-compatible ephemeral storage for sessions and tokens, renders server-side HTML with Templ, and ships a Tailwind-powered account and admin UI.

## Features

- OAuth 2.0 Authorization Code flow with forced PKCE support.
- OpenID Connect support, including discovery metadata, JWKS, `id_token` generation, `at_hash`, and `/userinfo`.
- RS256 JWT access tokens with `kid`, `jti`, issuer, audience, expiry, scope, user, and organization claims.
- Scope-driven OIDC claims for `openid`, `email`, and `profile`.
- Browser account flows for registration, login, logout, email verification, resend verification, forgot password, and reset password.
- Redis-backed browser sessions with a 24-hour TTL.
- Hashed OTP and password-reset token storage so raw one-time secrets are not persisted in Redis.
- Multi-tenant organizations with owner, admin, viewer, and member roles.
- Organization invitations with duplicate-member and pending-invite guards, invite acceptance, inline auto-submit role changes, ownership transfer, leave organization, and member removal.
- Organization-scoped OAuth2 client registration, client deletion, and client secret rotation.
- One-time OAuth2 client secret reveal using AES-256-GCM encrypted Redis flash values.
- OAuth2 token revocation with JWT `jti` blocklisting.
- Admin dashboard for users, OAuth2 clients, organizations, and audit logs.
- Admin role model with `superadmin`, `readonly`, and `org_admin` permissions for sensitive admin mutations.
- Audit log retention cleanup on startup and every 24 hours.
- Redis-backed fixed-window rate limiting for global and authentication-sensitive routes.
- CSRF protection for browser forms, with bearer-token API exemptions for `/token`, `/revoke`, and `/userinfo`.
- Security headers including HSTS, CSP, X-Frame-Options, referrer policy, and CORS origin control.
- Health and readiness probes at `/healthz` and `/readyz`.
- Local Mailpit setup for development email testing.
- Unit and integration-style tests using `sqlmock`, `miniredis`, and Playwright E2E coverage.

## Tech Stack

- **Language:** Go 1.26.0.
- **HTTP routing:** `julienschmidt/httprouter`.
- **OAuth2 server:** `github.com/go-oauth2/oauth2/v4`.
- **JWTs:** `github.com/golang-jwt/jwt/v5` with RSA keys loaded from `certs/private.pem` and `certs/public.pem`.
- **Templates:** [Templ](https://templ.guide), with source templates in `web/ui/**/*.templ`.
- **CSS:** Tailwind CSS 4 via `@tailwindcss/cli`, compiled from `web/static/tailwind.css` to `web/static/app.css`.
- **Persistent datastore:** PostgreSQL, with Goose migrations in `migrations/`.
- **Ephemeral datastore:** Redis-compatible storage through `github.com/go-redis/redis/v8`.
- **Local Redis image:** `redis/redis-stack:latest` from `docker-compose.yml`.
- **Valkey compatibility:** The app talks to Redis through `REDIS_URL`; a Valkey deployment should work if it supports the Redis commands used by the app, including `GETDEL`.
- **Email:** `wneessen/go-mail`, with local Mailpit support.
- **CSRF:** `justinas/nosurf`.
- **Password hashing:** `golang.org/x/crypto/bcrypt`.
- **Static analysis:** `go vet` and `go tool staticcheck ./...`.
- **E2E tests:** Playwright under `tests/`.
- **Containers:** Multi-stage Dockerfile with runtime and migration images.

## Prerequisites

- Go 1.26.0 or newer.
- Node.js and npm for Tailwind CSS.
- Docker and Docker Compose for local PostgreSQL, Redis Stack, and Mailpit.
- `make`.
- OpenSSL for local RSA key generation.
- Goose migration CLI. The `make migrate-up` target installs it automatically if `goose` is not already available.
- Optional: `psql` for direct database access and E2E seeding outside Docker.
- Optional: Playwright browsers for E2E tests via `make e2e-install`.

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/iabhishekrajput/anekdote-auth.git
cd anekdote-auth
```

### 2. Install frontend dependencies

Tailwind is driven by npm. Install Node dependencies before building CSS.

```bash
npm install
```

### 3. Create local configuration

The server loads `.env` automatically on startup. Existing shell or container environment variables take precedence over values in `.env`.

```bash
cp .env.example .env
```

Review these variables before running locally:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | HTTP listen port. |
| `APP_ENV` | `development` | Set to `production` for production hardening checks. |
| `APP_URL` | `http://localhost:8080` | Public issuer/base URL used in OIDC metadata and tokens. |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:8080` | Value used by the security headers middleware. |
| `DB_DSN` | `postgres://authuser:authpassword@localhost:5432/authdb?sslmode=disable` | PostgreSQL connection string. |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis or Valkey-compatible connection URL. |
| `RSA_PRIVATE_KEY_PATH` | `certs/private.pem` | Private RSA key for signing JWTs. |
| `RSA_PUBLIC_KEY_PATH` | `certs/public.pem` | Public RSA key exposed through JWKS. |
| `SESSION_SECRET` | `EpQ6pGzCF3vkXCfP5F12HY8qqr/p7ovk9k1DBk6wqdk=` | Required random 32+ byte secret in production. |
| `REDIS_ENCRYPTION_KEY` | `e426b5dea0c75ad0eeaeb19b53f9fc52d9b2bc639567293a55c5e4945518834f` | 64-character hex AES-256 key for encrypted Redis flash values. Required in production. |
| `SMTP_HOST` | `localhost` | SMTP host. |
| `SMTP_PORT` | `1025` | SMTP port. Local Mailpit listens here. |
| `SMTP_USERNAME` | `test` | SMTP username. |
| `SMTP_PASSWORD` | `test` | SMTP password. |
| `SMTP_FROM` | `noreply@anekdoteauth.local` | From address for application email. |
| `SMTP_INSECURE_SKIP_VERIFY` | `true` in `.env.example` | Allows local Mailpit SMTP without production TLS checks. |
| `AUDIT_RETENTION_DAYS` | `90` | Days to retain admin audit log rows. |
| `LOG_LEVEL` | `info` | Optional runtime logger level: `debug`, `info`, `warn`, or `error`. |

For production, set `SESSION_SECRET` to a random secret and `REDIS_ENCRYPTION_KEY` to a 64-character hex value:

```bash
openssl rand -base64 32
openssl rand -hex 32
```

### 4. Start local services

```bash
make postgres-up
make redis-up
make mailpit-up
```

This starts:

- PostgreSQL on `localhost:5432`.
- Redis Stack on `localhost:6379`.
- RedisInsight from the Redis Stack image on `localhost:8001`.
- Mailpit SMTP on `localhost:1025`.
- Mailpit web UI on `http://localhost:8025`.

### 5. Generate RSA keys

JWT access tokens and ID tokens are signed with RSA keys loaded from disk.

```bash
make generate-certs
```

This creates `certs/private.pem` and `certs/public.pem` if they do not already exist.

### 6. Generate templates and CSS

Templ source files are not served directly. Regenerate Go template code after editing any `.templ` file, and build CSS after changing Tailwind input or template classes.

```bash
make generate
make css-build
```

Static files are served from `web/static/` at runtime, not embedded into the Go binary. If you deploy the compiled binary directly, ship `web/static/` beside it.

### 7. Apply database migrations

Migrations are managed by Goose and are not applied automatically at application startup.

```bash
make migrate-up
```

The last migration seeds a bootstrap admin account:

- Email: `admin@localhost`
- Password: `ChangeMe1!`

Use it only for first-time setup. After creating and promoting your real account, remove the bootstrap account by rolling back `00005_seed_admin.sql` with `make migrate-down`, disabling it in the admin UI, or deleting it manually from a trusted database session.

### 8. Run the server

```bash
make run
```

Open `http://localhost:8080`. The root path redirects to `/login`.

### 9. Build binaries

```bash
make build
```

This builds:

- `bin/auth-server` for the host platform.
- `bin/linux_amd64/auth-server` for Linux AMD64.

### 10. Run checks

```bash
go test ./...
make audit
```

`make audit` runs dependency checks, `go vet`, Staticcheck, and race-enabled tests. If generated Templ files are missing or stale, run `make generate` first.

For E2E tests:

```bash
cp .env.test.example .env.test
make e2e-install
make e2e
```

## Project Structure

```text
.
|-- cmd/auth-server/          # Application entry point and runtime wiring.
|-- internal/auth/            # OAuth2 manager setup and custom JWT/id_token generator.
|-- internal/config/          # .env loading, runtime defaults, and production validation.
|-- internal/crypto/          # RSA key loading and JWKS helpers.
|-- internal/handlers/        # Identity, OAuth2, OIDC, account, org, admin, and probe handlers.
|-- internal/mailer/          # SMTP email delivery.
|-- internal/middleware/      # Auth, admin roles, logging, security headers, and rate limiting.
|-- internal/models/          # Core user and organization model types.
|-- internal/server/          # Router construction and route registration.
|-- internal/store/postgres/  # PostgreSQL stores for users, clients, orgs, and audit logs.
|-- internal/store/redis/     # Redis stores for sessions, tokens, revocation, OTPs, and flashes.
|-- internal/types/           # Shared context keys.
|-- migrations/               # Goose SQL migrations.
|-- tests/                    # Playwright E2E tests, fixtures, and seed data.
|-- web/static/               # Runtime static assets and Tailwind input/output.
|-- web/ui/                   # Templ page and email templates.
|-- docker-compose.yml        # Local PostgreSQL, Redis Stack, and Mailpit services.
|-- Dockerfile                # Runtime and migration image builds.
|-- Makefile                  # Common development, build, migration, and test commands.
|-- go.mod                    # Go module, library dependencies, and Go tool dependencies.
`-- package.json              # Tailwind CLI dependencies and CSS scripts.
```

### Runtime Wiring

`cmd/auth-server/main.go` initializes the application in dependency order:

1. Load and validate configuration.
2. Connect to PostgreSQL and Redis-compatible storage.
3. Load the RSA key pair.
4. Initialize PostgreSQL and Redis stores.
5. Build the OAuth2/OIDC server and JWT generator.
6. Initialize the SMTP mailer.
7. Construct handlers.
8. Start audit retention cleanup.
9. Register routes and wrap them with CSRF and request logging middleware.
10. Start the HTTP server with graceful shutdown.

### Storage Responsibilities

PostgreSQL stores durable data:

- Users and admin roles.
- OAuth2 clients.
- Organizations and memberships.
- Admin audit log entries.

Redis or Valkey-compatible storage handles ephemeral state:

- Browser sessions at `session:*`.
- OAuth2 tokens through the `go-oauth2/redis` token store.
- JWT revocation blocklist entries at `revoked_jti:*`.
- Per-client token indexes at `oauth:client-tokens:*`.
- Email verification OTPs at `otp:*`.
- Failed login counters at `failed_login:*`.
- Password reset tokens at `reset_token:*`.
- Pending invite handoff entries at `invite:pending:*`.
- Organization invite payloads at `org:invite:*` and pending invite sets at `org:invites:*`.
- One-time encrypted OAuth2 client secret flashes at `oauth:client-secret-flash:*`.
- Rate-limit counters.

## Management API

The Management API provides programmatic control over per-client custom claim definitions. It is designed for CI/CD pipelines and service accounts that need to configure JWT claims without using the admin UI.

### Authentication

All Management API requests require a Bearer JWT signed with the server's RSA private key and targeting the management audience (`MANAGEMENT_AUDIENCE`, default `<APP_URL>/api/v1/`).

```
Authorization: Bearer <signed-RS256-JWT>
```

Required JWT claims:

| Claim | Description |
|-------|-------------|
| `iss` | Must equal `APP_URL` |
| `aud` | Must equal `MANAGEMENT_AUDIENCE` |
| `org_id` | Organization that owns the target client |
| `scope` | Space-separated scopes (see below) |
| `jti` | Unique token ID (prevents replay) |
| `exp` | Expiry timestamp |

### Service Account Tokens

Create a service account from an organization's client list or the Developer Apps page. A service account is a confidential, org-bound OAuth2 client; when it uses `client_credentials`, issued access tokens include that organization's `org_id` and can call the Management API.

Example token request:

```bash
curl -X POST "$APP_URL/token" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=client_credentials \
  -d scope="read:client_claims update:client_claims"
```

### Scopes

| Scope | Access |
|-------|--------|
| `read:client_claims` | `GET /api/v1/clients/:id/claims` |
| `update:client_claims` | `PUT /api/v1/clients/:id/claims`, `PATCH /api/v1/clients/:id/claims/:key` |

### Endpoints

#### GET /api/v1/clients/:id/claims

Returns the current custom claim definitions for a client. The caller's `org_id` must match the client's owning organization.

```json
{
  "claims": [
    {
      "key": "https://example.com/role",
      "type": "string",
      "value": "admin",
      "destinations": "access_token",
      "scope_gate": "openid",
      "source_kind": "static"
    }
  ]
}
```

Claims are sorted by key. Results are filtered to claims owned by the caller's organization.

#### PUT /api/v1/clients/:id/claims

Replaces all custom claim definitions atomically (replace-all semantics). Accepts an array of claim objects.

```json
{
  "claims": [
    {
      "key": "https://example.com/tier",
      "type": "string",
      "value": "pro",
      "destinations": "access_token,id_token"
    }
  ]
}
```

Response on success (`200 OK`):

```json
{
  "operation": "replace_all",
  "count": 1,
  "claims": [...]
}
```

#### PATCH /api/v1/clients/:id/claims/:key

Creates or updates one claim without replacing the rest of the client's claim set. URL-encode `:key` when it contains `/` characters, or send the same key in the JSON body for readability.

```json
{
  "key": "https://example.com/tier",
  "type": "string",
  "value": "enterprise",
  "destinations": "access_token",
  "scope_gate": "premium",
  "source_kind": "static"
}
```

Response on success (`200 OK`):

```json
{
  "operation": "patch",
  "claim": {
    "key": "https://example.com/tier",
    "type": "string",
    "value": "enterprise",
    "destinations": "access_token",
    "scope_gate": "premium",
    "source_kind": "static"
  }
}
```

### Claim Fields

| Field | Required | Description |
|-------|----------|-------------|
| `key` | Yes | Claim key — must start with `https://` (namespace-prefixed) |
| `type` | Yes | `"string"`, `"number"`, or `"boolean"` |
| `value` | Yes | Claim value as a string; coerced to the declared type at token issuance |
| `destinations` | No | Comma-separated destination list (default: `token`). Valid values: `token`, `access_token`, `id_token`, `userinfo`, `access_token,id_token,userinfo`, and combinations |
| `scope_gate` | No | Single scope identifier. Claim is only injected when that scope is present in the token |
| `source_kind` | No | `static` stores `value` directly; `user_attribute` reads one supported token-time attribute; `expression` expands `{{user.email}}`, `{{user.name}}`, `{{user.username}}`, `{{user.id}}`, `{{org.id}}`, and `{{org.role}}` |

Up to 20 claims per client. Keys longer than 100 characters are rejected.

### Rate Limiting

Management API routes are rate-limited to 20 requests per minute per IP. Exceeded limits return `429 Too Many Requests` with a `Retry-After` header.

### Error Responses

Errors follow RFC 6750 format:

```json
{
  "error": "invalid_token",
  "error_description": "token validation failed"
}
```

The `WWW-Authenticate` header is set on `401` responses with the appropriate `error` and `error_description` challenge parameters.

## Contributing

Pull requests are welcome. Before opening a PR, please run the relevant local checks:

```bash
make generate
make css-build
go test ./...
make audit
```

Keep changes focused, include tests for behavior changes, and update documentation when setup, configuration, routes, or developer workflows change.
