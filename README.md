[![CI](https://github.com/iabhishekrajput/anekdote-auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/iabhishekrajput/anekdote-auth/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/iabhishekrajput/anekdote-auth?include_prereleases&display_name=release&logo=github&label=Release&cacheSeconds=3600)](https://github.com/iabhishekrajput/anekdote-auth/releases/latest) [![Image](https://img.shields.io/badge/ghcr.io-anekdote--auth-2496ed?logo=docker&logoColor=white)](https://github.com/iabhishekrajput/anekdote-auth/pkgs/container/anekdote-auth) [![CodeQL Advanced](https://github.com/iabhishekrajput/anekdote-auth/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/iabhishekrajput/anekdote-auth/actions/workflows/codeql.yml)

[![Go Report Card](https://goreportcard.com/badge/github.com/iabhishekrajput/anekdote-auth)](https://goreportcard.com/report/github.com/iabhishekrajput/anekdote-auth) [![Go Coverage](https://github.com/iabhishekrajput/anekdote-auth/wiki/coverage.svg)](https://raw.githack.com/wiki/iabhishekrajput/anekdote-auth/coverage.html)

# Anekdote Auth

Anekdote Auth is a self-hosted **OAuth2 and OpenID Connect (OIDC)** Authorization Server built in Go. It supports multi-tenant organizations, per-org OAuth2 client registration, email-based member invites, and a full account center — making it a complete identity platform for teams and multi-tenant SaaS products.

## Features

- **OAuth 2.0 & OIDC** — Authorization Code flow, consent UI, RS256 JWTs with scope-driven claims (`email`, `name`, `updated_at`), `id_token` in token response (openid scope), `/userinfo` endpoint (OIDC Core §5.3), and a complete OpenID Connect discovery document.
- **PKCE Support** — Enforced for SPA and mobile clients.
- **Native Identity Management** — Registration, login, email verification (OTP), forgot password, and password reset.
- **Multi-Tenant Organizations** — Orgs with owner / admin / viewer / member roles, email invites, per-org OAuth2 client registration, and a full invite acceptance state machine.
- **Account Center Dashboard** — Session-protected dashboard for profile, password, and org management.
- **Immediate JWT Revocation** — RFC 7009 `/revoke` endpoint; denied tokens are blocklisted in Redis by `jti`.
- **Admin Panel** — DB-backed admin roles (`is_admin`), user management (disable/enable/promote/demote), OAuth2 client management, org management, and a tamper-evident audit log with IP and User-Agent capture.
- **Hardened Security** — bcrypt password hashing, CSRF protection, security headers (HSTS, CSP, X-Frame-Options), Redis-backed token-bucket rate limiting per route.

## Tech Stack

- **Go 1.26+** — Core server logic.
- **PostgreSQL** — Persistent storage for users, OAuth2 clients, orgs, and memberships.
- **Redis** — Sessions (24h TTL), JWT blocklist, rate limiting, invite tokens, and flash secrets.
- **Tailwind CSS & Templ** — Utility-first CSS and type-safe HTML templating for all UI pages.

---

## Quick Start

### 1. Requirements

- Go 1.26+
- Node.js & npm (for Tailwind CSS)
- Docker and Docker Compose (datastores)
- `make`

[Templ](https://templ.guide) is a Go tool dependency in `go.mod` — `make generate` invokes it via `go tool templ`, no separate install needed.

### 2. Infrastructure Setup

```bash
make postgres-up
make redis-up
make mailpit-up   # local SMTP for email testing
```

### 3. Cryptography Setup

```bash
make generate-certs   # RSA-2048 key pair → certs/private.pem + certs/public.pem
```

### 4. Configuration

Copy the example env file and fill in your values — the server loads `.env` automatically on startup:

```bash
cp .env.example .env
```

Override any of the following variables (shell exports and container env always take precedence over `.env`):

| Variable | Default | Notes |
|----------|---------|-------|
| `PORT` | `8080` | |
| `APP_ENV` | `development` | |
| `APP_URL` | `http://localhost:8080` | |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:8080` | |
| `DB_DSN` | `postgres://authuser:authpassword@localhost:5432/authdb?sslmode=disable` | |
| `REDIS_URL` | `redis://localhost:6379/0` | |
| `RSA_PRIVATE_KEY_PATH` | `certs/private.pem` | |
| `RSA_PUBLIC_KEY_PATH` | `certs/public.pem` | |
| `SESSION_SECRET` | *(insecure placeholder)* | ⚠️ Defaults to a well-known placeholder. In production (`APP_ENV=production`) the server **refuses to start** if this is not overridden — set it to a random 32+ byte secret. |
| `REDIS_ENCRYPTION_KEY` | *(dev insecure key)* | ⚠️ 64-character hex string (32 bytes). Used for AES-256-GCM encryption of sensitive Redis values (OAuth2 client secret flash). In production the server **refuses to start** if not set. Generate with `openssl rand -hex 32`. |
| `AUDIT_RETENTION_DAYS` | `90` | Audit log entries older than this many days are automatically deleted on startup and every 24 hours. |
| `SMTP_HOST` | `localhost` | |
| `SMTP_PORT` | `1025` | |
| `SMTP_USERNAME` | `test` | |
| `SMTP_PASSWORD` | `test` | |
| `SMTP_FROM` | `noreply@anekdoteauth.local` | |
| `SMTP_INSECURE_SKIP_VERIFY` | `false` | Set `true` for local Mailpit. |

### 5. Running the Application

```bash
npm install
make generate
make css-build
make migrate-up
make run
```

Migrations are managed by [Goose](https://github.com/pressly/goose) and are **not** applied automatically at startup. The schema covers users, OAuth2 clients, orgs, org memberships, and org invites (as Redis keys).

### 6. Quality Control & Building

```bash
make tidy     # go mod tidy + vendor + fmt
make audit    # vet + staticcheck + tests with -race
make build    # cross-compiled binary (host + linux/amd64)
```

---

## Container Images

Multi-arch (`linux/amd64`, `linux/arm64`) images are published to [GitHub Container Registry](https://github.com/iabhishekrajput?tab=packages) on every tagged release.

| Image | Purpose |
|-------|---------|
| `ghcr.io/iabhishekrajput/anekdote-auth` | Auth server runtime. |
| `ghcr.io/iabhishekrajput/anekdote-auth-migrate` | Goose migration runner. |

```bash
docker pull ghcr.io/iabhishekrajput/anekdote-auth:latest
docker pull ghcr.io/iabhishekrajput/anekdote-auth-migrate:latest
```

Images are signed with [Sigstore cosign](https://docs.sigstore.dev/cosign/signing/overview/) via GitHub Actions OIDC:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/iabhishekrajput/anekdote-auth/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/iabhishekrajput/anekdote-auth:latest
```

---

## Route Reference

### Identity

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Redirects to `/login`. |
| `/register` | GET, POST | Create a new account. GET pre-fills email if `?invite=` param is present. |
| `/login` | GET, POST | Session login. GET accepts `?email=` and `?req=` for invite flows. |
| `/verify-email` | GET, POST | OTP verification after registration. Auto-joins org if a pending invite exists. |
| `/forgot-password` | GET, POST | Send a password reset email. |
| `/reset-password` | GET, POST | Set a new password via reset token. |
| `/logout` | POST | Destroys session. Accepts `redirect_to` field (local paths only). |

### Account

| Route | Method | Description |
|-------|--------|-------------|
| `/account` | GET | User profile dashboard. Requires auth. |
| `/account/profile` | POST | Update display name. Requires auth. |
| `/account/password` | POST | Change password. Requires auth. |

### Organizations

| Route | Method | Description |
|-------|--------|-------------|
| `/join` | GET | Accept an org invite by token. Not logged in → `/register`. Wrong account → styled mismatch page. |
| `/account/orgs` | GET, POST | List orgs / create org. Requires auth. |
| `/account/orgs/:slug` | GET | Org detail: members, roles, pending invites. Requires auth. |
| `/account/orgs/:slug/invites` | POST | Send an email invite. Rate-limited. Requires owner or admin role. |
| `/account/orgs/:slug/invites/:token/revoke` | POST | Revoke a pending invite. |
| `/account/orgs/:slug/members/:userID/role` | POST | Change member role (`admin`, `viewer`, or `member`). Owner role cannot be assigned via this form. |
| `/account/orgs/:slug/members/:userID/remove` | POST | Remove a member. |
| `/account/orgs/:slug/clients` | GET, POST | List / register OAuth2 clients scoped to the org. |
| `/account/orgs/:slug/clients/:clientID/delete` | POST | Delete an OAuth2 client. |
| `/account/orgs/:slug/clients/:clientID/rotate-secret` | POST | Rotate client secret (one-time reveal via Redis flash). |

### OAuth2 / OIDC

| Route | Method | Description |
|-------|--------|-------------|
| `/authorize` | GET, POST | Authorization Code flow. Renders consent UI if scope has not been granted. |
| `/token` | POST | Token exchange endpoint. |
| `/revoke` | POST | RFC 7009 token revocation. Blocklists `jti` in Redis. |
| `/userinfo` | GET, POST | OIDC UserInfo endpoint. Bearer JWT auth (`Authorization: Bearer <token>`). Returns scope-driven claims: `sub` always; `email`/`email_verified` with `email` scope; `name`/`updated_at` with `profile` scope. Revocation-checked; fail closed on Redis error. |
| `/.well-known/jwks.json` | GET | Public key set for RS256 JWT verification by resource servers. |
| `/.well-known/openid-configuration` | GET | OpenID Connect Discovery metadata. |

### Admin

All admin routes require `is_admin = true` in the database. The first admin account is bootstrapped via migration `00005_seed_admin.sql` (email: `admin@localhost`, password: `ChangeMe1!`) — log in, promote your real account, then roll back that migration or delete the bootstrap account.

| Route | Method | Description |
|-------|--------|-------------|
| `/admin` | GET | Admin dashboard. |
| `/admin/users` | GET | Paginated user list. |
| `/admin/users/:id` | GET | User detail. |
| `/admin/users/:id/disable` | POST | Disable a user account. |
| `/admin/users/:id/enable` | POST | Re-enable a disabled account. |
| `/admin/users/:id/promote` | POST | Grant admin access. |
| `/admin/users/:id/demote` | POST | Revoke admin access. Protected: last admin cannot be demoted. |
| `/admin/clients` | GET | Paginated OAuth2 client list. |
| `/admin/clients/:id/delete` | POST | Delete an OAuth2 client. |
| `/admin/orgs` | GET | Paginated org list. |
| `/admin/orgs/:slug` | GET | Org detail and members. |
| `/admin/orgs/:slug/members/:user_id/remove` | POST | Remove a member from an org. |
| `/admin/audit` | GET | Paginated admin audit log (action, target, IP, User-Agent). |

### Infrastructure

| Route | Method | Description |
|-------|--------|-------------|
| `/healthz` | GET | Liveness probe. Returns 200 when the process is up. |
| `/readyz` | GET | Readiness probe. Returns 200 when Postgres and Redis are reachable. |
| `/static/*` | GET | Static assets served from `web/static/` at runtime (not embedded). |

---

## Organizations

Anekdote Auth supports multi-tenant organizations. Each org has a unique URL slug, a display name, an owner (the creating user), and zero or more members with roles (`owner` / `admin` / `viewer` / `member`). Org owners and admins can register OAuth2 clients scoped to the org.

### Creating an org

POST `/account/orgs` with a slug and display name. The authenticated user becomes the owner.

### Inviting members

Owners and admins POST `/account/orgs/:slug/invites` with an email address and a role (`admin`, `viewer`, or `member`). An invite token (UUID) is stored in Redis with a 24-hour TTL. The invitee receives an email with a `/join?token=T` link.

### Accepting an invite

Here's what happens when you click an invite link:

1. **You're not logged in** — you land on `/register` with your email pre-filled and read-only. Register, verify your email with the OTP, and you're automatically added to the org.
2. **You're logged in as the right account** — you're added to the org immediately and redirected to the org page.
3. **You're logged in as the wrong account** — you see a styled mismatch page with a "Switch account" button. It logs you out and brings you back to the invite flow so you can sign in with the correct email.

### Per-org OAuth2 clients

Owners and admins can register OAuth2 clients against an org (POST `/account/orgs/:slug/clients`). The client secret is shown exactly once immediately after creation and is stored bcrypt-hashed in Postgres — save it before leaving the page. If you miss it, the client must be deleted and re-created; there is no recovery path.

---

## Architecture Flow

**Direct Web Flow:**
A user navigates to `/login`, provides their credentials, and gets a session UUID stored in Redis and bound as a browser cookie. They land in the `/account` dashboard.

**OAuth Flow:**
When a downstream app redirects to `/authorize?client_id=...`, the server checks for an active session. If none exists, the user is redirected to `/login` carrying the original path in `?req=`. After login they return to `/authorize`, which renders the consent UI. Once the user approves, the Authorization Code flow completes.

**Multi-Tenant Flow:**
When a user belongs to one or more organizations, their account dashboard exposes org management routes. OAuth2 clients are scoped to an org — the `oauth2_clients` table carries an `org_id` foreign key. The `/join` endpoint handles the full invite acceptance state machine (not logged in / wrong account / auto-join) with all state threaded through Redis and URL parameters rather than server-side session state.

---

## Design Decisions

### 1. Invite state lives in Redis, not Postgres

Org invites are stored as JSON in Redis at `org:invite:{token}` with a 24-hour TTL. The set of pending invite tokens per org is tracked at `org:invites:{orgID}` (a Redis Set) for display and revocation. This avoids a schema migration every time invite behavior changes and keeps TTL semantics natural. The tradeoff: invites don't survive a Redis flush, and there is no audit trail of expired invites.

### 2. Pending invite auto-join uses a two-step Redis handoff

When a new user registers via an invite link, the invite token travels as a hidden form field (not in the URL — POST strips query params). On POST, `SetPendingInvite` writes `pending_invite:{userID}` → `{orgID, role}` to Redis. On OTP verification, `GetAndDeletePendingInvite` atomically reads and deletes the key, then calls `AcceptMembership`. If the OTP step is skipped or Redis is flushed between steps, the user is registered but not auto-joined — they can click the invite link again.

### 3. Client secret one-time reveal via Redis flash key

After `CreateOrgClient`, the plaintext secret is stored in Redis at `oauth:client-secret-flash:{clientID}` with a 60-second TTL, and the response redirects to `/account/orgs/:slug/clients?newClientID={id}`. The GET handler calls `GetDel` (Redis ≥ 6.2) to retrieve-and-delete in one operation. The secret is never written to the URL and is bcrypt-hashed in Postgres. If the user misses the 60-second window, the client must be deleted and re-created.
