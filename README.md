[![CI](https://github.com/iabhishekrajput/anekdote-auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/iabhishekrajput/anekdote-auth/actions/workflows/ci.yml) [![CodeQL Advanced](https://github.com/iabhishekrajput/anekdote-auth/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/iabhishekrajput/anekdote-auth/actions/workflows/codeql.yml)

[![Go Report Card](https://goreportcard.com/badge/github.com/iabhishekrajput/anekdote-auth)](https://goreportcard.com/report/github.com/iabhishekrajput/anekdote-auth) [![Go Coverage](https://github.com/iabhishekrajput/anekdote-auth/wiki/coverage.svg)](https://raw.githack.com/wiki/iabhishekrajput/anekdote-auth/coverage.html)

# Anekdote Auth

Anekdote Auth is a robust, enterprise-grade **OAuth2** and **OpenID Connect (OIDC)** Authorization Server built entirely in Go.

It serves as a fully featured Identity Provider (IdP) equipped with a modern User Interface built with Tailwind CSS and Templ, comprehensive Session Management, and secure password-backed authentication flows.

## Features

- **OAuth 2.0 & OIDC**: Full support for Authorization Code paths, Token Exchanges, and `/authorize` consent interactions. Issues cryptographically signed JSON Web Tokens (JWTs) and structured `id_token` claims.
- **PKCE Support**: Strictly enforces Proof Key for Code Exchange validation for secure front-end SPA and mobile app architectures.
- **Native Identity Management**: Pre-built HTTP interfaces for User Registration, Login, Forgot Password, and Password Reset (backed by `github.com/wneessen/go-mail`).
- **Account Center Dashboard**: Dedicated, session-protected dashboard (`/account`) allowing users to dynamically manage their names and passwords.
- **Immediate JWT Revocation**: Provides an RFC 7009 compliant `/revoke` endpoint. Denied tokens are instantly pushed to a Redis-backed blocklist (`jti` tracking).
- **Hardened Security**:
  - `bcrypt` iterated password hashing.
  - Comprehensive middleware-driven Security Headers (HSTS, CSP, XSS-Protection).
  - Token Bucket algorithms dynamically throttling routes via Redis.
  - Automatic JSON Web Key Set (JWKS) Discovery Endpoints.

## Tech Stack
- **Go 1.22+**: Core server logic.
- **PostgreSQL**: Master persistent storage mechanism for Users and OAuth2 mapping schemas.
- **Redis**: High-speed, ephemeral memory cache leveraged for active HTTP Session Tracking, JWT Blocklisting, and Rate Limit throttling.
- **Tailwind CSS & Templ**: Utility-first CSS framework and type-safe HTML templating engine driving the identity web templates.

---

## 🚀 Quick Start Guide

### 1. Requirements
Ensure you have the following installed to run the backend natively:
- Go 1.22+
- Node.js & npm (for Tailwind CSS)
- [templ CLI](https://templ.guide)
- Docker and Docker Compose (to spawn backend datastores)
- `make`

### 2. Infrastructure Setup
Start up local PostgreSQL, Redis, and Mailpit (for local email testing) servers via Docker using the bundled `docker-compose.yml`:

```bash
docker compose up -d
```

### 3. Cryptography Setup
OAuth2 JWT signing and validation workflows mandate standard RSA public and private key chains.
Create a local `./certs` folder and execute the following `openssl` commands to produce them:

```bash
mkdir certs
openssl genpkey -algorithm RSA -out certs/private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in certs/private.pem -out certs/public.pem
```

### 4. Configuration (Environment Variables)
Global variables can be provided natively or securely through a local `.env`. See the variables available natively mapped:
- `PORT` (default: `8080`)
- `APP_ENV` (default: `development`)
- `APP_URL` (default: `http://localhost:8080` - dynamic based on port)
- `CORS_ALLOWED_ORIGINS` (default: `http://localhost:8080`)
- `DB_DSN` (default `postgres://authuser:authpassword@localhost:5432/authdb?sslmode=disable`)
- `REDIS_URL` (default `redis://localhost:6379/0`)
- `RSA_PRIVATE_KEY_PATH` (default `certs/private.pem`)
- `RSA_PUBLIC_KEY_PATH` (default `certs/public.pem`)
- `SESSION_SECRET`

**SMTP Configurations** (to activate functional Forgot Password emails):
- `SMTP_HOST` (default `localhost`)
- `SMTP_PORT` (default `1025`)
- `SMTP_USERNAME` (default `test`)
- `SMTP_PASSWORD` (default `test`)
- `SMTP_FROM` (default `noreply@anekdoteauth.local`)
- `SMTP_INSECURE_SKIP_VERIFY` (default: `false`)

*Note: For local development, Mailpit is available via the `docker-compose.yml` file. You can set `SMTP_HOST=localhost`, `SMTP_PORT=1025`, and access the web UI at `http://localhost:8025`.*

### 5. Running the Application
A built-in `Makefile` provides macro hooks. To install dependencies, generate templates, build CSS, and start the application:

```bash
npm install
make generate
make css-build
make run
```
_The server will connect to Postgres to auto-migrate schemas, poll Redis, parse all HTML templates, load standard cryptographic certs, and bind onto port `8080`._

---

## Accessing the Core Interfaces

While the true purpose of this API is headless `go-oauth2` downstream logic, the application binds several Human-Facing Identity APIs natively over the browser on port `:8080`:

| Interface | Route | Action |
| ------ | ------ | ------ |
| **Login** | `http://localhost:8080/login` | Native session establishment. |
| **Register** | `http://localhost:8080/register` | Create a new Identity record in Postgres. |
| **Dashboard** | `http://localhost:8080/account` | Protected portal for active users. |
| **JWKS Endpoint** | `http://localhost:8080/.well-known/jwks.json` | Public key verification for Resource Servers. |

---

## Architecture Flow (Session vs OAuth)

**Direct Web Flow:**
When a standard user manually connects to `localhost:8080/login` and provides a valid payload, the `/login` handler validates `bcrypt` iterations, builds a unique secure UUID Session record inside **Redis**, binds the session via standard internal Browser Cookies, and drops the user straight into the `/account` profile center.

**OAuth Flow:**
When cross-site infrastructure (e.g. NextJS) redirects to `localhost:8080/authorize?client_id=...`, the server executes the `Authorize` workflow. Middleware traps and catches if no `auth_session` cookie is appended. The consumer is redirected to `/login` *carrying the origin path locally*. Following standard re-validation, they are returned dynamically to the Consent page to finish `code` exchange validation seamlessly!
