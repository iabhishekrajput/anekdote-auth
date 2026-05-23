# Plan: Playwright E2E Testing

<!-- /autoplan restore point: /Users/abhishek/.gstack/projects/iabhishekrajput-anekdote-auth/main-autoplan-restore-20260523-103720.md -->

## Goal

Add Playwright browser automation tests to anekdote-auth. The project already has Go unit tests (`go test ./...`) covering handler logic and template rendering. Playwright fills the gap that unit tests can't: real browser flows against a live server — CSRF token handling, cookie auth, form submissions, redirect chains, and multi-page OAuth consent.

## Scope

### In scope
- Playwright installation + `playwright.config.ts`
- Core flow tests:
  - Register → OTP verify (intercept OTP via Mailpit API)
  - Login (valid, invalid credentials)
  - Logout
  - Forgot password → reset password (intercept link via Mailpit API)
  - Account dashboard (view, update profile)
  - Org list + create org + invite + leave
  - OAuth consent flow (authorize → token exchange with test client)
- `make e2e` Makefile target (starts server, runs tests, tears down)
- GitHub Actions E2E job (postgres + redis + mailpit services, runs on PR)

### Out of scope
- Admin panel flows (covered by auth + unit tests sufficiently)
- Visual regression / screenshot diffing (scope creep)
- Mobile viewport testing (future)
- Load testing

## Key Technical Constraints

1. **OTP email** — `SMTP_INSECURE_SKIP_VERIFY=true` routes mail to Mailpit locally. Playwright must query `http://localhost:8025/api/v1/messages` (Mailpit REST API) to extract the OTP code before submitting the verify-email form.

2. **CSRF tokens** — `nosurf` injects CSRF tokens into every form as a hidden input. Playwright submits forms as a real browser does — CSRF is handled automatically via cookie+token pairing. No special handling needed.

3. **Test isolation** — each test registers a unique user (`test-{timestamp}@example.com`) so tests can run in parallel without conflicts.

4. **OAuth test client** — the consent flow requires a registered OAuth2 client. The test setup script (or a fixture) creates one via `POST /account/orgs/:slug/clients` before running the OAuth tests.

5. **Vendor directory** — Go uses `-mod=vendor`. Playwright is Node-only and lives outside the Go module; `node_modules/` is gitignored. Playwright config and tests live in `e2e/`.

6. **CI services** — the existing CI job runs Go tests only. Add a separate `e2e` job with `services: postgres, redis, mailpit` so E2E failures don't block the fast Go test gate.

## File Layout

```
e2e/
  playwright.config.ts
  fixtures/
    auth.ts           # Page Objects: LoginPage, RegisterPage
    mail.ts           # Mailpit helper: waitForOTP(email), waitForResetLink(email)
  tests/
    auth.spec.ts      # register, login, logout, forgot/reset password
    account.spec.ts   # /account dashboard, profile update
    orgs.spec.ts      # org create, invite, leave
    oauth.spec.ts     # full OAuth2 authorization_code + PKCE flow
.github/workflows/
  e2e.yml             # separate CI job for Playwright
Makefile              # + e2e target
package.json          # add @playwright/test devDependency
```

## Decision Audit Trail

| # | Phase | Decision | Classification | Principle | Rationale | Rejected |
|---|-------|----------|----------------|-----------|-----------|---------|
