# TODOS

Deferred items — each has a clear "why not now" note so the decision doesn't get relitigated.

---

## Admin Panel

### Cursor-based pagination on admin list pages
`/admin/users`, `/admin/clients`, `/admin/orgs`, `/admin/audit` use offset/limit pagination. Acceptable at current scale; degrades past ~10k rows per list.
**When:** When any list hits 10k+ rows.
**Shape:** Cursor-based pagination keyed on `created_at DESC` + `id` (stable tiebreaker). The page/pageSize wiring already exists; the query layer needs a `WHERE created_at < $cursor` clause.

### Audit log filter and export
`/admin/audit` shows all events unfiltered. No way to narrow by admin, date range, or action type. No export for compliance evidence.
**When:** Before SOC 2 or any compliance audit, or when the audit table exceeds a few thousand rows.
**Shape:** Query params: `?admin_id=`, `?action=`, `?from=`, `?to=`. Export: `GET /admin/audit/export.csv` streaming from the same query. Retention: auto-delete entries older than configurable TTL (default 90 days).

---

## Auth & Security

### Sensitive data stored plaintext in Redis
Three Redis keys hold usable secrets in plaintext. A Redis read compromise (or a `redis-cli MONITOR` during an incident) directly exposes them:

| Key pattern | Value stored | Risk |
|---|---|---|
| `otp:{userID}` | 6-digit verification code | Attacker bypasses email OTP for any active user |
| `oauth:client-secret-flash:{clientID}` | Full plaintext OAuth2 client secret (60s TTL) | Attacker gets a long-lived credential in the flash window |
| `reset_token:{TOKEN}` | userID (token is the key name) | `SCAN reset_token:*` reveals all active password-reset links |

**When:** Before any production deployment with more than one Redis client, or before any compliance review.

**Shape:**
- **OTPs** — hash before storing: `redis.Set("otp:"+userID, sha256hex(otp), otpTTL)`. On verify, hash the submitted code and compare. `crypto/sha256` in stdlib, no new dependencies.
- **Reset tokens** — same pattern: store `reset_token:{sha256hex(TOKEN)}` → `{userID}`. Send raw token to user in email; hash on lookup. The raw token never appears as a Redis key.
- **Client secret flash** — encrypt with an app-level key before storing. `AES-256-GCM` via `crypto/aes` + `crypto/cipher` in stdlib. The key comes from a new env var `REDIS_ENCRYPTION_KEY` (32 random bytes). `storeSecretFlash` encrypts; `popSecretFlash` decrypts. Redis holds ciphertext only.

Shared infrastructure: a `redisutil` package with `HashForStorage(val string) string` (SHA-256 hex) and `Encrypt/Decrypt(key []byte, plaintext string)` (AES-256-GCM) covers all three cases.

### Role gradations beyond `is_admin`
`is_admin` is a binary: full access or none. There's no read-only admin (view-only, no mutations) or scoped admin (manage orgs but not clients, etc.).
**When:** When the admin team grows beyond 1-2 trusted people, or when audit requirements demand least-privilege roles.
**Shape:** `admin_roles` table or a `role` column with values like `superadmin`, `readonly`, `org_admin`. `RequireAdmin` becomes `RequireRole(...)`.

---

## OAuth2

### Full OAuth2 flow integration suite
Only the org-denial path in `userAuthorizeHandler` is integration-tested. The full Authorization Code flow (consent render, code exchange, token validation, revocation) has no end-to-end test.
**When:** Before upgrading `go-oauth2` or making structural changes to the authorize/token pipeline.
**Shape:** A test server spun up with a real in-memory Postgres (testcontainers) and Redis; flow driven via `net/http/httptest`. Assert each step: redirect to login → consent render → code in redirect → token exchange → JWKS validation → revocation.
