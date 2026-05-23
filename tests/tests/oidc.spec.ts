import { test, expect } from '@playwright/test';
import { loginSeeded } from '../fixtures/auth';
import * as crypto from 'crypto';

const CLIENT_ID = 'e2e-test-client';
const CLIENT_SECRET = 'e2e-test-client-secret';
const REDIRECT_URI = 'http://localhost:9999/callback';

function buildPKCE(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  refresh_token?: string;
  id_token?: string;
}

/** Complete the PKCE authorization_code flow and return the token response.
 *  Requires the page to already be authenticated. */
async function getTokens(page: Parameters<typeof loginSeeded>[0], baseURL: string): Promise<TokenResponse> {
  const { verifier, challenge } = buildPKCE();
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');

  const authorizeURL = `${baseURL}/authorize?` + new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });

  await page.route(`${REDIRECT_URI}**`, route => route.abort());
  await page.goto(authorizeURL);

  const [request] = await Promise.all([
    page.waitForRequest(`${REDIRECT_URI}**`),
    page.click('button[name="accept"][value="true"], button:has-text("Authorize")'),
  ]);

  const code = new URL(request.url()).searchParams.get('code')!;

  const res = await fetch(`${baseURL}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code_verifier: verifier,
    }),
  });
  expect(res.status).toBe(200);
  return res.json() as Promise<TokenResponse>;
}

// ---------------------------------------------------------------------------
// OpenID Connect Discovery
// ---------------------------------------------------------------------------

test('GET /.well-known/openid-configuration returns valid OIDC metadata', async ({ baseURL }) => {
  const res = await fetch(`${baseURL}/.well-known/openid-configuration`);
  expect(res.status).toBe(200);
  const doc = await res.json() as Record<string, unknown>;

  expect(doc.issuer).toBe(baseURL);
  expect(doc.authorization_endpoint).toBe(`${baseURL}/authorize`);
  expect(doc.token_endpoint).toBe(`${baseURL}/token`);
  expect(doc.userinfo_endpoint).toBe(`${baseURL}/userinfo`);
  expect(doc.jwks_uri).toBe(`${baseURL}/.well-known/jwks.json`);
  expect(doc.revocation_endpoint).toBe(`${baseURL}/revoke`);
  expect(doc.id_token_signing_alg_values_supported).toEqual(expect.arrayContaining(['RS256']));
  expect(doc.scopes_supported).toEqual(expect.arrayContaining(['openid', 'email', 'profile']));
  expect(doc.response_types_supported).toEqual(expect.arrayContaining(['code']));
  expect(doc.code_challenge_methods_supported).toEqual(expect.arrayContaining(['S256']));
});

test('GET /.well-known/jwks.json returns valid RSA public key', async ({ baseURL }) => {
  const res = await fetch(`${baseURL}/.well-known/jwks.json`);
  expect(res.status).toBe(200);
  const jwks = await res.json() as { keys: Array<Record<string, unknown>> };

  expect(Array.isArray(jwks.keys)).toBe(true);
  expect(jwks.keys.length).toBeGreaterThanOrEqual(1);

  const key = jwks.keys[0];
  expect(key.kty).toBe('RSA');
  expect(key.use).toBe('sig');
  expect(key.alg).toBe('RS256');
  expect(typeof key.kid).toBe('string');
  expect(typeof key.n).toBe('string');  // base64url modulus
  expect(typeof key.e).toBe('string');  // base64url exponent
});

// ---------------------------------------------------------------------------
// /userinfo — unauthenticated paths
// ---------------------------------------------------------------------------

test('GET /userinfo without token returns 401 with WWW-Authenticate header', async ({ baseURL }) => {
  const res = await fetch(`${baseURL}/userinfo`);
  expect(res.status).toBe(401);
  expect(res.headers.get('www-authenticate')).toContain('Bearer');
});

test('GET /userinfo with malformed Authorization header returns 400', async ({ baseURL }) => {
  const res = await fetch(`${baseURL}/userinfo`, {
    headers: { Authorization: 'NotBearer abc123' },
  });
  expect(res.status).toBe(400);
  const body = await res.json() as Record<string, unknown>;
  expect(body.error).toBe('invalid_request');
});

// ---------------------------------------------------------------------------
// /userinfo — authenticated paths
// ---------------------------------------------------------------------------

test('GET /userinfo returns email and profile claims for openid+email+profile scope', async ({ page, baseURL }) => {
  await loginSeeded(page);
  const tokens = await getTokens(page, baseURL!);

  const res = await fetch(`${baseURL}/userinfo`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  expect(res.status).toBe(200);
  expect(res.headers.get('cache-control')).toBe('no-store');

  const body = await res.json() as Record<string, unknown>;
  expect(typeof body.sub).toBe('string');
  expect(body.email).toBe('e2e-seed@example.com');
  expect(body.email_verified).toBe(true);
  expect(body.name).toBe('E2E Test User');
  expect(typeof body.updated_at).toBe('number');
});

test('POST /userinfo returns same claims as GET', async ({ page, baseURL }) => {
  await loginSeeded(page);
  const tokens = await getTokens(page, baseURL!);

  const res = await fetch(`${baseURL}/userinfo`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  expect(res.status).toBe(200);

  const body = await res.json() as Record<string, unknown>;
  expect(typeof body.sub).toBe('string');
  expect(body.email).toBe('e2e-seed@example.com');
  expect(body.email_verified).toBe(true);
  expect(body.name).toBe('E2E Test User');
});

// ---------------------------------------------------------------------------
// id_token
// ---------------------------------------------------------------------------

test('token response includes id_token when openid scope is requested', async ({ page, baseURL }) => {
  await loginSeeded(page);
  const tokens = await getTokens(page, baseURL!);
  expect(tokens.id_token).toBeTruthy();
});

// ---------------------------------------------------------------------------
// Token revocation
// ---------------------------------------------------------------------------

test('POST /revoke makes access token rejected by /userinfo', async ({ page, baseURL }) => {
  await loginSeeded(page);
  const tokens = await getTokens(page, baseURL!);

  // Token works before revocation
  const before = await fetch(`${baseURL}/userinfo`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  expect(before.status).toBe(200);

  // Revoke
  const revoke = await fetch(`${baseURL}/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      token: tokens.access_token,
      token_type_hint: 'access_token',
    }),
  });
  expect(revoke.status).toBe(200);

  // Token is now rejected
  const after = await fetch(`${baseURL}/userinfo`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  expect(after.status).toBe(401);
});
