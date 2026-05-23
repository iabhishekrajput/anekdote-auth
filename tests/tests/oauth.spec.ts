import { test, expect } from '@playwright/test';
import { loginSeeded } from '../fixtures/auth';
import { clearMailbox } from '../fixtures/mail';
import * as crypto from 'crypto';

// Pre-seeded test client (from e2e/seed.sql)
const CLIENT_ID = 'e2e-test-client';
const CLIENT_SECRET = 'e2e-test-client-secret';
const REDIRECT_URI = 'http://localhost:9999/callback';

function buildPKCE(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
  return { verifier, challenge };
}

function buildAuthorizeURL(
  baseURL: string,
  challenge: string,
  state: string,
  nonce: string,
): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  return `${baseURL}/authorize?${params}`;
}

test.beforeEach(async () => {
  await clearMailbox();
});

test('OAuth consent approve completes authorization_code + PKCE flow', async ({ page, baseURL }) => {
  // Log in as the seeded user first
  await loginSeeded(page);

  const { verifier, challenge } = buildPKCE();
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');

  const authorizeURL = buildAuthorizeURL(baseURL!, challenge, state, nonce);

  // Navigate to /authorize — server renders the consent page
  await page.goto(authorizeURL);
  await expect(page).toHaveURL(/\/authorize/);
  // Consent page has no h2 — verify the Authorize button is visible
  await expect(page.locator('button:has-text("Authorize")')).toBeVisible();

  // Route intercept: abort the redirect to localhost:9999 (nothing runs there).
  // Register before the click so waitForRequest doesn't race.
  await page.route(`${REDIRECT_URI}**`, route => route.abort());

  // Click approve and wait for the browser to attempt the callback redirect.
  const [request] = await Promise.all([
    page.waitForRequest(`${REDIRECT_URI}**`),
    page.click('button[name="accept"][value="true"], button:has-text("Authorize")'),
  ]);

  const redirectedURL = new URL(request.url());

  expect(redirectedURL.searchParams.get('state')).toBe(state);
  const code = redirectedURL.searchParams.get('code');
  expect(code).toBeTruthy();

  // Exchange code for tokens
  const tokenRes = await fetch(`${baseURL}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code!,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code_verifier: verifier,
    }),
  });

  expect(tokenRes.status).toBe(200);
  const tokens = await tokenRes.json() as Record<string, unknown>;
  expect(tokens.access_token).toBeTruthy();
  expect(tokens.token_type).toBe('Bearer');
});

test('OAuth consent deny redirects with error', async ({ page, baseURL }) => {
  await loginSeeded(page);

  const { challenge } = buildPKCE();
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');

  await page.goto(buildAuthorizeURL(baseURL!, challenge, state, nonce));
  await expect(page.locator('button:has-text("Cancel")')).toBeVisible();

  // Route intercept: server redirects to localhost:9999?error=access_denied but nothing
  // runs there. Abort the navigation and capture the URL to assert on the error param.
  await page.route(`${REDIRECT_URI}**`, route => route.abort());

  const [request] = await Promise.all([
    page.waitForRequest(`${REDIRECT_URI}**`),
    page.click('button[name="reject"][value="true"], button:has-text("Cancel")'),
  ]);

  const callbackURL = request.url();
  expect(callbackURL).toContain('error=access_denied');
  expect(page.url()).not.toContain('/account');
});
