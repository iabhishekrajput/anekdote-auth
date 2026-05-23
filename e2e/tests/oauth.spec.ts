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
  await expect(page.locator('h2')).toContainText(/authorize|allow|E2E Test Client/i);

  // Intercept the redirect to our callback before clicking approve
  const callbackPromise = page.waitForURL(`${REDIRECT_URI}**`).catch(() => null);

  // Click the approve / Allow button
  await page.click('button[name="action"][value="approve"], button:has-text("Allow"), input[value="approve"]');

  // Wait for redirect to the callback URI with the code
  await callbackPromise;
  const redirectedURL = new URL(page.url());

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
  await expect(page).toHaveURL(/\/authorize/);

  // Click the deny / Cancel button
  await page.click('button[name="action"][value="deny"], button:has-text("Deny"), button:has-text("Cancel"), a:has-text("Cancel")');

  // Server should redirect back with error=access_denied or to the access-denied page
  await page.waitForURL(/(access.?denied|error=access_denied)/i);
  // Just verify we are not on /account (not logged in or consent not granted)
  expect(page.url()).not.toContain('/account');
});
