import { test, expect } from '@playwright/test';
import {
  uniqueEmail,
  RegisterPage,
  VerifyEmailPage,
  LoginPage,
  ForgotPasswordPage,
  ResetPasswordPage,
  loginSeeded,
} from '../fixtures/auth';
import { clearMailbox, waitForOTP, waitForResetLink } from '../fixtures/mail';

test.beforeEach(async () => {
  await clearMailbox();
});

// ---------------------------------------------------------------------------
// Register → OTP verify
// ---------------------------------------------------------------------------

test('register and verify email', async ({ page }) => {
  const email = uniqueEmail();
  const register = new RegisterPage(page);
  const verify = new VerifyEmailPage(page);

  await register.register('Test User', email, 'TestPassword1!');

  // Server redirects to /verify-email after registration
  await expect(page).toHaveURL(/\/verify-email/);

  const otp = await waitForOTP(email);
  await verify.submitOTP(otp);

  // After verification the server creates a session and redirects to /account
  await expect(page).toHaveURL('/account');
});

test('register with duplicate email shows error', async ({ page }) => {
  const register = new RegisterPage(page);
  // Use the seeded user's email — guaranteed to already exist
  await register.register('Dup User', 'e2e-seed@example.com', 'TestPassword1!');
  await expect(await register.errorAlert()).toBeVisible();
});

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

test('login with valid credentials', async ({ page }) => {
  const login = new LoginPage(page);
  await login.login('e2e-seed@example.com', 'TestPassword1!');
  await expect(page).toHaveURL('/account');
});

test('login with wrong password shows error', async ({ page }) => {
  const login = new LoginPage(page);
  await login.login('e2e-seed@example.com', 'WrongPassword99!');
  await expect(await login.errorAlert()).toBeVisible();
  await expect(page).toHaveURL('/login');
});

test('login with unknown email shows error', async ({ page }) => {
  const login = new LoginPage(page);
  await login.login('nobody@example.com', 'TestPassword1!');
  await expect(await login.errorAlert()).toBeVisible();
});

test('login is rate-limited after 5 failed attempts', async ({ page }) => {
  // Use a unique email so this test does not lock the seeded user
  const email = uniqueEmail();
  const login = new LoginPage(page);

  // Navigate once — submitting multiple times reuses the same page/session and
  // avoids burning the 10 req/min per-IP middleware limit with repeated GETs.
  await login.goto();
  for (let i = 0; i < 5; i++) {
    await login.fill(email, 'WrongPassword99!');
    await login.submit();
    await expect(page.locator('[data-testid="alert-error"]')).toBeVisible();
  }

  // 6th attempt: per-email lockout (5 failed logins) kicks in
  await login.fill(email, 'WrongPassword99!');
  await login.submit();
  await expect(page.locator('[data-testid="alert-error"]')).toContainText('locked');
});

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

test('logout clears session and redirects to login', async ({ page }) => {
  await loginSeeded(page);
  await page.click('form[action="/logout"] button[type="submit"]');
  await expect(page).toHaveURL('/login');

  // Navigating to a protected page should redirect back to login
  await page.goto('/account');
  await expect(page).toHaveURL(/\/login/);
});

// ---------------------------------------------------------------------------
// Forgot / reset password
// ---------------------------------------------------------------------------

test('forgot password sends email and reset link works', async ({ page }) => {
  const email = uniqueEmail();
  const register = new RegisterPage(page);
  const verify = new VerifyEmailPage(page);

  // Register and verify a fresh user so we have a reset target
  await register.register('Reset User', email, 'TestPassword1!');
  await expect(page).toHaveURL(/\/verify-email/);
  const otp = await waitForOTP(email);
  await verify.submitOTP(otp);
  await expect(page).toHaveURL('/account');

  // Log out so we can test the reset flow
  await page.click('form[action="/logout"] button[type="submit"]');

  await clearMailbox();
  const forgot = new ForgotPasswordPage(page);
  await forgot.requestReset(email);
  await expect(await forgot.successAlert()).toBeVisible();

  const resetURL = await waitForResetLink(email);
  const reset = new ResetPasswordPage(page);
  await reset.goto(resetURL);
  await reset.setNewPassword('NewPassword2!');
  await expect(await reset.successAlert()).toBeVisible();

  // Login with new password
  const login = new LoginPage(page);
  await login.login(email, 'NewPassword2!');
  await expect(page).toHaveURL('/account');
});

test('expired OTP shows error and resend works', async ({ page }) => {
  const email = uniqueEmail();
  const register = new RegisterPage(page);
  const verify = new VerifyEmailPage(page);

  await register.register('Resend User', email, 'TestPassword1!');
  await expect(page).toHaveURL(/\/verify-email/);

  // Submit wrong code
  await verify.submitOTP('000000');
  await expect(await verify.errorAlert()).toBeVisible();

  // Resend and verify with the new OTP
  await clearMailbox();
  await verify.clickResend();
  const freshOTP = await waitForOTP(email);
  await verify.submitOTP(freshOTP);
  await expect(page).toHaveURL('/account');
});
