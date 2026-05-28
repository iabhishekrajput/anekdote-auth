import { type Page, expect } from '@playwright/test';

/** Generates a unique test email address that cannot collide across runs. */
export function uniqueEmail(): string {
  return `e2e-${crypto.randomUUID()}@example.com`;
}

/** Generates a unique username that cannot collide across runs. */
export function uniqueUsername(): string {
  return `user_${crypto.randomUUID().replace(/-/g, '').substring(0, 10)}`;
}

export class RegisterPage {
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto('/register');
  }

  async fill(name: string, email: string, password: string, username = uniqueUsername()) {
    await this.page.fill('#name', name);
    await this.page.fill('#username', username);
    await this.page.fill('#email', email);
    await this.page.fill('#password', password);
  }

  async submit() {
    await this.page.click('[data-testid="submit-register"]');
  }

  async register(name: string, email: string, password: string, username = uniqueUsername()) {
    await this.goto();
    await this.fill(name, email, password, username);
    await this.submit();
  }

  async errorAlert() {
    return this.page.locator('[data-testid="alert-error"]');
  }
}

export class VerifyEmailPage {
  constructor(private page: Page) {}

  /** Fill the OTP input and submit the verify form (scoped to avoid the resend form). */
  async submitOTP(otp: string) {
    await this.page.fill('#otp', otp);
    await this.page.click('[data-testid="submit-verify"]');
  }

  async clickResend() {
    // Resend form uses a plain <button> with no testid — select by action
    await this.page.click('form[action="/verify-email/resend"] button[type="submit"]');
  }

  async errorAlert() {
    return this.page.locator('[data-testid="alert-error"]');
  }
}

export class LoginPage {
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto('/login');
  }

  async fill(email: string, password: string) {
    await this.page.fill('#email', email);
    await this.page.fill('#password', password);
  }

  async submit() {
    await this.page.click('[data-testid="submit-login"]');
  }

  async login(email: string, password: string) {
    await this.goto();
    await this.fill(email, password);
    await this.submit();
  }

  async errorAlert() {
    return this.page.locator('[data-testid="alert-error"]');
  }
}

export class ForgotPasswordPage {
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto('/forgot-password');
  }

  async requestReset(email: string) {
    await this.goto();
    await this.page.fill('#email', email);
    await this.page.click('[data-testid="submit-forgot-password"]');
  }

  async successAlert() {
    return this.page.locator('[data-testid="alert-success"]');
  }
}

export class ResetPasswordPage {
  constructor(private page: Page) {}

  async goto(url: string) {
    await this.page.goto(url);
  }

  async setNewPassword(password: string) {
    await this.page.fill('#password', password);
    await this.page.click('[data-testid="submit-reset-password"]');
  }

  async successAlert() {
    return this.page.locator('[data-testid="alert-success"]');
  }
}

/** Log in with the pre-seeded E2E user and return to /account. */
export async function loginSeeded(page: Page) {
  const login = new LoginPage(page);
  await login.login('e2e-seed@example.com', 'TestPassword1!');
  await expect(page).toHaveURL('/account');
}
