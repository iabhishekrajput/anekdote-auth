import { defineConfig, devices } from '@playwright/test';

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:8080';

export default defineConfig({
  testDir: './tests',
  timeout: 30_000,
  expect: { timeout: 10_000 },

  // Serial: shared Postgres/Redis/Mailpit cannot handle parallel isolation
  workers: 1,
  retries: process.env.CI ? 1 : 0,

  reporter: process.env.CI ? 'github' : 'list',

  use: {
    baseURL: BASE_URL,
    // Full browser context so CSRF cookie + token pairing works naturally
    browserName: 'chromium',
    headless: true,
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
    { name: 'mobile-chrome', use: { ...devices['Pixel 5'] } },
  ],

  // Start the auth server before tests, wait for /readyz (checks DB + Redis).
  // Env vars are enumerated explicitly so the server gets the right values
  // regardless of how Playwright propagates process.env to the spawned child.
  webServer: {
    command: 'cd .. && E2E=true ./bin/auth-server',
    url: `${BASE_URL}/readyz`,
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
    env: {
      PORT:                    process.env.PORT                    || '8080',
      APP_URL:                 process.env.APP_URL                 || 'http://localhost:8080',
      APP_ENV:                 process.env.APP_ENV                 || 'test',
      DB_DSN:                  process.env.DB_DSN                  || 'postgres://authuser:authpassword@localhost:5432/authdb?sslmode=disable',
      REDIS_URL:               process.env.REDIS_URL               || 'redis://localhost:6379/0',
      REDIS_ENCRYPTION_KEY:    process.env.REDIS_ENCRYPTION_KEY    || '',
      RSA_PRIVATE_KEY_PATH:    process.env.RSA_PRIVATE_KEY_PATH    || 'certs/private.pem',
      RSA_PUBLIC_KEY_PATH:     process.env.RSA_PUBLIC_KEY_PATH     || 'certs/public.pem',
      SMTP_HOST:               process.env.SMTP_HOST               || 'localhost',
      SMTP_PORT:               process.env.SMTP_PORT               || '1025',
      SMTP_USERNAME:           process.env.SMTP_USERNAME           || 'test',
      SMTP_PASSWORD:           process.env.SMTP_PASSWORD           || 'test',
      SMTP_FROM:               process.env.SMTP_FROM               || 'noreply@anekdoteauth.local',
      SMTP_INSECURE_SKIP_VERIFY: process.env.SMTP_INSECURE_SKIP_VERIFY || 'true',
    },
  },
});
