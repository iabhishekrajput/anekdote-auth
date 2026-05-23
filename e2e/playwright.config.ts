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
  ],

  // Start the auth server before tests, wait for /readyz (checks DB + Redis)
  webServer: {
    command: 'cd .. && E2E=true ./bin/auth-server',
    url: `${BASE_URL}/readyz`,
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
    env: {
      // Load from .env.e2e if present; individual vars below override
      PORT: '8080',
      APP_ENV: 'test',
      SMTP_INSECURE_SKIP_VERIFY: 'true',
    },
  },
});
