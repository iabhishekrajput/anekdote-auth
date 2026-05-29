import { test, expect } from '@playwright/test';
import { loginSeeded } from '../fixtures/auth';

test.describe('custom claims UI', () => {
  test.beforeEach(async ({ page }) => {
    await loginSeeded(page);
    await page.goto('/account/orgs/e2e-test-org/clients/e2e-test-client/claims');
  });

  test('destinations select persists access_token + userinfo', async ({ page }) => {
    const key = `https://example.com/e2e_${Date.now()}`;
    await page.click('[data-add-claim-row]');
    const row = page.locator('#claims-rows tr:not([data-claims-template]):not([aria-hidden])').last();
    await row.locator('input[name="key[]"]').fill(key);
    await row.locator('select[name="type[]"]').selectOption('string');
    await row.locator('[name="value[]"]').fill('enterprise');
    await row.locator('select[name="destination[]"]').selectOption('access_token,userinfo');
    await page.getByRole('button', { name: 'Save claims' }).click();
    await expect(page.locator('[data-testid="alert-success"]')).toBeVisible();
    // Assert against the persisted row matching our key — not .last(), which would
    // catch the hidden template row (always "token") or another claim, since rows
    // render ordered by key, not insertion order.
    const savedRow = page.locator('#claims-rows tr', {
      has: page.locator(`input[name="key[]"][value="${key}"]`),
    });
    await expect(savedRow.locator('select[name="destination[]"]')).toHaveValue('access_token,userinfo');
  });

  test('namespace rejection is shown inline before submit', async ({ page }) => {
    await page.click('[data-add-claim-row]');
    const row = page.locator('#claims-rows tr:not([data-claims-template]):not([aria-hidden])').last();
    await row.locator('input[name="key[]"]').fill('tier');
    await row.locator('[name="value[]"]').fill('enterprise');
    await page.getByRole('button', { name: 'Save claims' }).click();
    await expect(row.locator('[data-row-error]')).toContainText('https://');
  });
});
