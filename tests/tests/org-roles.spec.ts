import { test, expect } from '@playwright/test';
import { loginSeeded } from '../fixtures/auth';

const ORG_SLUG = 'e2e-test-org';
const MEMBER_EMAIL = 'e2e-member@example.com';

test.describe('org role management', () => {
  test.beforeEach(async ({ page }) => {
    await loginSeeded(page);
    await page.goto(`/account/orgs/${ORG_SLUG}`);
  });

  test('role select uses data-autosubmit (no inline onchange)', async ({ page }) => {
    const select = page.locator('select[name="role"]').first();
    await expect(select).toHaveAttribute('data-autosubmit');
    // Verify the inline onchange attribute is absent — it is a CSP violation
    const onchange = await select.getAttribute('onchange');
    expect(onchange).toBeNull();
  });

  test('remove button uses data-confirm-email (no inline onclick)', async ({ page }) => {
    const removeBtn = page.locator(`button[data-confirm-email="${MEMBER_EMAIL}"]`);
    await expect(removeBtn).toBeVisible();
    const onclick = await removeBtn.getAttribute('onclick');
    expect(onclick).toBeNull();
  });

  test('changing role dropdown submits and shows success message', async ({ page }) => {
    const select = page.locator('select[name="role"]').first();

    // Change the member's role from member → viewer
    await select.selectOption('viewer');

    // Expect navigation to the same org detail page with a success message
    await expect(page).toHaveURL(new RegExp(`/account/orgs/${ORG_SLUG}`));
    const successAlert = page.locator('[data-testid="alert-success"]');
    await expect(successAlert).toBeVisible({ timeout: 5000 });

    // Restore to member so subsequent runs start clean
    const selectAfter = page.locator('select[name="role"]').first();
    await selectAfter.selectOption('member');
    await expect(page).toHaveURL(new RegExp(`/account/orgs/${ORG_SLUG}`));
  });

  test('remove button shows confirm dialog and cancelling leaves member in list', async ({ page }) => {
    const removeBtn = page.locator(`button[data-confirm-email="${MEMBER_EMAIL}"]`);
    await expect(removeBtn).toBeVisible();

    // Intercept the confirm dialog and dismiss it (cancel)
    page.on('dialog', async (dialog) => {
      expect(dialog.message()).toContain(MEMBER_EMAIL);
      await dialog.dismiss();
    });

    await removeBtn.click();

    // Member should still be in the table
    await expect(page.getByText(MEMBER_EMAIL)).toBeVisible();
  });
});
