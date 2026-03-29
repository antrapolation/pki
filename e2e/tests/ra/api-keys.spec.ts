import { test, expect } from "../../lib/fixtures";
import { loginRaPortal, uniqueName, waitForLiveView } from "../../lib/fixtures";

test.describe("RA Portal — API Key Management", () => {
  test.beforeEach(async ({ page }) => {
    await loginRaPortal(page, "admin");
    await page.goto("/api-keys");
    await waitForLiveView(page);
  });

  // UC-RA-10: Create API Key
  test("UC-RA-10: create API key and display raw key", async ({ page }) => {
    const name = uniqueName("test-key");
    await page.fill("#api-key-name", name);
    await page.click('#create-api-key-form button[type="submit"]');

    // Raw key should be displayed once
    await expect(page.locator("#raw-key-display")).toBeVisible();
    const rawKey = await page.locator("#raw-key-value").textContent();
    expect(rawKey).toBeTruthy();
    expect(rawKey!.length).toBeGreaterThan(10);

    // Dismiss raw key display
    await page.click('button:has-text("Dismiss")');
    await expect(page.locator("#raw-key-display")).not.toBeVisible();

    // Key should appear in table
    await expect(page.locator("#api-key-list")).toContainText(name);
    await expect(page.locator("#api-key-list")).toContainText("active");
  });

  // UC-RA-11: Revoke API Key
  test("UC-RA-11: revoke API key", async ({ page }) => {
    // Create a key first
    const name = uniqueName("revoke-me");
    await page.fill("#api-key-name", name);
    await page.click('#create-api-key-form button[type="submit"]');
    await page.click('button:has-text("Dismiss")');

    // Revoke it
    const row = page.locator(`#api-key-list tr`, { hasText: name });
    await row.locator('button:has-text("Revoke")').click();

    // Verify status changed
    await expect(row).toContainText("revoked");
  });
});
