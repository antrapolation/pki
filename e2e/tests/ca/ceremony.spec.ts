import { test, expect } from "../../lib/fixtures";
import { loginCaPortal, waitForLiveView } from "../../lib/fixtures";

test.describe("CA Portal — Key Ceremony", () => {
  test.beforeEach(async ({ page }) => {
    await loginCaPortal(page, "key_manager");
  });

  // UC-CA-08: Initiate Synchronous Key Ceremony
  test("UC-CA-08: initiate sync ceremony with RSA-4096", async ({ page }) => {
    // First ensure a keystore exists
    await page.goto("/keystores");
    await waitForLiveView(page);
    await page.selectOption("#keystore-type", "software");
    await page.click('#configure-keystore-form button[type="submit"]');
    await expect(page.locator("#keystore-list")).toContainText("software");

    // Now initiate ceremony
    await page.goto("/ceremony");
    await waitForLiveView(page);
    await expect(page.locator("#initiate-ceremony-form")).toBeVisible();

    await page.selectOption("#ceremony-algorithm", "RSA-4096");
    // Select the first available keystore
    await page.locator("#ceremony-keystore").selectOption({ index: 0 });
    await page.fill("#ceremony-k", "2");
    await page.fill("#ceremony-n", "3");
    await page.click('#initiate-ceremony-form button[type="submit"]');

    // Verify ceremony status displayed
    await expect(page.locator("#ceremony-status")).toBeVisible({ timeout: 15000 });
    await expect(page.locator("#ceremony-state")).toContainText(/initiated/i, { timeout: 15000 });
  });

  // UC-CA-09: Initiate ceremony with PQC algorithm
  test("UC-CA-09: initiate ceremony with ECC-P256", async ({ page }) => {
    await page.goto("/keystores");
    await waitForLiveView(page);
    await page.selectOption("#keystore-type", "software");
    await page.click('#configure-keystore-form button[type="submit"]');

    await page.goto("/ceremony");
    await waitForLiveView(page);
    await page.selectOption("#ceremony-algorithm", "ECC-P256");
    await page.locator("#ceremony-keystore").selectOption({ index: 0 });
    await page.fill("#ceremony-k", "2");
    await page.fill("#ceremony-n", "3");
    await page.click('#initiate-ceremony-form button[type="submit"]');

    await expect(page.locator("#ceremony-state")).toContainText(/initiated/i, { timeout: 15000 });
  });

  // UC-CA-08: Ceremony appears in history table
  test("UC-CA-08: ceremony appears in history", async ({ page }) => {
    await page.goto("/ceremony");
    await waitForLiveView(page);
    await expect(page.locator("#ceremony-table")).toBeVisible();
    await expect(page.locator("#ceremony-list")).toBeVisible();
  });
});
