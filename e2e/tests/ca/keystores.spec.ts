import { test, expect } from "../../lib/fixtures";
import { loginCaPortal } from "../../lib/fixtures";

test.describe("CA Portal — Keystore Management", () => {
  test.beforeEach(async ({ page }) => {
    await loginCaPortal(page, "key_manager");
    await page.goto("/keystores");
  });

  // UC-CA-06: Configure Software Keystore
  test("UC-CA-06: configure software keystore", async ({ page }) => {
    await page.selectOption("#keystore-type", "software");
    await page.click('#configure-keystore-form button[type="submit"]');

    await expect(page.locator("#keystore-list")).toContainText("software");
    await expect(page.locator("#keystore-list")).toContainText("active");
  });

  // UC-CA-07: Configure HSM Keystore
  test("UC-CA-07: configure HSM keystore", async ({ page }) => {
    await page.selectOption("#keystore-type", "hsm");
    await page.click('#configure-keystore-form button[type="submit"]');

    await expect(page.locator("#keystore-list")).toContainText("hsm");
    await expect(page.locator("#keystore-list")).toContainText("active");
  });
});
