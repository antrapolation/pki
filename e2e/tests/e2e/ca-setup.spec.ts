import { test, expect } from "@playwright/test";
import { URLS, uniqueUsername as uniqueDid } from "../../lib/fixtures";

test.describe("E2E — CA Setup from Scratch (UC-E2E-09)", () => {
  test("UC-E2E-09: full CA initial setup", async ({ browser }) => {
    const context = await browser.newContext({ baseURL: URLS.caPortal });
    const page = await context.newPage();

    // 1. Login as CA Admin
    await page.goto("/login");
    await page.fill("#session_username", "admin");
    await page.fill("#session_password", "password123");
    await page.click('button[type="submit"]');
    await page.waitForURL("/");
    await expect(page.locator("#dashboard")).toBeVisible();

    // 2-4. Create 3 key manager users
    await page.goto("/users");
    for (let i = 1; i <= 3; i++) {
      const kmDid = uniqueDid(`km-${i}`);
      await page.fill("#user-did", kmDid);
      await page.fill("#user-display-name", `Key Manager ${i}`);
      await page.selectOption("#user-role", "key_manager");
      await page.click('#create-user-form button[type="submit"]');
      await expect(page.locator("#user-list")).toContainText(kmDid);
    }

    // 5. Create auditor
    const auditorDid = uniqueDid("auditor");
    await page.fill("#user-did", auditorDid);
    await page.fill("#user-display-name", "Auditor");
    await page.selectOption("#user-role", "auditor");
    await page.click('#create-user-form button[type="submit"]');
    await expect(page.locator("#user-list")).toContainText(auditorDid);

    // 6. Configure software keystore
    await page.goto("/keystores");
    await page.selectOption("#keystore-type", "software");
    await page.click('#configure-keystore-form button[type="submit"]');
    await expect(page.locator("#keystore-list")).toContainText("software");

    // 7. Initiate ceremony
    await page.goto("/ceremony");
    await page.selectOption("#ceremony-algorithm", "RSA-4096");
    await page.locator("#ceremony-keystore").selectOption({ index: 0 });
    await page.fill("#ceremony-k", "2");
    await page.fill("#ceremony-n", "3");
    await page.click('#initiate-ceremony-form button[type="submit"]');
    await expect(page.locator("#ceremony-state")).toContainText(/initiated/i);

    // 8. Verify dashboard reflects setup
    await page.goto("/");
    await expect(page.locator("#dashboard")).toBeVisible();

    await context.close();
  });
});
