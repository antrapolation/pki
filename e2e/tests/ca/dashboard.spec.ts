import { test, expect } from "../../lib/fixtures";
import { loginCaPortal } from "../../lib/fixtures";

test.describe("CA Portal — Dashboard", () => {
  test.beforeEach(async ({ page }) => {
    await loginCaPortal(page, "admin");
  });

  // UC-CA-02: View Dashboard
  test("UC-CA-02: dashboard displays engine status", async ({ page }) => {
    await expect(page.locator("#status-card")).toBeVisible();
    await expect(page.locator("#engine-status")).toBeVisible();
  });

  test("UC-CA-02: dashboard displays key count", async ({ page }) => {
    await expect(page.locator("#key-summary")).toBeVisible();
    await expect(page.locator("#key-count")).toBeVisible();
  });

  test("UC-CA-02: dashboard displays recent ceremonies", async ({ page }) => {
    await expect(page.locator("#recent-ceremonies")).toBeVisible();
  });

  test("UC-CA-02: dashboard has quick action links", async ({ page }) => {
    await expect(page.locator("#quick-actions")).toBeVisible();
    await expect(page.locator('a[href="/users"]')).toBeVisible();
    await expect(page.locator('a[href="/keystores"]')).toBeVisible();
    await expect(page.locator('a[href="/ceremony"]')).toBeVisible();
  });
});
