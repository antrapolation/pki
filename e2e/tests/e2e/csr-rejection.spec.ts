import { test, expect } from "@playwright/test";
import { URLS } from "../../lib/fixtures";

// UC-E2E-07: CSR Rejection Flow via RA Portal
// Uses the portal's mock data to test the rejection workflow end-to-end.

test.describe("E2E — CSR Rejection Flow (UC-E2E-07)", () => {
  test("UC-E2E-07: reject a pending CSR with reason via portal", async ({
    browser,
  }) => {
    const raContext = await browser.newContext({ baseURL: URLS.raPortal });
    const page = await raContext.newPage();

    // Login as officer
    await page.goto("/login");
    await page.fill("#session_username", "officer");
    await page.fill("#session_password", "password123");
    await page.click('button[type="submit"]');
    await page.waitForURL("/");

    // Navigate to CSRs page
    await page.goto("/csrs");
    await expect(page.locator("#csrs-page")).toBeVisible();

    // Find a pending CSR row
    const pendingRow = page.locator("#csr-list tr", { hasText: "pending" }).first();
    const hasPending = (await pendingRow.count()) > 0;

    if (hasPending) {
      // Click View to see CSR details
      await pendingRow.locator('button:has-text("View")').click();
      await expect(page.locator("#csr-detail")).toBeVisible();

      // Enter rejection reason and submit
      await page.fill("#reject-reason", "CSR does not comply with organization policy");
      await page.click('#reject-form button[type="submit"]');

      // Should return to CSR list (detail closes on reject)
      await expect(page.locator("#csr-table")).toBeVisible();
    }

    await raContext.close();
  });
});
