import { test, expect } from "../../lib/fixtures";
import { loginCaPortal } from "../../lib/fixtures";

test.describe("CA Portal — Audit Log", () => {
  test.beforeEach(async ({ page }) => {
    await loginCaPortal(page, "auditor");
    await page.goto("/audit-log");
  });

  // UC-CA-22: View Audit Log
  test("UC-CA-22: audit log page loads with events table", async ({ page }) => {
    await expect(page.locator("#audit-log-page")).toBeVisible();
    await expect(page.locator("#audit-table")).toBeVisible();
  });

  // UC-CA-22: Filter audit log by action
  test("UC-CA-22: filter by action", async ({ page }) => {
    await page.selectOption("#filter-action", "ceremony_initiated");
    await page.click('#audit-filter button[type="submit"]');

    // Table should update (may be empty if no matching events)
    await expect(page.locator("#audit-table")).toBeVisible();
  });

  // UC-CA-22: Filter by actor DID
  test("UC-CA-22: filter by actor DID", async ({ page }) => {
    await page.fill("#filter-actor", "did:example:admin");
    await page.click('#audit-filter button[type="submit"]');

    await expect(page.locator("#audit-table")).toBeVisible();
  });

  // UC-CA-22: Filter by date range
  test("UC-CA-22: filter by date range", async ({ page }) => {
    const today = new Date().toISOString().split("T")[0];
    await page.fill("#filter-date-from", today);
    await page.fill("#filter-date-to", today);
    await page.click('#audit-filter button[type="submit"]');

    await expect(page.locator("#audit-table")).toBeVisible();
  });
});
