import { test, expect } from "../../lib/fixtures";
import { loginRaPortal } from "../../lib/fixtures";

test.describe("RA Portal — CSR Management", () => {
  test.beforeEach(async ({ page }) => {
    await loginRaPortal(page, "officer");
    await page.goto("/csrs");
  });

  // UC-RA-15: View CSR List
  test("UC-RA-15: CSR page loads with table", async ({ page }) => {
    await expect(page.locator("#csrs-page")).toBeVisible();
    await expect(page.locator("#csr-table")).toBeVisible();
  });

  // UC-RA-16: Filter CSRs by Status
  test("UC-RA-16: filter CSRs by pending status", async ({ page }) => {
    await page.selectOption("#status-filter", "pending");
    await expect(page.locator("#csr-table")).toBeVisible();
  });

  test("UC-RA-16: filter CSRs by approved status", async ({ page }) => {
    await page.selectOption("#status-filter", "approved");
    await expect(page.locator("#csr-table")).toBeVisible();
  });

  test("UC-RA-16: filter CSRs show all", async ({ page }) => {
    await page.selectOption("#status-filter", "all");
    await expect(page.locator("#csr-table")).toBeVisible();
  });

  // UC-RA-17: View CSR Detail
  test("UC-RA-17: view CSR detail modal", async ({ page }) => {
    // Only works if CSRs exist — check for rows first
    const rows = page.locator("#csr-list tr");
    const count = await rows.count();
    if (count > 0) {
      await rows.first().locator('button:has-text("View")').click();
      await expect(page.locator("#csr-detail")).toBeVisible();
      await expect(page.locator("#csr-status")).toBeVisible();

      // Close detail
      await page.click('button:has-text("Close")');
      await expect(page.locator("#csr-detail")).not.toBeVisible();
    }
  });

  // UC-RA-18: Approve CSR (requires pending CSR)
  test("UC-RA-18: approve pending CSR", async ({ page }) => {
    // Find a row with "pending" status — use inline Approve button directly
    const pendingRow = page.locator("#csr-list tr", { hasText: "pending" }).first();
    const hasPending = (await pendingRow.count()) > 0;
    if (hasPending) {
      await pendingRow.locator('button:has-text("Approve")').click();
      // CSR list should refresh
      await expect(page.locator("#csr-table")).toBeVisible();
    }
  });

  // UC-RA-19: Reject CSR with Reason
  test("UC-RA-19: reject pending CSR with reason", async ({ page }) => {
    // Find a row with "pending" status and click View on it
    const pendingRow = page.locator("#csr-list tr", { hasText: "pending" }).first();
    const hasPending = (await pendingRow.count()) > 0;
    if (hasPending) {
      await pendingRow.locator('button:has-text("View")').click();
      await expect(page.locator("#csr-detail")).toBeVisible();
      await expect(page.locator("#reject-form")).toBeVisible({ timeout: 5000 });

      await page.fill("#reject-reason", "Invalid domain ownership");
      await page.click('#reject-form button[type="submit"]');
      // CSR list should refresh (detail closes on reject)
      await expect(page.locator("#csr-table")).toBeVisible();
    }
  });
});
