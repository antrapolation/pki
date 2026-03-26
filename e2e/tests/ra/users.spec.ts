import { test, expect } from "../../lib/fixtures";
import { loginRaPortal, uniqueUsername } from "../../lib/fixtures";

test.describe("RA Portal — User Management", () => {
  test.beforeEach(async ({ page }) => {
    await loginRaPortal(page, "admin");
    await page.goto("/users");
    await expect(page.locator("#users-page")).toBeVisible();
  });

  // UC-RA-03: Create RA User
  test("UC-RA-03: create ra_officer user", async ({ page }) => {
    const username = uniqueUsername("officer");
    await page.fill("#user-username", username);
    await page.fill("#user-display-name", "Test RA Officer");
    await page.selectOption("#user-role", "ra_officer");
    await page.click('#create-user-form button[type="submit"]');

    // Verify user appears in table
    await expect(page.locator("#user-list")).toContainText(username);
    await expect(page.locator("#user-list")).toContainText("ra_officer");
  });

  test("UC-RA-03: create ra_admin user", async ({ page }) => {
    const username = uniqueUsername("ra-admin");
    await page.fill("#user-username", username);
    await page.fill("#user-display-name", "Test RA Admin");
    await page.selectOption("#user-role", "ra_admin");
    await page.click('#create-user-form button[type="submit"]');

    await expect(page.locator("#user-list")).toContainText(username);
    await expect(page.locator("#user-list")).toContainText("ra_admin");
  });

  // UC-RA-04: Filter Users by Role
  test("UC-RA-04: filter users by role", async ({ page }) => {
    // Create an ra_officer user first
    const officerUsername = uniqueUsername("officer-filter");
    await page.fill("#user-username", officerUsername);
    await page.fill("#user-display-name", "Officer Filter Test");
    await page.selectOption("#user-role", "ra_officer");
    await page.click('#create-user-form button[type="submit"]');
    await expect(page.locator("#user-list")).toContainText(officerUsername);

    // Filter to ra_officer only
    await page.selectOption("#role-filter", "ra_officer");
    await expect(page.locator("#user-list")).toContainText("ra_officer");

    // Filter to all
    await page.selectOption("#role-filter", "all");
  });

  // UC-RA-05: Suspend (Delete) RA User
  test("UC-RA-05: suspend user removes from list", async ({ page }) => {
    const username = uniqueUsername("suspend-me");
    await page.fill("#user-username", username);
    await page.fill("#user-display-name", "To Suspend");
    await page.selectOption("#user-role", "ra_officer");
    await page.click('#create-user-form button[type="submit"]');
    await expect(page.locator("#user-list")).toContainText(username);

    // Suspend the user
    const userRow = page.locator(`#user-list tr`, { hasText: username });
    await userRow.locator('button:has-text("Suspend")').click();

    // Verify removed from list
    await expect(page.locator("#user-list")).not.toContainText(username);
  });
});
