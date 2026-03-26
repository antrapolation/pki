import { test, expect } from "../../lib/fixtures";
import { loginCaPortal, uniqueUsername } from "../../lib/fixtures";

test.describe("CA Portal — User Management", () => {
  test.beforeEach(async ({ page }) => {
    await loginCaPortal(page, "admin");
    await page.goto("/users");
    await expect(page.locator("#users-page")).toBeVisible();
  });

  // UC-CA-03: Create CA User
  test("UC-CA-03: create key_manager user", async ({ page }) => {
    const username = uniqueUsername("km");
    await page.fill("#user-username", username);
    await page.fill("#user-display-name", "Test Key Manager");
    await page.selectOption("#user-role", "key_manager");
    await page.click('#create-user-form button[type="submit"]');

    // Verify user appears in table
    await expect(page.locator("#user-list")).toContainText(username);
    await expect(page.locator("#user-list")).toContainText("key_manager");
  });

  test("UC-CA-03: create auditor user", async ({ page }) => {
    const username = uniqueUsername("auditor");
    await page.fill("#user-username", username);
    await page.fill("#user-display-name", "Test Auditor");
    await page.selectOption("#user-role", "auditor");
    await page.click('#create-user-form button[type="submit"]');

    await expect(page.locator("#user-list")).toContainText(username);
    await expect(page.locator("#user-list")).toContainText("auditor");
  });

  // UC-CA-04: Filter Users by Role
  test("UC-CA-04: filter users by role", async ({ page }) => {
    // Create users of different roles first
    const kmUsername = uniqueUsername("km-filter");
    await page.fill("#user-username", kmUsername);
    await page.fill("#user-display-name", "KM Filter Test");
    await page.selectOption("#user-role", "key_manager");
    await page.click('#create-user-form button[type="submit"]');
    await expect(page.locator("#user-list")).toContainText(kmUsername);

    // Filter to key_manager only
    await page.selectOption("#role-filter", "key_manager");
    await expect(page.locator("#user-list")).toContainText("key_manager");

    // Filter to all
    await page.selectOption("#role-filter", "all");
  });

  // UC-CA-05: Delete (Suspend) CA User
  test("UC-CA-05: delete user removes from list", async ({ page }) => {
    const username = uniqueUsername("delete-me");
    await page.fill("#user-username", username);
    await page.fill("#user-display-name", "To Delete");
    await page.selectOption("#user-role", "key_manager");
    await page.click('#create-user-form button[type="submit"]');
    await expect(page.locator("#user-list")).toContainText(username);

    // Delete the user
    const userRow = page.locator(`#user-list tr`, { hasText: username });
    await userRow.locator('button:has-text("Delete")').click();

    // Verify removed from list
    await expect(page.locator("#user-list")).not.toContainText(username);
  });
});
