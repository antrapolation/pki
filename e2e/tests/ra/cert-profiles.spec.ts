import { test, expect } from "../../lib/fixtures";
import { loginRaPortal, uniqueName, waitForLiveView } from "../../lib/fixtures";

test.describe("RA Portal — Certificate Profiles", () => {
  test.beforeEach(async ({ page }) => {
    await loginRaPortal(page, "admin");
    await page.goto("/cert-profiles");
    await waitForLiveView(page);
  });

  // UC-RA-06: Create Certificate Profile
  test("UC-RA-06: create TLS server profile", async ({ page }) => {
    const name = uniqueName("TLS-Server");
    await page.fill("#profile-name", name);
    await page.fill("#profile-key-usage", "digitalSignature,keyEncipherment");
    await page.fill("#profile-ext-key-usage", "serverAuth,clientAuth");
    await page.selectOption("#profile-digest-algo", "SHA-256");
    await page.fill("#profile-validity", "365");
    await page.click('#create-profile-form button[type="submit"]');

    await expect(page.locator("#profile-list")).toContainText(name);
  });

  // UC-RA-07: Edit Certificate Profile
  test("UC-RA-07: edit profile validity", async ({ page }) => {
    // Create a profile first
    const name = uniqueName("Edit-Test");
    await page.fill("#profile-name", name);
    await page.fill("#profile-key-usage", "digitalSignature");
    await page.selectOption("#profile-digest-algo", "SHA-256");
    await page.fill("#profile-validity", "365");
    await page.click('#create-profile-form button[type="submit"]');
    await expect(page.locator("#profile-list")).toContainText(name);

    // Click edit
    const row = page.locator(`#profile-list tr`, { hasText: name });
    await row.locator('button:has-text("Edit")').click();

    await expect(page.locator("#edit-profile-form")).toBeVisible();
    await page.fill("#edit-validity", "730");
    await page.click('#edit-profile-form button[type="submit"]');

    await expect(page.locator("#profile-list")).toContainText("730");
  });

  // UC-RA-08: Delete Certificate Profile
  test("UC-RA-08: delete profile", async ({ page }) => {
    const name = uniqueName("Delete-Me");
    await page.fill("#profile-name", name);
    await page.fill("#profile-key-usage", "digitalSignature");
    await page.selectOption("#profile-digest-algo", "SHA-256");
    await page.fill("#profile-validity", "365");
    await page.click('#create-profile-form button[type="submit"]');
    await expect(page.locator("#profile-list")).toContainText(name);

    const row = page.locator(`#profile-list tr`, { hasText: name });
    await row.locator('button:has-text("Delete")').click();

    await expect(page.locator("#profile-list")).not.toContainText(name);
  });
});
