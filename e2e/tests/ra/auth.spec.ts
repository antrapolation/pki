import { test, expect } from "../../lib/fixtures";
import { loginRaPortal, logoutPortal } from "../../lib/fixtures";

test.describe("RA Portal — Authentication", () => {
  // UC-RA-01: Login
  test("UC-RA-01: login with valid username and password", async ({ page }) => {
    await page.goto("/login");
    await page.fill("#session_username", "admin");
    await page.fill("#session_password", "password123");
    await page.click('button[type="submit"]');

    await page.waitForURL("/");
    await expect(page.locator("#dashboard")).toBeVisible();
  });

  // UC-RA-29: Logout
  test("UC-RA-29: logout clears session", async ({ page }) => {
    await loginRaPortal(page, "admin");
    await logoutPortal(page);

    await page.goto("/csrs");
    await expect(page).toHaveURL(/login/);
  });
});
