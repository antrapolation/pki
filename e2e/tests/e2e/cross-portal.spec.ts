import { test, expect, type Browser } from "@playwright/test";
import { URLS, logoutPortal } from "../../lib/fixtures";

test.describe("E2E — Cross-Portal (UC-E2E-12)", () => {
  // UC-E2E-12: Sessions are independent across portals
  test("UC-E2E-12: CA and RA portals have independent sessions", async ({
    browser,
  }) => {
    // Open CA portal in one context
    const caContext = await browser.newContext({ baseURL: URLS.caPortal });
    const caPage = await caContext.newPage();
    await caPage.goto("/login");
    await expect(caPage).toHaveURL(/login/);
    await caPage.fill("#session_username", "admin");
    await caPage.fill("#session_password", "password123");
    await caPage.click('button[type="submit"]');
    await caPage.waitForURL("/");
    await expect(caPage.locator("#dashboard")).toBeVisible();

    // Open RA portal in separate context
    const raContext = await browser.newContext({ baseURL: URLS.raPortal });
    const raPage = await raContext.newPage();
    await raPage.goto("/login");
    await expect(raPage).toHaveURL(/login/);
    await raPage.fill("#session_username", "admin");
    await raPage.fill("#session_password", "password123");
    await raPage.click('button[type="submit"]');
    await raPage.waitForURL("/");
    await expect(raPage.locator("#dashboard")).toBeVisible();

    // Both are logged in independently
    await caPage.goto("/users");
    await expect(caPage.locator("#users-page")).toBeVisible();

    await raPage.goto("/csrs");
    await expect(raPage.locator("#csrs-page")).toBeVisible();

    // Logout from CA portal doesn't affect RA portal
    await logoutPortal(caPage);

    // RA portal still logged in
    await raPage.goto("/cert-profiles");
    await expect(raPage.locator("#cert-profiles-page")).toBeVisible();

    await caContext.close();
    await raContext.close();
  });
});
