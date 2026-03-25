import { test, expect } from "../../lib/fixtures";
import { loginRaPortal } from "../../lib/fixtures";

const PROTECTED_ROUTES = [
  { path: "/", name: "Dashboard" },
  { path: "/users", name: "Users" },
  { path: "/csrs", name: "CSRs" },
  { path: "/cert-profiles", name: "Cert Profiles" },
  { path: "/service-configs", name: "Service Configs" },
  { path: "/api-keys", name: "API Keys" },
];

test.describe("RA Portal — Authorization Enforcement (UC-RA-36)", () => {
  test.describe("Unauthenticated access redirects to /login", () => {
    for (const route of PROTECTED_ROUTES) {
      test(`UC-RA-36: unauthenticated access to ${route.name} (${route.path}) redirects to /login`, async ({
        page,
      }) => {
        // Access protected route without logging in
        const response = await page.goto(route.path);

        // Should redirect to /login
        await expect(page).toHaveURL(/\/login/);

        // Login form should be visible
        await expect(page.locator('form[action="/login"]')).toBeVisible();
      });
    }
  });

  test.describe("Authenticated access succeeds", () => {
    for (const route of PROTECTED_ROUTES) {
      test(`UC-RA-36: authenticated user can access ${route.name} (${route.path})`, async ({
        page,
      }) => {
        // Login first
        await loginRaPortal(page, "admin");

        // Navigate to protected route
        const response = await page.goto(route.path);

        // Should not be redirected to login
        expect(page.url()).not.toMatch(/\/login/);

        // Page should return 200 (LiveView renders)
        expect(response?.status()).toBe(200);

        // Should have LiveView content (phx-* attributes indicate LiveView mounted)
        await expect(
          page.locator("[data-phx-main], [phx-connected], #dashboard, main, [data-phx-session]").first()
        ).toBeVisible({ timeout: 10_000 });
      });
    }
  });
});
