import { test, expect } from "../../lib/fixtures";

test.describe("CA Portal — Bootstrap Setup", () => {
  // UC-CA-00B: Setup page blocked after initial setup (redirects to /login)
  test("UC-CA-00B: setup page redirects to login when already configured", async ({ page }) => {
    await page.goto("/setup");

    // Should redirect to /login since system is already configured
    await expect(page).toHaveURL(/login/);
  });

  // UC-CA-00B: POST to setup also blocked when already configured
  test("UC-CA-00B: POST to setup rejected when already configured", async ({ request }) => {
    const response = await request.post("/setup", {
      form: {
        "setup[username]": "hacker",
        "setup[display_name]": "Hacker",
        "setup[password]": "password123",
        "setup[password_confirmation]": "password123",
      },
    });

    // Should be blocked: 302 redirect to /login, or 403 from CSRF protection
    expect([302, 403]).toContain(response.status());
  });
});
