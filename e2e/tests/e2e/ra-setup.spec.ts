import { test, expect } from "../../lib/fixtures";
import { loginRaPortal, uniqueUsername, uniqueName, waitForLiveView } from "../../lib/fixtures";

test.describe("E2E — RA Setup from Scratch (UC-E2E-10)", () => {
  test("UC-E2E-10: full RA initial setup", async ({ page }) => {
    // 1. Login as RA Admin
    await loginRaPortal(page, "admin");
    await expect(page.locator("#dashboard")).toBeVisible();

    // 2. Create RA officer
    await page.goto("/users");
    await waitForLiveView(page);
    const officerUsername = uniqueUsername("ra-officer");
    await page.fill("#user-username", officerUsername);
    await page.fill("#user-display-name", "RA Officer");
    await page.selectOption("#user-role", "ra_officer");
    await page.click('#create-user-form button[type="submit"]');
    await expect(page.locator("#user-list")).toContainText(officerUsername);

    // 3. Create cert profile
    await page.goto("/cert-profiles");
    await waitForLiveView(page);
    const profileName = uniqueName("TLS-Server");
    await page.fill("#profile-name", profileName);
    await page.fill("#profile-key-usage", "digitalSignature,keyEncipherment");
    await page.fill("#profile-ext-key-usage", "serverAuth");
    await page.selectOption("#profile-digest-algo", "SHA-256");
    await page.fill("#profile-validity", "365");
    await page.click('#create-profile-form button[type="submit"]');
    await expect(page.locator("#profile-list")).toContainText(profileName);

    // 4-5. Configure services
    await page.goto("/service-configs");
    await waitForLiveView(page);
    await page.selectOption("#service-type", "OCSP Responder");
    await page.fill("#service-port", "4005");
    await page.fill("#service-url", "http://pki-validation:4005/ocsp");
    await page.click('#configure-service-form button[type="submit"]');
    await expect(page.locator("#config-list")).toContainText("OCSP");

    // 6. Create API key
    await page.goto("/api-keys");
    await waitForLiveView(page);
    await page.fill("#api-key-name", uniqueName("integration-key"));
    await page.click('#create-api-key-form button[type="submit"]');
    await expect(page.locator("#raw-key-display")).toBeVisible();

    // Capture raw key
    const rawKey = await page.locator("#raw-key-value").textContent();
    expect(rawKey).toBeTruthy();
    await page.click('button:has-text("Dismiss")');

    // 7. Verify dashboard reflects setup
    await page.goto("/");
    await waitForLiveView(page);
    await expect(page.locator("#dashboard")).toBeVisible();
  });
});
