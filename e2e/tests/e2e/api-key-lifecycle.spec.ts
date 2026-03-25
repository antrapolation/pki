import { test, expect, request as playwrightRequest } from "@playwright/test";
import { URLS, SAMPLE_CSR_PEM, uniqueName } from "../../lib/fixtures";

// UC-RA-24 / UC-E2E-08: API Key Lifecycle with CSR Operations
// Combines portal browser interaction (key management) with API calls (CSR submission).
// NOTE: Portal uses mock client, RA Engine API is the real service.
// The mock creates keys locally; the real engine won't recognize them.
// So this test validates the portal lifecycle only, and API calls go to the real engine
// with a test key (may get 401 if no real key exists, which is acceptable).

test.describe("E2E — API Key Lifecycle (UC-RA-24 / UC-E2E-08)", () => {
  test("UC-E2E-08: create keys, revoke key, verify portal state", async ({
    browser,
  }) => {
    const raContext = await browser.newContext({ baseURL: URLS.raPortal });
    const page = await raContext.newPage();

    // Login to RA Portal
    await page.goto("/login");
    await page.fill("#session_username", "admin");
    await page.fill("#session_password", "password123");
    await page.click('button[type="submit"]');
    await page.waitForURL("/");

    // Navigate to API keys page
    await page.goto("/api-keys");
    await expect(page.locator("#api-keys-page")).toBeVisible();

    // Step 1: Create first API key "client-v1"
    const keyName1 = uniqueName("client-v1");
    await page.fill("#api-key-name", keyName1);
    await page.click('#create-api-key-form button[type="submit"]');

    // Capture raw key value
    await expect(page.locator("#raw-key-display")).toBeVisible();
    const rawKeyV1 = await page.locator("#raw-key-value").textContent();
    expect(rawKeyV1).toBeTruthy();
    expect(rawKeyV1!.length).toBeGreaterThan(10);

    // Dismiss the key display
    await page.click('button:has-text("Dismiss")');
    await expect(page.locator("#raw-key-display")).not.toBeVisible();

    // Step 2: Create second API key "client-v2"
    const keyName2 = uniqueName("client-v2");
    await page.fill("#api-key-name", keyName2);
    await page.click('#create-api-key-form button[type="submit"]');

    await expect(page.locator("#raw-key-display")).toBeVisible();
    const rawKeyV2 = await page.locator("#raw-key-value").textContent();
    expect(rawKeyV2).toBeTruthy();

    // Keys should be different
    expect(rawKeyV1).not.toBe(rawKeyV2);

    // Dismiss
    await page.click('button:has-text("Dismiss")');

    // Step 3: Both keys should appear in the table as active
    await expect(page.locator("#api-key-list")).toContainText(keyName1);
    await expect(page.locator("#api-key-list")).toContainText(keyName2);

    // Step 4: Revoke key v1
    const keyV1Row = page.locator("#api-key-list tr", { hasText: keyName1 });
    await keyV1Row.locator('button:has-text("Revoke")').click();

    // Step 5: Verify v1 shows revoked, v2 still active
    await expect(keyV1Row).toContainText("revoked");
    const keyV2Row = page.locator("#api-key-list tr", { hasText: keyName2 });
    await expect(keyV2Row).toContainText("active");

    await raContext.close();
  });
});
