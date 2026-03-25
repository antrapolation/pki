import { test, expect } from "../../lib/fixtures";
import { loginRaPortal } from "../../lib/fixtures";

test.describe("RA Portal — Service Configuration", () => {
  test.beforeEach(async ({ page }) => {
    await loginRaPortal(page, "admin");
    await page.goto("/service-configs");
  });

  // UC-RA-09: Configure OCSP Service
  test("UC-RA-09: configure OCSP responder", async ({ page }) => {
    await page.selectOption("#service-type", "OCSP Responder");
    await page.fill("#service-port", "4005");
    await page.fill("#service-url", "http://ocsp.example.com");
    await page.fill("#service-rate-limit", "1000");
    await page.click('#configure-service-form button[type="submit"]');

    await expect(page.locator("#config-list")).toContainText("OCSP Responder");
  });

  // UC-RA-09: Configure CRL Distribution
  test("UC-RA-09: configure CRL distribution", async ({ page }) => {
    await page.selectOption("#service-type", "CRL Distribution");
    await page.fill("#service-port", "4005");
    await page.fill("#service-url", "http://crl.example.com/crl");
    await page.click('#configure-service-form button[type="submit"]');

    await expect(page.locator("#config-list")).toContainText("CRL Distribution");
  });

  // UC-RA-34: Upsert behavior
  test("UC-RA-34: reconfigure overwrites existing config", async ({ page }) => {
    // First config
    await page.selectOption("#service-type", "TSA");
    await page.fill("#service-port", "4006");
    await page.fill("#service-url", "http://tsa.example.com");
    await page.click('#configure-service-form button[type="submit"]');
    await expect(page.locator("#config-list")).toContainText("TSA");

    // Reconfigure same type
    await page.selectOption("#service-type", "TSA");
    await page.fill("#service-port", "4007");
    await page.fill("#service-url", "http://tsa-new.example.com");
    await page.click('#configure-service-form button[type="submit"]');

    // Should have only one TSA entry, not two
    const tsaRows = page.locator("#config-list tr", { hasText: "TSA" });
    await expect(tsaRows).toHaveCount(1);
  });
});
