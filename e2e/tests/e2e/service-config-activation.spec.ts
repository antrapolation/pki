import { test, expect, request as playwrightRequest } from "@playwright/test";
import { URLS, waitForLiveView } from "../../lib/fixtures";

// UC-E2E-16: Service Config Activation — OCSP/CRL
// Configures services via RA Portal, then verifies validation endpoints respond.

test.describe("E2E — Service Config Activation (UC-E2E-16)", () => {
  test("UC-E2E-16: configure services in portal and verify validation endpoints", async ({
    browser,
  }) => {
    // --- Portal: Configure service endpoints ---
    const raContext = await browser.newContext({ baseURL: URLS.raPortal });
    const page = await raContext.newPage();

    // Login
    await page.goto("/login");
    await page.fill("#session_username", "admin");
    await page.fill("#session_password", "password123");
    await page.click('button[type="submit"]');
    await page.waitForURL("/");
    await waitForLiveView(page);

    // Navigate to service configs and configure OCSP
    await page.goto("/service-configs");
    await waitForLiveView(page);
    await expect(page.locator("#service-configs-page")).toBeVisible();

    await page.selectOption("#service-type", "OCSP Responder");
    await page.fill("#service-port", "4005");
    await page.fill("#service-url", "http://pki-validation:4005");
    await page.click('#configure-service-form button[type="submit"]');
    await expect(page.locator("#config-list")).toContainText("OCSP Responder");

    // Configure CRL
    await page.selectOption("#service-type", "CRL Distribution");
    await page.fill("#service-port", "4005");
    await page.fill("#service-url", "http://pki-validation:4005/crl");
    await page.click('#configure-service-form button[type="submit"]');
    await expect(page.locator("#config-list")).toContainText("CRL Distribution");

    await raContext.close();

    // --- Validation API: Verify endpoints respond ---
    const valCtx = await playwrightRequest.newContext({
      baseURL: URLS.validation,
    });

    // Verify health endpoint
    const healthRes = await valCtx.get("/health");
    expect(healthRes.status()).toBe(200);

    // Verify CRL endpoint returns valid structure
    const crlRes = await valCtx.get("/crl");
    expect(crlRes.status()).toBe(200);
    const crlBody = await crlRes.json();
    expect(crlBody).toHaveProperty("revoked_certificates");
    expect(Array.isArray(crlBody.revoked_certificates)).toBeTruthy();

    // Verify OCSP returns unknown for non-existent cert
    const ocspRes = await valCtx.post("/ocsp", {
      data: { serial_number: "config-test-unknown-cert" },
    });
    expect(ocspRes.status()).toBe(200);
    const ocspBody = await ocspRes.json();
    expect(ocspBody.status).toBe("unknown");

    await valCtx.dispose();
  });

  test("UC-E2E-16: validation health check is available", async () => {
    const valCtx = await playwrightRequest.newContext({
      baseURL: URLS.validation,
    });

    const response = await valCtx.get("/health");
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.status).toMatch(/ok|healthy/);

    await valCtx.dispose();
  });

  test("UC-E2E-16: CRL endpoint returns valid structure", async () => {
    const valCtx = await playwrightRequest.newContext({
      baseURL: URLS.validation,
    });

    const response = await valCtx.get("/crl");
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body).toHaveProperty("revoked_certificates");
    expect(Array.isArray(body.revoked_certificates)).toBeTruthy();

    await valCtx.dispose();
  });

  test("UC-E2E-16: OCSP returns unknown for non-existent certificate", async () => {
    const valCtx = await playwrightRequest.newContext({
      baseURL: URLS.validation,
    });

    const response = await valCtx.post("/ocsp", {
      data: { serial_number: "nonexistent-serial-99999" },
    });
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.status).toBe("unknown");

    await valCtx.dispose();
  });
});
