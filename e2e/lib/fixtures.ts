import { test as base, expect, type Page, type APIRequestContext } from "@playwright/test";

// Shared test URLs
export const URLS = {
  caPortal: process.env.CA_PORTAL_URL || "http://localhost:4002",
  caApi: process.env.CA_ENGINE_URL || "http://localhost:4001",
  raPortal: process.env.RA_PORTAL_URL || "http://localhost:4004",
  raApi: process.env.RA_ENGINE_URL || "http://localhost:4003",
  validation: process.env.VALIDATION_URL || "http://localhost:4005",
};

// Test data generators
export function uniqueUsername(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export function uniqueName(prefix: string): string {
  return `${prefix}-${Date.now()}`;
}

// Wait for Phoenix LiveView WebSocket to connect and become interactive.
// The [data-phx-main] element gets .phx-connected once the socket is up.
export async function waitForLiveView(page: Page): Promise<void> {
  await page.locator("[data-phx-main].phx-connected").waitFor({ timeout: 10_000 });
}

// CA Portal helpers
export async function loginCaPortal(
  page: Page,
  username: string,
  password: string = "password123"
): Promise<void> {
  await page.goto("/login");
  await page.fill("#session_username", username);
  await page.fill("#session_password", password);
  await page.click('button[type="submit"]');
  await page.waitForURL("/");
  await waitForLiveView(page);
}

// RA Portal helpers
export async function loginRaPortal(
  page: Page,
  username: string,
  password: string = "password123"
): Promise<void> {
  await page.goto("/login");
  await page.fill("#session_username", username);
  await page.fill("#session_password", password);
  await page.click('button[type="submit"]');
  await page.waitForURL("/");
  await waitForLiveView(page);
}

// Logout helper (no logout button in portal templates, must use DELETE /logout)
export async function logoutPortal(page: Page): Promise<void> {
  await page.evaluate(() => {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/logout';
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = '_method';
    input.value = 'delete';
    const csrf = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
    const csrfInput = document.createElement('input');
    csrfInput.type = 'hidden';
    csrfInput.name = '_csrf_token';
    csrfInput.value = csrf;
    form.appendChild(input);
    form.appendChild(csrfInput);
    document.body.appendChild(form);
    form.submit();
  });
  await page.waitForURL(/login/);
}

// RA API helpers
export async function createApiKey(
  request: APIRequestContext,
  name: string
): Promise<{ rawKey: string; keyId: number }> {
  // This would be done through the portal or a setup endpoint
  // For now, return a placeholder — actual implementation depends on API
  return { rawKey: "placeholder", keyId: 0 };
}

export async function submitCsr(
  request: APIRequestContext,
  apiKey: string,
  csrPem: string,
  certProfileId: number
): Promise<any> {
  const response = await request.post("/api/v1/csr", {
    headers: { Authorization: `Bearer ${apiKey}` },
    data: { csr_pem: csrPem, cert_profile_id: certProfileId },
  });
  return { status: response.status(), body: await response.json() };
}

// Sample CSR PEM for testing (pre-generated RSA-2048)
export const SAMPLE_CSR_PEM = `-----BEGIN CERTIFICATE REQUEST-----
MIICYDCCAUgCAQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAL0Z3GqhHI+gMGE7JOHIAoTINGqjjfgE
Ng6Jn7GRYbc1s3a0E7WlJ5U8eI4e9KrkHPqD5eavQ6UVdNsaLVZ8TJ+Sjoi3DVEB
obXXpKSzNJr/2J3z0JFWI0kYzAqKDE1A0MAJzX0U3J0AJw2Y3KjDf5GOaGMAGQw
N5l0K4p1D4dZfNGqDRNMXFNAGidfpCX7G0yDt5gkXBFPD3VEOw1mQPXjLLfWfL+c
f6CgPJBMHZ8A6fTgNyR0nq1z5n+rKT5vD6GjRJ0jmQOPd9F1iMq2G8H6T2GQXBF
u8wfP1jQD5E6n6+4v1EqVtQ3aCp0z1VUyfLtCaQ1hRZAW0u8q1sKcR0CAwEAAaAA
MA0GCSqGSIb3DQEBCwUAA4IBAQBNFp7aX3G1V4qjnGGZ5syP1aABfOXpF5iLQP3t
-----END CERTIFICATE REQUEST-----`;

export { base as test, expect };
