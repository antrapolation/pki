import { test, expect, request as playwrightRequest } from "@playwright/test";
import { URLS } from "../../lib/fixtures";

const API_SECRET = process.env.INTERNAL_API_SECRET || "dev-internal-api-secret-change-for-production";

// UC-E2E-20: Full Key Ceremony via API
test.describe("E2E — Key Ceremony Lifecycle (UC-E2E-20)", () => {
  test("UC-E2E-20: ceremony API health and auth checks", async () => {
    const caApi = await playwrightRequest.newContext({
      baseURL: URLS.caApi,
    });

    // Health check
    const health = await caApi.get("/health");
    expect(health.status()).toBe(200);

    // Ceremony start requires auth
    const noAuth = await caApi.post("/api/v1/ceremonies/start", {
      data: { sessions: [] },
    });
    expect(noAuth.status()).toBe(401);

    // Ceremony start with auth but empty sessions
    const emptyStart = await caApi.post("/api/v1/ceremonies/start", {
      headers: { Authorization: `Bearer ${API_SECRET}` },
      data: { sessions: [] },
    });
    expect([422, 500]).toContain(emptyStart.status());

    // Status of non-existent ceremony
    const status = await caApi.get("/api/v1/ceremonies/nonexistent/status", {
      headers: { Authorization: `Bearer ${API_SECRET}` },
    });
    expect(status.status()).toBe(404);

    await caApi.dispose();
  });

  test("UC-E2E-20: ceremony phase transitions require valid ceremony_id", async () => {
    const caApi = await playwrightRequest.newContext({
      baseURL: URLS.caApi,
    });

    const phases = [
      { path: "/api/v1/ceremonies/fake/generate-keypair", data: { algorithm: "ECC-P256" } },
      { path: "/api/v1/ceremonies/fake/self-sign", data: { subject_info: "/CN=Test" } },
      { path: "/api/v1/ceremonies/fake/csr", data: { subject_info: "/CN=Test" } },
      { path: "/api/v1/ceremonies/fake/assign-custodians", data: { custodians: [], threshold_k: 2 } },
      { path: "/api/v1/ceremonies/fake/finalize", data: { auditor_session: { role: "auditor" } } },
    ];

    for (const { path, data } of phases) {
      const response = await caApi.post(path, {
        headers: { Authorization: `Bearer ${API_SECRET}` },
        data,
      });
      expect(response.status()).toBe(404);
    }

    await caApi.dispose();
  });
});
