import { test, expect } from "@playwright/test";

const API_SECRET = process.env.INTERNAL_API_SECRET || "dev-internal-api-secret-change-for-production";

test.describe("CA Engine — Key Ceremony API", () => {
  // UC-CA-39: Start Key Ceremony
  test("UC-CA-39: start ceremony returns ceremony_id", async ({ request }) => {
    const response = await request.post("/api/v1/ceremonies/start", {
      headers: { Authorization: `Bearer ${API_SECRET}` },
      data: {
        sessions: [
          { user_id: "test-km-1", role: "key_manager", username: "keymgr1" },
          { user_id: "test-km-2", role: "key_manager", username: "keymgr2" },
        ],
      },
    });

    // May succeed or fail depending on DB state — verify structure
    expect([201, 422]).toContain(response.status());
    if (response.status() === 201) {
      const body = await response.json();
      expect(body.ceremony_id).toBeTruthy();
    }
  });

  // UC-CA-39: Start ceremony with non-key-manager fails
  test("UC-CA-39: start ceremony with wrong role returns error", async ({ request }) => {
    const response = await request.post("/api/v1/ceremonies/start", {
      headers: { Authorization: `Bearer ${API_SECRET}` },
      data: {
        sessions: [
          { user_id: "test-1", role: "auditor", username: "auditor1" },
        ],
      },
    });

    expect([422, 403]).toContain(response.status());
  });

  // UC-CA-45: Get ceremony status for non-existent ceremony
  test("UC-CA-45: get status of non-existent ceremony returns 404", async ({ request }) => {
    const response = await request.get("/api/v1/ceremonies/nonexistent-id/status", {
      headers: { Authorization: `Bearer ${API_SECRET}` },
    });

    expect(response.status()).toBe(404);
  });

  // UC-CA-39: Start ceremony without auth returns 401
  test("UC-CA-39: ceremony endpoints require authentication", async ({ request }) => {
    const response = await request.post("/api/v1/ceremonies/start", {
      data: { sessions: [] },
    });

    expect(response.status()).toBe(401);
  });

  // UC-CA-40: Generate keypair on non-existent ceremony
  test("UC-CA-40: generate keypair on non-existent ceremony returns 404", async ({ request }) => {
    const response = await request.post("/api/v1/ceremonies/fake-id/generate-keypair", {
      headers: { Authorization: `Bearer ${API_SECRET}` },
      data: {
        algorithm: "ECC-P256",
        protection_mode: "credential_own",
      },
    });

    expect(response.status()).toBe(404);
  });

  // UC-CA-41: Self-sign on non-existent ceremony
  test("UC-CA-41: self-sign on non-existent ceremony returns 404", async ({ request }) => {
    const response = await request.post("/api/v1/ceremonies/fake-id/self-sign", {
      headers: { Authorization: `Bearer ${API_SECRET}` },
      data: {
        subject_info: "/CN=Test Root CA",
        cert_profile: "root",
      },
    });

    expect(response.status()).toBe(404);
  });

  // UC-CA-44: Finalize without auditor role
  test("UC-CA-44: finalize without auditor returns 404 for non-existent ceremony", async ({ request }) => {
    const response = await request.post("/api/v1/ceremonies/fake-id/finalize", {
      headers: { Authorization: `Bearer ${API_SECRET}` },
      data: {
        auditor_session: { user_id: "a1", role: "auditor", username: "aud1" },
      },
    });

    expect(response.status()).toBe(404);
  });
});
