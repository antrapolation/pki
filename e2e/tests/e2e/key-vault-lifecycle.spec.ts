import { test, expect, request as playwrightRequest } from "@playwright/test";
import { URLS } from "../../lib/fixtures";

const API_SECRET = process.env.INTERNAL_API_SECRET || "dev-internal-api-secret-change-for-production";

// UC-E2E-21: Key Vault Lifecycle via API
test.describe("E2E — Key Vault Lifecycle (UC-E2E-21)", () => {
  test("UC-E2E-21: vault API health and list check", async () => {
    const caApi = await playwrightRequest.newContext({
      baseURL: URLS.caApi,
    });

    // List keypairs — should return empty or populated array
    const list = await caApi.get("/api/v1/keypairs", {
      headers: { Authorization: `Bearer ${API_SECRET}` },
    });
    expect(list.status()).toBe(200);
    const body = await list.json();
    expect(Array.isArray(body)).toBeTruthy();

    await caApi.dispose();
  });

  test("UC-E2E-21: vault requires authentication for all endpoints", async () => {
    const caApi = await playwrightRequest.newContext({
      baseURL: URLS.caApi,
    });

    const endpoints = [
      { method: "get", path: "/api/v1/keypairs" },
      { method: "post", path: "/api/v1/keypairs/register" },
      { method: "post", path: "/api/v1/keypairs/fake-id/grant" },
      { method: "post", path: "/api/v1/keypairs/fake-id/activate" },
      { method: "post", path: "/api/v1/keypairs/fake-id/revoke-grant" },
    ];

    for (const { method, path } of endpoints) {
      const response =
        method === "get"
          ? await caApi.get(path)
          : await caApi.post(path, { data: {} });
      expect(response.status()).toBe(401);
    }

    await caApi.dispose();
  });

  test("UC-E2E-21: vault returns 404 for non-existent keypair operations", async () => {
    const caApi = await playwrightRequest.newContext({
      baseURL: URLS.caApi,
    });

    const fakeId = "019d0000-aaaa-7000-bbbb-000000000000";

    // Get non-existent
    const getResp = await caApi.get(`/api/v1/keypairs/${fakeId}`, {
      headers: { Authorization: `Bearer ${API_SECRET}` },
    });
    expect(getResp.status()).toBe(404);

    // Activate non-existent
    const activateResp = await caApi.post(`/api/v1/keypairs/${fakeId}/activate`, {
      headers: { Authorization: `Bearer ${API_SECRET}` },
      data: { protection_mode: "split_auth_token", shares: [] },
    });
    expect(activateResp.status()).toBe(404);

    // Revoke grant on non-existent
    const revokeResp = await caApi.post(`/api/v1/keypairs/${fakeId}/revoke-grant`, {
      headers: { Authorization: `Bearer ${API_SECRET}` },
      data: { credential_id: fakeId },
    });
    expect([404, 422]).toContain(revokeResp.status());

    await caApi.dispose();
  });

  test("UC-E2E-21: register keypair with invalid data returns 422", async () => {
    const caApi = await playwrightRequest.newContext({
      baseURL: URLS.caApi,
    });

    const response = await caApi.post("/api/v1/keypairs/register", {
      headers: { Authorization: `Bearer ${API_SECRET}` },
      data: {}, // missing required fields
    });

    expect([400, 422]).toContain(response.status());

    await caApi.dispose();
  });
});
