import { test, expect } from "@playwright/test";

const API_SECRET = process.env.INTERNAL_API_SECRET || "dev-internal-api-secret-change-for-production";

test.describe("CA Engine — Key Vault API", () => {
  // UC-CA-50: List managed keypairs
  test("UC-CA-50: list keypairs returns array", async ({ request }) => {
    const response = await request.get("/api/v1/keypairs", {
      headers: { Authorization: `Bearer ${API_SECRET}` },
    });

    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(Array.isArray(body)).toBeTruthy();
  });

  // UC-CA-51: Get non-existent keypair
  test("UC-CA-51: get non-existent keypair returns 404", async ({ request }) => {
    const fakeId = "019d0000-0000-7000-0000-000000000000";
    const response = await request.get(`/api/v1/keypairs/${fakeId}`, {
      headers: { Authorization: `Bearer ${API_SECRET}` },
    });

    expect(response.status()).toBe(404);
  });

  // UC-CA-46: Register keypair with missing required fields
  test("UC-CA-46: register keypair without required fields returns 422", async ({ request }) => {
    const response = await request.post("/api/v1/keypairs/register", {
      headers: { Authorization: `Bearer ${API_SECRET}` },
      data: {},
    });

    expect([400, 422]).toContain(response.status());
  });

  // UC-CA-48: Activate non-existent keypair
  test("UC-CA-48: activate non-existent keypair returns 404", async ({ request }) => {
    const fakeId = "019d0000-0000-7000-0000-000000000000";
    const response = await request.post(`/api/v1/keypairs/${fakeId}/activate`, {
      headers: { Authorization: `Bearer ${API_SECRET}` },
      data: { protection_mode: "split_auth_token", shares: [] },
    });

    expect(response.status()).toBe(404);
  });

  // UC-CA-49: Revoke grant on non-existent keypair
  test("UC-CA-49: revoke grant on non-existent keypair returns error", async ({ request }) => {
    const fakeId = "019d0000-0000-7000-0000-000000000000";
    const response = await request.post(`/api/v1/keypairs/${fakeId}/revoke-grant`, {
      headers: { Authorization: `Bearer ${API_SECRET}` },
      data: { credential_id: "019d0000-0000-7000-0000-000000000001" },
    });

    expect([404, 422]).toContain(response.status());
  });

  // Key vault endpoints require authentication
  test("UC-CA-46: keypair endpoints require authentication", async ({ request }) => {
    const response = await request.get("/api/v1/keypairs");
    expect(response.status()).toBe(401);
  });

  // UC-CA-47: Grant access without required fields
  test("UC-CA-47: grant access without required fields returns error", async ({ request }) => {
    const fakeId = "019d0000-0000-7000-0000-000000000000";
    const response = await request.post(`/api/v1/keypairs/${fakeId}/grant`, {
      headers: { Authorization: `Bearer ${API_SECRET}` },
      data: {},
    });

    expect([400, 404, 422]).toContain(response.status());
  });
});
