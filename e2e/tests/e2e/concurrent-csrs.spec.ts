import { test, expect, request as playwrightRequest } from "@playwright/test";
import { URLS, SAMPLE_CSR_PEM } from "../../lib/fixtures";

// UC-E2E-11: Concurrent CSR Processing
// Verifies the RA Engine handles multiple simultaneous CSR submissions correctly.

const API_KEY = process.env.RA_API_KEY || "test-api-key";

test.describe("E2E — Concurrent CSR Processing (UC-E2E-11)", () => {
  test("UC-E2E-11: submit 3 CSRs concurrently, all return consistent status", async () => {
    const raApiCtx = await playwrightRequest.newContext({
      baseURL: URLS.raApi,
    });

    // Fire 3 parallel CSR submissions
    const submissions = await Promise.all([
      raApiCtx.post("/api/v1/csr", {
        headers: { Authorization: `Bearer ${API_KEY}` },
        data: { csr_pem: SAMPLE_CSR_PEM, cert_profile_id: 1 },
      }),
      raApiCtx.post("/api/v1/csr", {
        headers: { Authorization: `Bearer ${API_KEY}` },
        data: { csr_pem: SAMPLE_CSR_PEM, cert_profile_id: 1 },
      }),
      raApiCtx.post("/api/v1/csr", {
        headers: { Authorization: `Bearer ${API_KEY}` },
        data: { csr_pem: SAMPLE_CSR_PEM, cert_profile_id: 1 },
      }),
    ]);

    // None should return 500 (server error)
    for (const res of submissions) {
      expect(res.status()).not.toBe(500);
    }

    // All should return the same status (consistent behavior)
    const statuses = submissions.map((r) => r.status());
    const uniqueStatuses = new Set(statuses);
    expect(uniqueStatuses.size).toBe(1);

    // If all returned 201, verify each has a unique ID
    if (statuses[0] === 201) {
      const bodies = await Promise.all(submissions.map((r) => r.json()));
      const ids = bodies.map((b) => b.data.id);

      for (const id of ids) {
        expect(id).toBeTruthy();
      }

      // All IDs should be unique
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(3);
    }

    await raApiCtx.dispose();
  });

  test("UC-E2E-11: 5 concurrent submissions do not cause server errors", async () => {
    const raApiCtx = await playwrightRequest.newContext({
      baseURL: URLS.raApi,
    });

    const count = 5;
    const promises = Array.from({ length: count }, () =>
      raApiCtx.post("/api/v1/csr", {
        headers: { Authorization: `Bearer ${API_KEY}` },
        data: { csr_pem: SAMPLE_CSR_PEM, cert_profile_id: 1 },
      })
    );

    const results = await Promise.all(promises);

    // None should return 500
    for (const res of results) {
      expect(res.status()).not.toBe(500);
    }

    // All should return a consistent status code
    const statuses = results.map((r) => r.status());
    const uniqueStatuses = new Set(statuses);
    expect(uniqueStatuses.size).toBe(1);

    await raApiCtx.dispose();
  });
});
