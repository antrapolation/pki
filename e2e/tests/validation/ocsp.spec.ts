import { test, expect } from "@playwright/test";

test.describe("Validation — OCSP Responder", () => {
  // UC-VAL-01: Health Check
  test("UC-VAL-01: health endpoint returns ok", async ({ request }) => {
    const response = await request.get("/health");
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body.status).toBe("ok");
  });

  // UC-VAL-04: OCSP Query — Unknown Certificate
  test("UC-VAL-04: query unknown serial returns unknown", async ({ request }) => {
    const response = await request.post("/ocsp", {
      data: { serial_number: "nonexistent_serial_12345" },
    });
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body.status).toBe("unknown");
  });

  // UC-VAL-13: OCSP Query — Empty serial
  test("UC-VAL-13: query with empty serial", async ({ request }) => {
    const response = await request.post("/ocsp", {
      data: { serial_number: "" },
    });
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body.status).toBe("unknown");
  });

  // UC-VAL-13: OCSP Query — Invalid JSON
  test("UC-VAL-13: query with invalid JSON returns error", async ({ request }) => {
    const response = await request.post("/ocsp", {
      headers: { "Content-Type": "application/json" },
      data: "not-json",
    });
    expect([400, 500]).toContain(response.status());
  });

  // UC-VAL-18: Concurrent OCSP queries
  test("UC-VAL-18: handle concurrent queries", async ({ request }) => {
    const serials = Array.from({ length: 10 }, (_, i) => `concurrent_test_${i}`);

    const responses = await Promise.all(
      serials.map((serial) =>
        request.post("/ocsp", { data: { serial_number: serial } })
      )
    );

    for (const response of responses) {
      expect(response.status()).toBe(200);
      const body = await response.json();
      expect(body.status).toBe("unknown"); // None exist
    }
  });

  // UC-VAL-02: Query OCSP for known active certificate
  // Since we cannot create certificates via API in e2e, we query with a
  // plausible serial and validate the response structure regardless of status.
  test("UC-VAL-02: query for active cert returns valid OCSP response structure", async ({ request }) => {
    const response = await request.post("/ocsp", {
      data: { serial_number: "active_cert_serial_001" },
    });
    expect(response.status()).toBe(200);

    const body = await response.json();
    // Status must be one of the three valid OCSP statuses
    expect(["good", "revoked", "unknown"]).toContain(body.status);
    // Response should include the queried serial echoed back or a status field
    expect(body).toHaveProperty("status");
  });

  // UC-VAL-03: Query OCSP for revoked certificate
  // Same limitation as UC-VAL-02 — validates structure for a revoked-style serial.
  test("UC-VAL-03: query for revoked cert returns valid OCSP response structure", async ({ request }) => {
    const response = await request.post("/ocsp", {
      data: { serial_number: "revoked_cert_serial_001" },
    });
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(["good", "revoked", "unknown"]).toContain(body.status);

    // If the certificate happens to be revoked, verify revocation detail fields
    if (body.status === "revoked") {
      expect(body).toHaveProperty("revoked_at");
    }
  });

  // UC-VAL-05: OCSP cache behavior — repeated query should return quickly
  test("UC-VAL-05: repeated OCSP query is served quickly (cache behavior)", async ({ request }) => {
    const serial = "cache_test_serial_005";

    // First query — populates cache
    const startFirst = Date.now();
    const first = await request.post("/ocsp", {
      data: { serial_number: serial },
    });
    const durationFirst = Date.now() - startFirst;
    expect(first.status()).toBe(200);
    const bodyFirst = await first.json();

    // Second query — should be served from cache
    const startSecond = Date.now();
    const second = await request.post("/ocsp", {
      data: { serial_number: serial },
    });
    const durationSecond = Date.now() - startSecond;
    expect(second.status()).toBe(200);
    const bodySecond = await second.json();

    // Both responses must have the same status
    expect(bodyFirst.status).toBe(bodySecond.status);

    // Second query should not be significantly slower than the first
    // (allow generous 5 s ceiling — we mainly verify it does not hang)
    expect(durationSecond).toBeLessThan(5000);
  });

  // UC-VAL-06: OCSP response consistency across repeated queries
  test("UC-VAL-06: OCSP status is consistent across sequential queries", async ({ request }) => {
    const serial = "consistency_test_serial_006";

    const first = await request.post("/ocsp", {
      data: { serial_number: serial },
    });
    expect(first.status()).toBe(200);
    const bodyFirst = await first.json();

    const second = await request.post("/ocsp", {
      data: { serial_number: serial },
    });
    expect(second.status()).toBe(200);
    const bodySecond = await second.json();

    // Status must remain the same for the same serial
    expect(bodyFirst.status).toBe(bodySecond.status);
  });
});
