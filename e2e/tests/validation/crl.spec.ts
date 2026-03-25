import { test, expect } from "@playwright/test";

test.describe("Validation — CRL Publisher", () => {
  // UC-VAL-07: Get Current CRL
  test("UC-VAL-07: CRL endpoint returns valid structure", async ({ request }) => {
    const response = await request.get("/crl");
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body.type).toBe("X509CRL");
    expect(body.version).toBe(2);
    expect(body.this_update).toBeTruthy();
    expect(body.next_update).toBeTruthy();
    expect(Array.isArray(body.revoked_certificates)).toBeTruthy();
    expect(typeof body.total_revoked).toBe("number");
  });

  // UC-VAL-09: CRL with no revocations
  test("UC-VAL-09: CRL has valid timestamps", async ({ request }) => {
    const response = await request.get("/crl");
    const body = await response.json();

    const thisUpdate = new Date(body.this_update);
    const nextUpdate = new Date(body.next_update);

    // next_update should be after this_update
    expect(nextUpdate.getTime()).toBeGreaterThan(thisUpdate.getTime());
  });

  // UC-VAL-17: CRL validity window
  test("UC-VAL-17: CRL next_update is within expected interval", async ({ request }) => {
    const response = await request.get("/crl");
    const body = await response.json();

    const thisUpdate = new Date(body.this_update);
    const nextUpdate = new Date(body.next_update);
    const diffMs = nextUpdate.getTime() - thisUpdate.getTime();

    // Should be between 1 minute and 24 hours
    expect(diffMs).toBeGreaterThan(60_000);
    expect(diffMs).toBeLessThan(86_400_000);
  });

  // UC-VAL-19: Health check responds while CRL exists
  test("UC-VAL-19: health check independent of CRL state", async ({ request }) => {
    // Fire CRL and health in parallel
    const [crlRes, healthRes] = await Promise.all([
      request.get("/crl"),
      request.get("/health"),
    ]);

    expect(healthRes.status()).toBe(200);
    expect(crlRes.status()).toBe(200);
  });

  // UC-VAL-08: CRL contains revoked certificates with expected structure
  test("UC-VAL-08: revoked_certificates entries have required fields", async ({ request }) => {
    const response = await request.get("/crl");
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(Array.isArray(body.revoked_certificates)).toBeTruthy();

    // If there are revoked certificates, each entry must have serial_number
    for (const entry of body.revoked_certificates) {
      expect(entry).toHaveProperty("serial_number");
      expect(typeof entry.serial_number).toBe("string");

      // revoked_at should be present
      expect(entry).toHaveProperty("revoked_at");

      // reason is optional but if present should be a string
      if (entry.reason !== undefined) {
        expect(typeof entry.reason).toBe("string");
      }
    }
  });

  // UC-VAL-14: CRL multiple revocations — all entries have consistent structure
  test("UC-VAL-14: all revoked entries have consistent structure", async ({ request }) => {
    const response = await request.get("/crl");
    expect(response.status()).toBe(200);

    const body = await response.json();
    const revoked = body.revoked_certificates;

    expect(Array.isArray(revoked)).toBeTruthy();
    expect(body.total_revoked).toBe(revoked.length);

    // Collect the set of keys from each entry to verify consistency
    if (revoked.length > 0) {
      const referenceKeys = Object.keys(revoked[0]).sort();

      for (const entry of revoked) {
        const entryKeys = Object.keys(entry).sort();
        expect(entryKeys).toEqual(referenceKeys);
      }
    }
  });

  // UC-VAL-10: CRL regeneration — two fetches return valid, consistent data
  test("UC-VAL-10: CRL is consistent across sequential fetches", async ({ request }) => {
    const first = await request.get("/crl");
    expect(first.status()).toBe(200);
    const bodyFirst = await first.json();

    // Small delay to allow any potential regeneration
    await new Promise((resolve) => setTimeout(resolve, 500));

    const second = await request.get("/crl");
    expect(second.status()).toBe(200);
    const bodySecond = await second.json();

    // Both should be valid CRL structures
    expect(bodyFirst.type).toBe("X509CRL");
    expect(bodySecond.type).toBe("X509CRL");

    // this_update should be consistent (same CRL period)
    expect(bodyFirst.this_update).toBe(bodySecond.this_update);

    // Revocation count should match
    expect(bodyFirst.total_revoked).toBe(bodySecond.total_revoked);
  });
});
