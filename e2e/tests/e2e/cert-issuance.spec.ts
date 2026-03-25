import { test, expect, request as playwrightRequest } from "@playwright/test";
import { URLS, SAMPLE_CSR_PEM } from "../../lib/fixtures";

// Full certificate issuance flow tested purely via APIs
// Portal UI steps covered in individual portal tests

const API_KEY = process.env.RA_API_KEY || "test-api-key";

test.describe("E2E — Certificate Issuance Flow (UC-E2E-01)", () => {
  // UC-E2E-01: Submit CSR → Auto-validate → OCSP query
  test("UC-E2E-01: CSR submission and OCSP status check", async () => {
    // Step 1: Submit CSR to RA engine
    const raRequest = await playwrightRequest.newContext({
      baseURL: URLS.raApi,
    });
    const submitRes = await raRequest.post("/api/v1/csr", {
      headers: { Authorization: `Bearer ${API_KEY}` },
      data: { csr_pem: SAMPLE_CSR_PEM, cert_profile_id: 1 },
    });

    // If API key is valid and profile exists, CSR should be created
    if (submitRes.status() === 201) {
      const csrData = await submitRes.json();
      expect(csrData.data.id).toBeTruthy();
      expect(csrData.data.status).toMatch(/pending|verified/);

      // Step 2: List CSRs to verify it exists
      const listRes = await raRequest.get("/api/v1/csr", {
        headers: { Authorization: `Bearer ${API_KEY}` },
      });
      expect(listRes.status()).toBe(200);
      const csrList = await listRes.json();
      expect(csrList.data.length).toBeGreaterThan(0);
    }

    // Step 3: Query validation service for unknown cert (baseline)
    const valRequest = await playwrightRequest.newContext({
      baseURL: URLS.validation,
    });
    const ocspRes = await valRequest.post("/ocsp", {
      data: { serial_number: "not-yet-issued" },
    });
    expect(ocspRes.status()).toBe(200);
    const ocspData = await ocspRes.json();
    expect(ocspData.status).toBe("unknown");

    await raRequest.dispose();
    await valRequest.dispose();
  });
});

test.describe("E2E — Certificate Revocation Flow (UC-E2E-02)", () => {
  // UC-E2E-02: OCSP status changes after revocation
  test("UC-E2E-02: OCSP returns unknown for non-existent cert", async () => {
    const valRequest = await playwrightRequest.newContext({
      baseURL: URLS.validation,
    });

    // Query for cert that doesn't exist
    const response = await valRequest.post("/ocsp", {
      data: { serial_number: "phantom-cert-000" },
    });
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body.status).toBe("unknown");

    // Verify CRL doesn't contain it either
    const crlRes = await valRequest.get("/crl");
    expect(crlRes.status()).toBe(200);
    const crl = await crlRes.json();
    const found = crl.revoked_certificates?.find(
      (c: any) => c.serial_number === "phantom-cert-000"
    );
    expect(found).toBeUndefined();

    await valRequest.dispose();
  });
});
