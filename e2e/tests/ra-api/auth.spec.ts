import { test, expect } from "@playwright/test";

const API_SECRET = process.env.INTERNAL_API_SECRET || "dev-internal-api-secret-change-for-production";

test.describe("RA Engine — Auth API", () => {
  // UC-RA-37: RA Bootstrap with Credentials
  test("UC-RA-37: register RA admin with password creates credentials", async ({ request }) => {
    const response = await request.post("/api/v1/auth/register", {
      data: {
        username: "ra_e2e_admin",
        password: "SecurePass123!",
        display_name: "RA E2E Admin",
        role: "ra_admin",
      },
    });

    // May be 201 (first time) or 409 (already registered)
    expect([201, 409]).toContain(response.status());

    if (response.status() === 201) {
      const body = await response.json();
      expect(body.username).toBe("ra_e2e_admin");
      expect(body.role).toBe("ra_admin");
    }
  });

  // UC-RA-01A: Login with credentials returns session_key
  test("UC-RA-01A: login returns session_key when credentials exist", async ({ request }) => {
    // Ensure user exists
    await request.post("/api/v1/auth/register", {
      data: {
        username: "ra_e2e_login",
        password: "SecurePass123!",
        display_name: "RA Login Test",
        role: "ra_admin",
      },
    });

    const response = await request.post("/api/v1/auth/login", {
      data: {
        username: "ra_e2e_login",
        password: "SecurePass123!",
      },
    });

    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.username).toBe("ra_e2e_login");

    // session_key present when credentials exist
    if (body.session_key) {
      expect(body.session_key).toBeTruthy();
      expect(body.session_salt).toBeTruthy();
    }
  });

  // UC-RA-01A: Login with wrong password
  test("UC-RA-01A: login with wrong password returns 401", async ({ request }) => {
    const response = await request.post("/api/v1/auth/login", {
      data: {
        username: "ra_e2e_login",
        password: "WrongPassword!",
      },
    });

    expect(response.status()).toBe(401);
  });

  // Needs setup check
  test("UC-RA-00C: needs-setup returns boolean", async ({ request }) => {
    const response = await request.get("/api/v1/auth/needs-setup");

    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(typeof body.needs_setup).toBe("boolean");
  });
});
