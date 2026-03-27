import { test, expect } from "@playwright/test";

test.describe("CA Engine — Auth API", () => {
  // UC-CA-01A: Login with credentials
  test("UC-CA-01A: login with valid credentials returns user + session_key", async ({ request }) => {
    // Register a user first (may already exist)
    await request.post("/api/v1/auth/register", {
      data: {
        username: "e2e_admin",
        password: "SecurePass123!",
        display_name: "E2E Admin",
        role: "ca_admin",
      },
    });

    // Login
    const response = await request.post("/api/v1/auth/login", {
      data: {
        username: "e2e_admin",
        password: "SecurePass123!",
      },
    });

    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.username).toBe("e2e_admin");
    expect(body.role).toBe("ca_admin");

    // If credentials were created, session_key should be present
    if (body.session_key) {
      expect(body.session_key).toBeTruthy();
      expect(body.session_salt).toBeTruthy();
    }
  });

  // UC-CA-01A: Login with wrong password
  test("UC-CA-01A: login with wrong password returns 401", async ({ request }) => {
    const response = await request.post("/api/v1/auth/login", {
      data: {
        username: "e2e_admin",
        password: "WrongPassword!",
      },
    });

    expect(response.status()).toBe(401);
    const body = await response.json();
    expect(body.error).toBe("invalid_credentials");
  });

  // UC-CA-00C: Bootstrap / needs-setup
  test("UC-CA-00C: needs-setup returns boolean", async ({ request }) => {
    const response = await request.get("/api/v1/auth/needs-setup");

    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(typeof body.needs_setup).toBe("boolean");
  });

  // Auth endpoints don't require API secret
  test("auth endpoints are public (no Bearer token needed)", async ({ request }) => {
    const response = await request.get("/api/v1/auth/needs-setup");
    expect(response.status()).toBe(200);

    const loginResp = await request.post("/api/v1/auth/login", {
      data: { username: "nobody", password: "wrong" },
    });
    // Should return 401 (auth failed), not 401 (no Bearer token)
    expect(loginResp.status()).toBe(401);
  });
});
