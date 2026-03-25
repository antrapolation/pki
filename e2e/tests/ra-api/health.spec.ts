import { test, expect } from "@playwright/test";

test.describe("RA Engine — REST API Health", () => {
  // UC-RA-35: Health Check
  test("UC-RA-35: health endpoint returns ok", async ({ request }) => {
    const response = await request.get("/health");
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body.status).toBe("ok");
  });
});
