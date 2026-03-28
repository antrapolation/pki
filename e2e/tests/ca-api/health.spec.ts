import { test, expect } from "@playwright/test";

test.describe("CA Engine — Health", () => {
  test("UC-CA-00: health endpoint returns ok", async ({ request }) => {
    const response = await request.get("/health");
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.status).toBe("ok");
  });
});
