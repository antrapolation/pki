import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [["html", { open: "never" }], ["list"]],
  timeout: 30_000,

  use: {
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },

  projects: [
    {
      name: "ca-portal",
      testMatch: /\/tests\/ca\/.*\.spec\.ts/,
      use: {
        baseURL: process.env.CA_PORTAL_URL || "http://localhost:4002",
      },
    },
    {
      name: "ra-portal",
      testMatch: /\/tests\/ra\/.*\.spec\.ts/,
      use: {
        baseURL: process.env.RA_PORTAL_URL || "http://localhost:4004",
      },
    },
    {
      name: "ca-api",
      testMatch: /\/tests\/ca-api\/.*\.spec\.ts/,
      use: {
        baseURL: process.env.CA_ENGINE_URL || "http://localhost:4001",
      },
    },
    {
      name: "ra-api",
      testMatch: /\/tests\/ra-api\/.*\.spec\.ts/,
      use: {
        baseURL: process.env.RA_ENGINE_URL || "http://localhost:4003",
      },
    },
    {
      name: "validation",
      testMatch: /\/tests\/validation\/.*\.spec\.ts/,
      use: {
        baseURL: process.env.VALIDATION_URL || "http://localhost:4005",
      },
    },
    {
      name: "e2e",
      testMatch: /\/tests\/e2e\/.*\.spec\.ts/,
      use: {
        baseURL: process.env.RA_PORTAL_URL || "http://localhost:4004",
      },
    },
  ],
});
