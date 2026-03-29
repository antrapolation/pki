import type { FullConfig } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";

function loadDotEnv() {
  const envPath = path.join(__dirname, "..", ".env");
  if (!fs.existsSync(envPath)) return;

  const content = fs.readFileSync(envPath, "utf-8");
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    if (!process.env[key]) process.env[key] = trimmed.slice(eqIdx + 1).trim();
  }
}

async function createUser(
  baseUrl: string,
  secret: string,
  user: { username: string; password: string; display_name: string; role: string }
) {
  const resp = await fetch(`${baseUrl}/api/v1/users`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${secret}`,
    },
    body: JSON.stringify(user),
  });
  // 201 = created, 422 = already exists (duplicate username) — both are fine
  if (resp.status !== 201 && resp.status !== 422) {
    const body = await resp.text();
    console.warn(`[global-setup] POST /api/v1/users at ${baseUrl} → ${resp.status}: ${body}`);
  }
}

async function bootstrapEngine(opts: {
  baseUrl: string;
  users: Array<{ username: string; password: string; display_name: string; role: string }>;
  secret: string;
}) {
  const { baseUrl, users, secret } = opts;

  // Verify the engine is reachable
  let reachable = false;
  try {
    const resp = await fetch(`${baseUrl}/health`);
    reachable = resp.ok;
  } catch {
    // ignore
  }
  if (!reachable) {
    console.warn(`[global-setup] ${baseUrl} is not reachable — skipping bootstrap`);
    return;
  }

  // Create all required test users via the authenticated endpoint.
  // This works regardless of whether needs_setup is true or false, and
  // regardless of which user was registered first. Existing users return 422
  // (duplicate) which we ignore.
  for (const user of users) {
    await createUser(baseUrl, secret, user);
  }
}

export default async function globalSetup(_config: FullConfig) {
  loadDotEnv();

  const secret = process.env.INTERNAL_API_SECRET;
  if (!secret) {
    throw new Error(
      "[global-setup] INTERNAL_API_SECRET not set. Copy .env.example to .env and fill in the values."
    );
  }

  const caUrl = process.env.CA_ENGINE_URL || "http://localhost:4001";
  const raUrl = process.env.RA_ENGINE_URL || "http://localhost:4003";

  await Promise.all([
    bootstrapEngine({
      baseUrl: caUrl,
      secret,
      users: [
        { username: "admin", password: "password123", display_name: "Admin", role: "ca_admin" },
        { username: "key_manager", password: "password123", display_name: "Key Manager", role: "key_manager" },
        { username: "auditor", password: "password123", display_name: "Auditor", role: "auditor" },
      ],
    }),
    bootstrapEngine({
      baseUrl: raUrl,
      secret,
      users: [
        { username: "admin", password: "password123", display_name: "Admin", role: "ra_admin" },
        { username: "officer", password: "password123", display_name: "RA Officer", role: "ra_officer" },
      ],
    }),
  ]);
}
