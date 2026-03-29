import { spawnSync } from "child_process";
import type { FullConfig } from "@playwright/test";

/**
 * Runs a SQL statement against a database via `podman exec pki-postgres psql`.
 * Silently skips if the container is not available (e.g. CI without podman).
 */
function runSql(database: string, sql: string): void {
  const result = spawnSync(
    "podman",
    ["exec", "pki-postgres", "psql", "-U", "postgres", "-d", database, "-c", sql],
    { encoding: "utf-8" }
  );
  if (result.error) {
    // podman not available — skip silently
    return;
  }
  if (result.status !== 0 && result.stderr) {
    console.warn(`[global-teardown] SQL on ${database} failed: ${result.stderr.trim()}`);
  }
}

export default async function globalTeardown(_config: FullConfig) {
  console.log("[global-teardown] Cleaning test data from databases...");

  // ── RA Engine ────────────────────────────────────────────────────────────
  // Remove all test-generated rows; keep the base users created in global-setup
  runSql(
    "pki_ra_engine",
    [
      "DELETE FROM service_configs;",
      "DELETE FROM cert_profiles;",
      "DELETE FROM csr_requests;",
      "DELETE FROM ra_api_keys;",
      "DELETE FROM ra_users WHERE username NOT IN ('admin', 'officer');",
    ].join(" ")
  );

  // ── CA Engine ────────────────────────────────────────────────────────────
  // Delete in dependency order (FK-safe without needing CASCADE)
  runSql(
    "pki_ca_engine",
    [
      "DELETE FROM issued_certificates;",
      "DELETE FROM keypair_access;",
      "DELETE FROM threshold_shares;",
      "DELETE FROM key_ceremonies;",
      "DELETE FROM keystores;",
      "DELETE FROM issuer_keys;",
      "DELETE FROM ca_users WHERE username NOT IN ('admin', 'key_manager', 'auditor', '__acl_system__');",
    ].join(" ")
  );

  console.log("[global-teardown] Done.");
}
