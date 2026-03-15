# Plan 3: pki_ra_engine — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Registration Authority Engine — CSR processing, cert profile management, service configuration, user management, and external protocol endpoints (REST API, CMP).

**Architecture:** Elixir OTP application with Ecto/Postgres. Receives CSR submissions via REST/CMP, validates them, manages RA officer approval workflow, then forwards approved CSRs to `pki_ca_engine` for signing. Contains 2 process modules and 6 library modules per the product spec. Exposes Phoenix-based REST API for external clients.

**Tech Stack:** Elixir/OTP, Ecto (Postgres), Phoenix (REST API), `pki_audit_trail` (audit), `pki_ca_engine` (signing — via RPC interface)

**Spec Reference:** `docs/superpowers/specs/2026-03-15-pqc-ca-system-design.md` — Sections 3.4, 4.1 (RA database), 6, 9, 10

---

## Chunk 1: Project Scaffold and Database Schema

### Task 1: Create the Elixir project with Phoenix

**Files:**
- Create: `pki_ra_engine/mix.exs`
- Create: `pki_ra_engine/config/` (config, dev, test, runtime)
- Create: `pki_ra_engine/lib/pki_ra_engine/` (repo, application, main module)
- Create: `pki_ra_engine/test/support/` (data_case, conn_case)

- [ ] **Step 1: Generate Phoenix project**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src
mix phx.new pki_ra_engine --no-html --no-assets --no-mailer --no-dashboard --no-live
cd pki_ra_engine
```

If `phx.new` is not available, use `mix new pki_ra_engine --sup` and add Phoenix deps manually:
```elixir
{:phoenix, "~> 1.7"},
{:phoenix_ecto, "~> 4.5"},
{:plug_cowboy, "~> 2.7"}
```

- [ ] **Step 2: Configure for Postgres on localhost:5432, database `pki_ra_engine_dev`/`pki_ra_engine_test`**

- [ ] **Step 3: Verify compilation**

```bash
mix deps.get && mix compile
```

- [ ] **Step 4: Commit**

```bash
git init && git add -A && git commit -m "feat: scaffold pki_ra_engine project with Phoenix"
```

---

### Task 2: Create database migrations

**Files:**
- Create: 5 migration files

- [ ] **Step 1: Generate and implement migrations**

Order (FK dependencies):

1. **ra_users** — did (unique), display_name, role, status (default "active"), timestamps
2. **cert_profiles** — name (unique), subject_dn_policy (map), issuer_policy (map), key_usage (string), ext_key_usage (string), digest_algo (string), validity_policy (map), timestamping_policy (map), crl_policy (map), ocsp_policy (map), ca_repository_url, issuer_url, included_extensions (map), renewal_policy (map), notification_profile (map), cert_publish_policy (map), timestamps
3. **csr_requests** — csr_der (binary), csr_pem (text), subject_dn, cert_profile_id (FK), status (default "pending"), submitted_at, reviewed_by (FK to ra_users), reviewed_at, rejection_reason, issued_cert_serial, timestamps
4. **service_configs** — service_type, port (integer), url, rate_limit (integer), ip_whitelist (map), ip_blacklist (map), connection_security, credentials (binary, encrypted), ca_engine_ref, timestamps. Unique index on service_type.
5. **ra_api_keys** — hashed_key, ra_user_id (FK), label, expiry (utc_datetime), rate_limit (integer), status (default "active"), revoked_at, timestamps

- [ ] **Step 2: Run migrations**

```bash
mix ecto.create && mix ecto.migrate
```

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat: add database migrations for RA engine tables"
```

---

### Task 3: Create Ecto schemas

**Files:**
- Create: `lib/pki_ra_engine/schema/ra_user.ex`
- Create: `lib/pki_ra_engine/schema/cert_profile.ex`
- Create: `lib/pki_ra_engine/schema/csr_request.ex`
- Create: `lib/pki_ra_engine/schema/service_config.ex`
- Create: `lib/pki_ra_engine/schema/ra_api_key.ex`
- Create: `test/pki_ra_engine/schema_test.exs`

**Enums:**
- RaUser roles: ["ra_admin", "ra_officer", "auditor"], statuses: ["active", "suspended"]
- CsrRequest statuses: ["pending", "verified", "approved", "rejected", "issued"]
- ServiceConfig types: ["csr_web", "crl", "ldap", "ocsp"]
- RaApiKey statuses: ["active", "revoked"]

TDD: write schema tests first → fail → implement → pass.

- [ ] **Step 1: Write tests, Step 2: Verify fail, Step 3: Implement, Step 4: Verify pass**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add Ecto schemas for RA engine tables"
```

---

## Chunk 2: RA User Management + Cert Profile Configuration

### Task 4: RA User Management (Process module)

**Files:**
- Create: `lib/pki_ra_engine/user_management.ex`
- Create: `test/pki_ra_engine/user_management_test.exs`

Per spec: "RA Admin — manage RA admins & RA officers. Auditor CRUD by CA Admin (cross-service)."

- [ ] **Step 1-4: TDD cycle**

Functions:
- `create_user/1` — creates RA user (ra_admin, ra_officer). Auditor creation requires `created_by_ca_admin: true` flag.
- `list_users/1` — filterable by role, status
- `get_user/1`, `update_user/2`, `delete_user/1` (soft-delete)
- `authorize/2` — role-permission check:
  - ra_admin: [:manage_ra_admins, :manage_ra_officers, :manage_cert_profiles, :manage_service_configs, :manage_api_keys]
  - ra_officer: [:process_csrs, :view_csrs]
  - auditor: [:view_audit_log]

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add RA user management with role-based access"
```

---

### Task 5: Cert Profile Configuration (Library module)

**Files:**
- Create: `lib/pki_ra_engine/cert_profile_config.ex`
- Create: `test/pki_ra_engine/cert_profile_config_test.exs`

Per spec: the big configuration module. Full CRUD for cert profiles with all fields from the product spec.

- [ ] **Step 1-4: TDD cycle**

Functions:
- `create_profile/1` — creates cert profile with all jsonb fields
- `get_profile/1` — by ID
- `list_profiles/0` — all profiles
- `update_profile/2` — updates any profile fields
- `delete_profile/1` — hard delete (profiles are config, not operational data)
- `validate_csr_against_profile/2` — checks a CSR's subject DN matches profile's mandatory fields, algorithm is allowed, etc. Returns `:ok` or `{:error, reasons}`.

Key validations:
- key_usage must be valid X.509 key usage values
- digest_algo must be recognized algorithm string
- validity_policy.validity_period must be positive integer

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add cert profile configuration with validation"
```

---

## Chunk 3: Service Configuration Libraries

### Task 6: Service Configuration Libraries

**Files:**
- Create: `lib/pki_ra_engine/service_config.ex`
- Create: `test/pki_ra_engine/service_config_test.exs`

Covers 4 library modules from the spec: Web Services Config, CRL Services Config, LDAP Services Config, OCSP Services Config. Since they all follow the same pattern (CRUD on service_configs table with different service_type), implement as a single module with type parameter.

- [ ] **Step 1-4: TDD cycle**

Functions:
- `configure_service/2` — creates/updates config for a service_type
- `get_service_config/1` — by service_type
- `list_service_configs/0` — all configs
- `update_service_config/2` — update port, url, rate_limit, ip_whitelist, etc.
- `delete_service_config/1` — remove config

Also: `lib/pki_ra_engine/ca_engine_config.ex` — separate module for CA Engine Configuration (connection params to CA engine nodes).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add service configuration and CA engine configuration"
```

---

## Chunk 4: CSR Validation Module

### Task 7: CSR Validation Process

**Files:**
- Create: `lib/pki_ra_engine/csr_validation.ex`
- Create: `test/pki_ra_engine/csr_validation_test.exs`

Per spec: "View, verify, approve, reject CSRs." This is the core RA workflow.

- [ ] **Step 1-4: TDD cycle**

Functions:
- `submit_csr/2` — accepts CSR (PEM or DER binary) + cert_profile_id. Stores in csr_requests with status "pending". Returns `{:ok, csr_request}`.
- `validate_csr/1` — runs automatic validation checks on a pending CSR:
  - Signature verification (placeholder for now)
  - Subject DN matches cert profile policy
  - Returns status: "verified" or "rejected" with reason
- `approve_csr/2` — RA officer approves a verified CSR. Sets status "approved", reviewed_by, reviewed_at.
- `reject_csr/3` — RA officer rejects. Sets status "rejected" with reason.
- `get_csr/1` — by ID with preloads
- `list_csrs/1` — filterable by status, cert_profile_id
- `forward_to_ca/1` — takes an approved CSR and calls the CA engine to sign it. Returns `{:ok, issued_cert_serial}` or `{:error, reason}`. For now, this is a stub that simulates the CA call — real RPC integration comes later.
- `mark_issued/2` — updates CSR status to "issued" with cert serial

Status flow: pending → verified → approved → issued
                            ↘ rejected

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add CSR validation module with approval workflow"
```

---

## Chunk 5: API Key Management + REST API

### Task 8: API Key Management

**Files:**
- Create: `lib/pki_ra_engine/api_key_management.ex`
- Create: `test/pki_ra_engine/api_key_management_test.exs`

- [ ] **Step 1-4: TDD cycle**

Functions:
- `create_api_key/1` — generates random key, stores SHA3-256 hash, returns the raw key (only time it's visible). Returns `{:ok, %{raw_key: "...", api_key: %RaApiKey{}}}`.
- `verify_key/1` — takes raw key, hashes it, looks up. Returns `{:ok, api_key}` or `{:error, :invalid_key}`. Checks expiry and status.
- `list_keys/1` — by ra_user_id
- `revoke_key/1` — sets status "revoked" with revoked_at

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add API key management with hash-based verification"
```

---

### Task 9: REST API Endpoints

**Files:**
- Create: `lib/pki_ra_engine/api/router.ex`
- Create: `lib/pki_ra_engine/api/csr_controller.ex`
- Create: `lib/pki_ra_engine/api/cert_controller.ex`
- Create: `lib/pki_ra_engine/api/auth_plug.ex`
- Create: `test/pki_ra_engine/api/csr_controller_test.exs`
- Create: `test/pki_ra_engine/api/cert_controller_test.exs`

Phoenix REST endpoints for external clients.

- [ ] **Step 1-4: TDD cycle**

**Endpoints:**

```
POST   /api/v1/csr          — Submit CSR (requires API key auth)
GET    /api/v1/csr/:id      — Get CSR status
GET    /api/v1/csr           — List CSRs (with status filter)
POST   /api/v1/csr/:id/approve  — Approve CSR (RA officer)
POST   /api/v1/csr/:id/reject   — Reject CSR (RA officer)

GET    /api/v1/cert/:serial  — Get certificate by serial
GET    /api/v1/cert          — List certificates
POST   /api/v1/cert/:serial/revoke — Revoke certificate
```

**AuthPlug:** Extracts API key from `Authorization: Bearer <key>` header, verifies via ApiKeyManagement.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add REST API endpoints with API key authentication"
```

---

## Summary

**What is built after completing this plan:**

| Module | Spec Type | Responsibility |
|--------|-----------|----------------|
| `PkiRaEngine.UserManagement` | Process | RA user CRUD (ra_admin, ra_officer, auditor) |
| `PkiRaEngine.CsrValidation` | Process | CSR submit, validate, approve, reject, forward to CA |
| `PkiRaEngine.CertProfileConfig` | Library | Full cert profile CRUD with validation |
| `PkiRaEngine.ServiceConfig` | Library | Web/CRL/LDAP/OCSP service configuration |
| `PkiRaEngine.CaEngineConfig` | Library | CA engine connection parameters |
| `PkiRaEngine.ApiKeyManagement` | — | API key lifecycle (create, verify, revoke) |
| `PkiRaEngine.Api.Router` | — | Phoenix REST API router |
| `PkiRaEngine.Api.CsrController` | — | CSR endpoints |
| `PkiRaEngine.Api.CertController` | — | Certificate endpoints |
| `PkiRaEngine.Api.AuthPlug` | — | API key authentication plug |
| `PkiRaEngine.Schema.*` | — | 5 Ecto schemas |

**Database:** 5 tables (ra_users, cert_profiles, csr_requests, service_configs, ra_api_keys)

**Next plan:** Plan 4 — `pki_ca_portal` (Phoenix LiveView CA admin GUI)
