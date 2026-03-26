# Platform Module — Use Cases

## Actors

| Actor | Role | Description |
|-------|------|-------------|
| Platform Admin | `platform_admin` | Manages tenants, monitors platform health (credentials from env vars) |
| Tenant Admin | `ca_admin` | First user of a new tenant, bootstraps the CA instance |

---

## UC-PLT-01: Platform Admin Login

**Actor:** Platform Admin
**Precondition:** Platform Portal running, `PLATFORM_ADMIN_USERNAME` and `PLATFORM_ADMIN_PASSWORD` env vars configured
**Trigger:** Navigate to Platform Portal `/login`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/login` | Login form displayed with username and password fields |
| 2 | Enter username (from `PLATFORM_ADMIN_USERNAME`) | Field populated |
| 3 | Enter password (from `PLATFORM_ADMIN_PASSWORD`) | Field populated |
| 4 | Click "Login" | Redirected to Platform Dashboard (`/`) |
| 5 | Verify session | Session cookie set, "Platform Admin" identity in nav bar |

**Error Cases:**
- Wrong username → "Invalid credentials" error
- Wrong password → "Invalid credentials" error
- Empty fields → validation error

---

## UC-PLT-02: View Platform Dashboard

**Actor:** Platform Admin
**Precondition:** Logged in to Platform Portal
**Trigger:** Navigate to `/`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Page loads | Total tenants count displayed |
| 2 | — | Active tenants count displayed |
| 3 | — | Recent tenants table populated (name, subdomain, status, created_at) |
| 4 | — | "Create Tenant" action button visible |

---

## UC-PLT-03: Create Tenant

**Actor:** Platform Admin
**Precondition:** Logged in, PostgreSQL server accessible
**Trigger:** Click "Create Tenant" on dashboard or navigate to tenant creation form

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Enter organization name (e.g., "Acme Corp") | Field populated |
| 2 | Enter subdomain slug (e.g., "acme") | Field populated |
| 3 | Click "Create Tenant" | Tenant provisioning begins |
| 4 | System generates tenant UUID | UUID assigned |
| 5 | System creates database `pki_tenant_{uuid}` | Database created |
| 6 | System creates 4 PostgreSQL schemas (ca, ra, validation, audit) | Schemas created with role isolation |
| 7 | System runs migrations for all schemas | Tables created in each schema |
| 8 | System inserts tenant record in `pki_platform.tenants` | Record with status = "initialized" |
| 9 | Setup URL returned | `https://{slug}.ca.domain.com/setup` displayed to platform admin |

**Error Cases:**
- Duplicate subdomain slug → "Subdomain already taken" error
- Database creation failure → error with rollback
- Missing required fields → validation error

---

## UC-PLT-04: Suspend Tenant

**Actor:** Platform Admin
**Precondition:** Tenant exists with status "active"
**Trigger:** On tenant list or detail page

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Locate tenant in table | Tenant row visible with "active" status |
| 2 | Click "Suspend" on tenant row | Confirmation prompt displayed |
| 3 | Confirm suspension | Tenant status changes to "suspended" |
| 4 | Verify tenant not resolvable | Requests to `{slug}.ca.domain.com` return error (tenant suspended) |
| 5 | Verify tenant users cannot login | Login attempts fail with "Tenant suspended" |

---

## UC-PLT-05: Activate Tenant

**Actor:** Platform Admin
**Precondition:** Tenant exists with status "suspended" or "initialized"
**Trigger:** On tenant list or detail page

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Locate tenant in table | Tenant row visible with "suspended" or "initialized" status |
| 2 | Click "Activate" on tenant row | Tenant status changes to "active" |
| 3 | Verify tenant resolvable | Requests to `{slug}.ca.domain.com` route correctly |
| 4 | Verify tenant users can login | Login attempts succeed (if users exist) |

---

## UC-PLT-06: Delete Tenant

**Actor:** Platform Admin
**Precondition:** Tenant exists (any status)
**Trigger:** On tenant list or detail page

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Locate tenant in table | Tenant row visible |
| 2 | Click "Delete" on tenant row | Confirmation prompt with warning "This action is irreversible" |
| 3 | Confirm deletion | Tenant database `pki_tenant_{uuid}` dropped |
| 4 | — | Tenant record removed from `pki_platform.tenants` |
| 5 | Verify tenant gone | Subdomain no longer resolves, tenant not in list |

**Error Cases:**
- Database drop failure → error displayed, tenant record preserved for retry

---

## UC-PLT-07: Tenant Bootstrap (First Admin Setup)

**Actor:** Tenant Admin (first user)
**Precondition:** Tenant created (UC-PLT-03), status = "initialized" or "active", no users exist in tenant database
**Trigger:** Navigate to `https://{slug}.ca.domain.com/setup`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/setup` | Bootstrap form displayed with title "CA Portal Setup" |
| 2 | Enter name | Field populated |
| 3 | Enter login (username, min 3 chars) | Field populated |
| 4 | Enter password (min 8 chars) | Field populated |
| 5 | Enter organization name | Field populated |
| 6 | Click "Create Admin Account" | Bootstrap process begins |
| 7 | System creates CA Admin with password hash (Argon2) | User record created with role `ca_admin` |
| 8 | System generates signing keypair (per tenant algorithm config) | Signing public key stored plain, private key encrypted with password-derived key |
| 9 | System generates KEM keypair | KEM public key stored plain, private key encrypted with password-derived key |
| 10 | System self-certifies admin's public keys | Certificates created (no higher authority yet) |
| 11 | System creates Keypair ACL credential | ACL signing + KEM keypairs generated, random password encrypted with admin's KEM public key |
| 12 | System grants admin activation rights on Keypair ACL | Grant record stored |
| 13 | System creates 4 bootstrap keypairs: `:root`, `:sub_root`, `:strap_ca_remote_service_host_signing_key`, `:strap_ca_remote_service_host_cipher_key` | All random passwords encrypted with admin's KEM public key |
| 14 | Tenant status updated to "active" | Status transition recorded |
| 15 | Redirected to `/login` with flash "Admin account created. Please sign in." | Success |

**Error Cases:**
- Password too short (< 8 chars) → validation error
- Username too short (< 3 chars) → validation error
- Setup page visited after bootstrap complete → redirected to `/login` with "System already configured."
- Keypair generation failure → error with rollback (no partial state)

---

## UC-PLT-08: Tenant Resolution

**Actor:** System (automatic on every request)
**Precondition:** Tenant exists and is active
**Trigger:** Any HTTP request to a tenant-scoped service

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Request arrives at portal/engine | Request intercepted by tenant resolution plug/middleware |
| 2 | Extract tenant identifier from subdomain, session, or API key header | Tenant slug or ID extracted |
| 3 | Look up tenant in `pki_platform.tenants` | Tenant record found |
| 4 | Verify tenant status = "active" | Access allowed |
| 5 | Set dynamic Ecto repo to `pki_tenant_{uuid}` | Database connection configured |
| 6 | Set `search_path` per service role (ca/ra/validation/audit) | Schema isolation enforced |
| 7 | Process request | All queries scoped to correct tenant and schema |

**Error Cases:**
- Tenant not found → 404 or redirect to error page
- Tenant status = "suspended" → 403 "Tenant suspended"
- Tenant status = "initialized" → redirect to `/setup` (if no users exist)
- Database connection failure → 503 Service Unavailable
