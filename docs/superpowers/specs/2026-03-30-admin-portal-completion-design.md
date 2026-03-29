# Admin Portal Completion — Design Spec

**Date:** 2026-03-30
**Status:** Draft
**Scope:** Platform Admin Portal, RA Engine multi-tenancy, CA/RA setup page tenant awareness

---

## 1. Overview

Complete the Platform Admin Portal with proper bootstrap flow, tenant creation wizard, tenant health metrics, system monitoring, and platform admin user management. Additionally, make the RA Engine multi-tenant and update CA/RA portal setup pages to accept tenant context.

## 2. Tenant Lifecycle

```
initialized ──→ active ──→ suspended ──→ active (reactivate)
                                       ──→ deleted
```

- **initialized**: Tenant created, CA/RA admins not yet bootstrapped
- **active**: Operational, CA/RA admins configured
- **suspended**: Temporarily disabled (future: billing-driven)
- **deleted**: Only from suspended state, drops tenant database

Status transitions are managed from the tenant detail page in the admin portal.

## 3. Bootstrap Flow (First-Run Setup)

### 3.1 Platform Admin Bootstrap

When the platform portal starts with no admin users in the database:

- All routes redirect to `/setup`
- `/setup` page presents a form: username, display name, password, confirm password
- Creates the first `platform_admin` record in `pki_platform` database
- After creation, redirects to login
- `/setup` returns 404 if any admin already exists

### 3.2 Database: `platform_admins` table

Migration in `pki_platform_engine`:

```
platform_admins
├── id          UUID (primary key)
├── username    string (unique, required)
├── password_hash string (required, Argon2)
├── display_name string (required)
├── role        string (default: "super_admin")
├── status      string (default: "active") — active | suspended
├── inserted_at timestamp
├── updated_at  timestamp
```

### 3.3 Auth Changes

Replace the current env-based single admin auth with database-backed auth:

- `SessionController.create/2` queries `platform_admins` table instead of comparing env vars
- Remove `PLATFORM_ADMIN_USERNAME`, `PLATFORM_ADMIN_PASSWORD`, `PLATFORM_ADMIN_PASSWORD_HASH` from `.env`
- Keep backward compatibility: if env vars are set AND no DB admins exist, seed from env vars on first boot

## 4. Tenant Creation (Simplified)

### 4.1 Create Tenant Page (`/tenants/new`)

Single-page form (not a multi-step wizard since we removed credential steps):

- **Name** (required text)
- **Slug** (required, pattern: `[a-z0-9][a-z0-9-]*[a-z0-9]`)
- **Signing Algorithm** (select: Classical + Post-Quantum options)
- **Create** button with loading state

On success:
- Tenant created with status `initialized`
- Show success page with setup URLs:
  ```
  CA Admin setup: https://{CA_PORTAL_HOST}/setup?tenant={slug}
  RA Admin setup: https://{RA_PORTAL_HOST}/setup?tenant={slug}
  ```
- Platform admin copies/shares these URLs with the designated CA and RA admins

### 4.2 Tenant List (`/tenants`)

Keep existing list view. Remove the inline create form — replaced by the `/tenants/new` page. Add a "New Tenant" button linking to `/tenants/new`.

## 5. Tenant Detail Page (`/tenants/:id`)

### 5.1 Tenant Info Section

Display and allow editing:
- Name, slug (read-only after creation), signing algorithm (read-only)
- Status with action buttons:
  - If `initialized` or `active`: "Suspend" button
  - If `suspended`: "Activate" button, "Delete" button (with confirmation)
  - If `initialized`: show that CA/RA admins haven't set up yet

### 5.2 Setup Status Section

Shows whether CA and RA admins have been bootstrapped:

- **CA Admin**: "Pending setup" (orange badge) or "Configured" (green badge)
  - Query: check if any `ca_users` with role `ca_admin` exist in the tenant's CA instance
- **RA Admin**: "Pending setup" (orange badge) or "Configured" (green badge)
  - Query: check if any `ra_users` with role `ra_admin` and matching `tenant_id` exist

Display setup URLs for pending setups:
```
CA: https://{CA_PORTAL_HOST}/setup?tenant={slug}
RA: https://{RA_PORTAL_HOST}/setup?tenant={slug}
```

### 5.3 Health Metrics Section

Query tenant database via `PkiPlatformEngine.TenantRepo`:

| Metric | Source | Query |
|--------|--------|-------|
| DB Size | PostgreSQL | `SELECT pg_database_size('{db_name}')` |
| CA Users | Tenant DB, `ca` schema | `SELECT count(*) FROM ca.ca_users` |
| RA Users | Tenant DB, `ra` schema | `SELECT count(*) FROM ra.ra_users` |
| Certificates Issued | Tenant DB, `ca` schema | `SELECT count(*) FROM ca.issued_certificates` |
| Active Certificates | Tenant DB, `ca` schema | `SELECT count(*) FROM ca.issued_certificates WHERE status = 'active'` |
| Pending CSRs | Tenant DB, `ra` schema | `SELECT count(*) FROM ra.csr_requests WHERE status = 'pending'` |

Display as stat cards with icons.

## 6. System Monitoring Page (`/system`)

### 6.1 Service Health Cards

Poll each service's `/health` endpoint on page mount and periodically (every 30 seconds via `Process.send_after`):

| Service | URL | Port |
|---------|-----|------|
| CA Engine | `http://127.0.0.1:4001/health` | 4001 |
| CA Portal | `http://127.0.0.1:4002/` | 4002 |
| RA Engine | `http://127.0.0.1:4003/health` | 4003 |
| RA Portal | `http://127.0.0.1:4004/` | 4004 |
| Validation | `http://127.0.0.1:4005/health` | 4005 |
| Platform Portal | Self (always up) | 4006 |

Display per service:
- Status badge: "Healthy" (green) / "Unreachable" (red)
- Response time (ms)
- Last checked timestamp

### 6.2 Database Health

- PostgreSQL status: check connection to main database
- Total database count (system + tenant DBs)

## 7. Platform Admin Management (`/admins`)

### 7.1 Admin List

Table showing all platform admins:
- Username, display name, role, status, created date
- Actions: Suspend / Activate / Delete (cannot delete self)

### 7.2 Create Admin

Form: username, display name, password, confirm password
- Validates password strength (min 8 chars)
- Creates record in `platform_admins` table

### 7.3 Constraints

- Cannot delete or suspend yourself
- Must have at least one active super_admin at all times

## 8. RA Engine Multi-Tenancy

### 8.1 Migration

Add `tenant_id` column to `ra_users` table:

```sql
ALTER TABLE ra_users ADD COLUMN tenant_id UUID;
CREATE INDEX ra_users_tenant_id_index ON ra_users (tenant_id);
```

Nullable for backward compatibility — existing users have `NULL` tenant_id.

### 8.2 Schema Update

Add `tenant_id` field to `RaUser` schema. Update changeset to cast `tenant_id`.

### 8.3 UserManagement Updates

- `register_user/1` → `register_user/1` (accepts `tenant_id` in attrs)
- `list_users/1` → add `:tenant_id` filter option
- `authenticate/2` → filter by `tenant_id` when provided

### 8.4 API Updates

- `POST /api/v1/users` — accept `tenant_id` in request body
- `GET /api/v1/users` — accept `tenant_id` query param for filtering

## 9. CA/RA Portal Setup Page Changes

### 9.1 Tenant-Aware Setup

Both CA and RA portals already have `/setup` pages. Update them to:

1. Accept `?tenant={slug}` query parameter
2. Validate:
   - If no `tenant` param → show error: "Tenant not specified. Contact your platform administrator."
   - If `tenant` slug doesn't exist → show error: "Tenant not found."
   - If tenant status is `suspended` → show error: "Tenant is suspended."
   - If admin already exists for this tenant → show error: "Setup already completed. Please log in."
3. On the setup form, display the tenant name so the admin knows which tenant they're configuring
4. On submit, create the admin user scoped to that tenant

### 9.2 CA Portal Setup

- Existing setup at `/setup` already creates a CA admin
- Add: resolve `tenant` slug → look up tenant → find/create CA instance for tenant
- Create CA admin user with `ca_instance_id` set to the tenant's CA instance

### 9.3 RA Portal Setup

- Existing setup at `/setup` already creates an RA admin
- Add: resolve `tenant` slug → look up tenant
- Create RA admin user with `tenant_id` set to the tenant's ID

## 10. Navigation Updates

### 10.1 Sidebar

```
Platform Admin
├── Dashboard        /           (hero-home)
├── Tenants          /tenants    (hero-building-office-2)
├── System           /system     (hero-server-stack)
├── Admins           /admins     (hero-users)
```

### 10.2 Active State

`is_active?/2` updated to match all new page titles.

## 11. Environment Variable Changes

### Removed
- `PLATFORM_ADMIN_USERNAME`
- `PLATFORM_ADMIN_PASSWORD`
- `PLATFORM_ADMIN_PASSWORD_HASH`

### Added
- None required — admin credentials are now database-managed

### Backward Compatibility

On first boot, if env vars are set and no admin exists in DB, auto-seed the first admin from env vars and log a deprecation warning.

## 12. Files to Create/Modify

### New Files
- `pki_platform_engine/priv/platform_repo/migrations/TIMESTAMP_create_platform_admins.exs`
- `pki_platform_engine/lib/pki_platform_engine/platform_admin.ex` (schema)
- `pki_platform_engine/lib/pki_platform_engine/admin_management.ex` (context)
- `pki_platform_engine/lib/pki_platform_engine/system_health.ex` (health check module)
- `pki_platform_engine/lib/pki_platform_engine/tenant_metrics.ex` (tenant health queries)
- `pki_platform_portal_web/live/setup_live.ex`
- `pki_platform_portal_web/live/tenant_new_live.ex`
- `pki_platform_portal_web/live/tenant_detail_live.ex`
- `pki_platform_portal_web/live/system_live.ex`
- `pki_platform_portal_web/live/admins_live.ex`
- `pki_ra_engine/priv/repo/migrations/TIMESTAMP_add_tenant_id_to_ra_users.exs`

### Modified Files
- `pki_platform_portal_web/router.ex` — new routes
- `pki_platform_portal_web/components/layouts.ex` — updated sidebar nav
- `pki_platform_portal_web/controllers/session_controller.ex` — DB-backed auth
- `pki_platform_portal_web/live/tenants_live.ex` — remove inline form, add link to /tenants/new
- `pki_platform_portal_web/live/dashboard_live.ex` — add setup status summary
- `pki_platform_portal_web.ex` — add RequireSetup plug
- `pki_platform_engine/provisioner.ex` — add tenant metrics functions
- `pki_ra_engine/lib/pki_ra_engine/schema/ra_user.ex` — add tenant_id
- `pki_ra_engine/lib/pki_ra_engine/user_management.ex` — tenant filtering
- `pki_ra_engine/lib/pki_ra_engine/api/user_controller.ex` — tenant_id param
- `pki_ra_portal_web/controllers/setup_controller.ex` — tenant-aware setup
- `pki_ca_portal_web/controllers/setup_controller.ex` — tenant-aware setup
- `deploy/.env.production` — remove admin credential vars

## 13. Out of Scope

- Subscription/billing module (future)
- Tenant-specific algorithm restrictions on CSR validation
- SSDID wallet integration
- RA engine per-tenant database isolation (RA uses shared DB with tenant_id scoping)
