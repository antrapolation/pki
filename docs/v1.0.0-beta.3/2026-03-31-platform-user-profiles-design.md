# Platform-Level User Profiles for Multi-Tenant Authentication

**Date:** 2026-03-31
**Status:** Approved
**Version:** 1.0.0-beta.3

## Problem

At login time, the system doesn't know which tenant database to query. Currently, usernames encode the tenant slug (e.g., `six-corp-ca-admin`), which is a hack. The CA/RA portals authenticate against `PkiCaEngine.Repo` (the static default DB) instead of the tenant's database.

## Solution

Store user profiles and credentials in the platform database. Authentication happens against the platform DB, which resolves the user's tenant. Engine-specific data (keypairs, credentials, ACLs) stays in the tenant DB.

## Schema (Platform DB — `pki_platform_dev`)

### user_profiles

| Column | Type | Notes |
|--------|------|-------|
| id | UUID v7 | PK |
| username | string | unique, 3-50 chars |
| password_hash | string | Argon2 |
| display_name | string | |
| email | string | nullable |
| status | string | active, suspended |
| must_change_password | boolean | default false |
| credential_expires_at | utc_datetime | nullable |
| inserted_at | naive_datetime | |
| updated_at | naive_datetime | |

### user_tenant_roles

| Column | Type | Notes |
|--------|------|-------|
| id | UUID v7 | PK |
| user_profile_id | UUID FK | → user_profiles |
| tenant_id | UUID FK | → tenants |
| role | string | ca_admin, key_manager, ra_admin, ra_officer, auditor |
| portal | string | ca, ra |
| ca_instance_id | string | nullable — CA users only |
| status | string | active, suspended |
| inserted_at | naive_datetime | |
| updated_at | naive_datetime | |

**Unique constraint:** `(user_profile_id, tenant_id, portal)` — one role per portal per tenant.

## Login Flow

```
1. POST /login {username, password}
2. PlatformAuth.authenticate(username, password)
   → query platform_db.user_profiles
   → verify Argon2 password
   → return user_profile
3. PlatformAuth.get_tenant_roles(user_profile.id, portal: "ca")
   → query user_tenant_roles WHERE portal = "ca" AND status = "active"
   → return [{tenant_id, role, ca_instance_id}]
4. If one tenant: auto-select, store in session
   If zero: error "No active tenant assignment"
   If multiple: (future release) show tenant picker. For now: use first.
5. Session stores: user_profile_id, tenant_id, role, ca_instance_id
6. All subsequent requests route to tenant DB via TenantRegistry
```

## Module Changes

### New Modules (Platform Engine)

| Module | Purpose |
|--------|---------|
| `PkiPlatformEngine.UserProfile` | Ecto schema for user_profiles |
| `PkiPlatformEngine.UserTenantRole` | Ecto schema for user_tenant_roles |
| `PkiPlatformEngine.PlatformAuth` | authenticate, get_tenant_roles, create_user_profile, assign_tenant_role |

### Modified Modules

| Module | Change |
|--------|--------|
| `TenantDetailLive.ensure_admins` | Create user_profile + user_tenant_role in platform DB, then ca_user/ra_user in tenant DB |
| `CaEngineClient.Direct.authenticate` | Call PlatformAuth instead of CA UserManagement |
| `RaEngineClient.Direct.authenticate` | Call PlatformAuth instead of RA UserManagement |
| `CA SessionController` | Pass tenant_id from PlatformAuth result to session |
| `RA SessionController` | Same |

### Unchanged

- Tenant DB `ca_users` / `ra_users` — still exist for engine-specific data
- All engine CRUD operations — still use tenant DB via TenantRepo
- CA/RA engine UserManagement — still manages tenant-level user records
- Session flow after login — tenant_id in session, unchanged

## Activation Flow (Updated)

```
activate_tenant(tenant_id)
  → start engines (TenantSupervisor)
  → ensure default CA/RA instances in tenant DB
  → create user_profile in platform DB (if not exists)
  → create user_tenant_role for CA portal (ca_admin)
  → create user_tenant_role for RA portal (ra_admin)
  → create ca_user in tenant DB (linked by username)
  → create ra_user in tenant DB (linked by username)
  → send credential email
```

## Tenant DB ↔ Platform DB Link

Users are linked by `username` across databases. The platform DB is authoritative for authentication. The tenant DB stores engine-specific data.

```
Platform DB                          Tenant DB
user_profiles.username ────────────── ca_users.username
user_tenant_roles.tenant_id ───────── (the tenant's database)
user_tenant_roles.ca_instance_id ──── ca_users.ca_instance_id
```

## Future (Next Release)

- Multi-tenant user: one user_profile, multiple user_tenant_roles
- Tenant picker UI after login when user has multiple tenants
- Cross-tenant admin dashboard

## Out of Scope

- SSO/OIDC integration
- User self-registration
- Password policies (min complexity, rotation)
