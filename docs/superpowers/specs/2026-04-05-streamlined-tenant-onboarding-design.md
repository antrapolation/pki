# Streamlined Tenant Onboarding — Design Spec

**Date:** 2026-04-05
**Status:** Approved

---

## Problem

The current tenant onboarding flow requires 5 phases across multiple pages: fill form, verify email (6-digit OTP with inbox context switch), wait for DB provisioning, manually deploy engines, and manually click Activate from the tenant detail page. The entire process takes 5-15 minutes and involves 3+ clicks plus out-of-band actions.

In reality, the CA/RA engines are already running in the same BEAM node and tenant-specific processes (Ecto repos) spawn in ~1-2 seconds. Database provisioning takes ~1-2.5 seconds. There is no technical reason for the multi-step flow.

## Solution

Replace the multi-step wizard with a single-form, single-click onboarding that provisions, activates, and sets up the tenant in ~2-4 seconds. Introduce a `tenant_admin` role in the Platform Portal so tenant administrators can self-serve CA/RA user creation.

---

## 1. Onboarding Wizard — Single Form, Single Click

### Form Fields

| Field | Required | Validation |
|-------|----------|-----------|
| **Name** | Yes | Non-empty |
| **Slug** | Yes | Lowercase alphanumeric + hyphens, must start/end with letter or number |
| **Email** | Yes | Regex format validation only (no OTP verification) |

Email is the tenant admin's email address. Platform Portal login credentials will be sent here.

### Provisioning Chain

On form submit, the form fields become read-only and a progress checklist appears below. Each step executes synchronously; the UI updates in real-time via LiveView.

| Step | Label | Backend Operation | Est. Time |
|------|-------|-------------------|-----------|
| 1 | "Database created" | `Provisioner.create_tenant/3` — CREATE DATABASE, apply CA + RA schemas, run tenant migrations | ~1-2.5s |
| 2 | "Engines started" | `Provisioner.activate_tenant/1` — spawn 3 Ecto repos (ca, ra, audit) via TenantSupervisor, register in ETS, set status "active" | ~0.3-1.5s |
| 3 | "CA and RA instances created" | Create default "{Name} Root CA" and "{Name} RA" instances in tenant DB | ~10ms |
| 4 | "Tenant admin account created" | Create user profile (username: `{slug}-admin`), assign `tenant_admin` role scoped to this tenant with `portal: "platform"` | ~50ms |
| 5 | "Credentials sent" | Email Platform Portal login credentials (temp password) to the tenant admin email | ~100ms |

**Total estimated time: ~2-4 seconds.**

### Success State

```
✓ Database created
✓ Engines started
✓ CA and RA instances created
✓ Tenant admin account created
✓ Credentials sent to admin@acme.com

Tenant "Acme Corp" is ready.

[View Tenant]  [Create Another]
```

### Error Handling

If any step fails, progress stops at that step with an error message and a **Retry** button. Retry resends the failed step's message (operations are idempotent):
- `create_tenant` cleans up the DB on failure
- `activate_tenant` handles `{:error, {:already_started, pid}}`
- Admin creation checks if user already exists
- Email send failure is non-critical (logged, credentials can be resent from detail page)

### LiveView State

```elixir
%{
  phase: :form | :provisioning,
  form_data: %{name: "", slug: "", email: ""},
  progress: [
    {:database, :pending | :in_progress | :done | {:error, String.t()}},
    {:engines, :pending | :in_progress | :done | {:error, String.t()}},
    {:instances, :pending | :in_progress | :done | {:error, String.t()}},
    {:tenant_admin, :pending | :in_progress | :done | {:error, String.t()}},
    {:credentials, :pending | :in_progress | :done | {:error, String.t()}}
  ],
  tenant: nil | %Tenant{},
  error: nil | String.t()
}
```

### Message Flow

```
handle_event("submit")          → phase = :provisioning, send(:run_provision)
handle_info(:run_provision)     → create_tenant → update progress → send(:run_activate)
handle_info(:run_activate)      → activate_tenant → update progress → send(:run_instances)
handle_info(:run_instances)     → create CA + RA instances → update progress → send(:run_tenant_admin)
handle_info(:run_tenant_admin)  → create tenant_admin user → update progress → send(:run_credentials)
handle_info(:run_credentials)   → send email → update progress → done
```

---

## 2. Tenant Admin Role

### Role Definition

A new role `tenant_admin` is added to the Platform Portal. Tenant admins can log in to the Platform Portal and manage users for their own tenant only.

| Role | Scope | Access |
|------|-------|--------|
| **super_admin** (existing) | Platform-wide | All tenants, admins, HSM devices, system health, sessions |
| **tenant_admin** (new) | Single tenant | Their tenant detail, CA/RA user management for their tenant, own profile |

### Storage

The `tenant_admin` role is stored in the existing `user_tenant_roles` table:

| Column | Value |
|--------|-------|
| `user_profile_id` | The tenant admin's user profile ID |
| `tenant_id` | The tenant they belong to |
| `role` | `tenant_admin` |
| `portal` | `platform` |
| `status` | `active` |

No schema changes needed — the table already supports arbitrary role/portal combinations.

### Authentication & Routing

On login to the Platform Portal:

1. Check `platform_admins` table (existing flow for superadmins)
2. If not found, check `user_profiles` + `user_tenant_roles` where `role = "tenant_admin"` and `portal = "platform"` and `status = "active"`
3. If authenticated as `tenant_admin`, set session with `tenant_id` scoping

Route scoping after login:

| Route | super_admin | tenant_admin |
|-------|-------------|-------------|
| `/` (dashboard) | Full dashboard | Tenant-scoped dashboard (their tenant only) |
| `/tenants` | All tenants | Redirect to `/tenants/:their_tenant_id` |
| `/tenants/:id` | Any tenant | Only their tenant (403 otherwise) |
| `/tenants/new` | Allowed | Not allowed (403) |
| `/hsm-devices` | Allowed | Not allowed (403) |
| `/system` | Allowed | Not allowed (403) |
| `/admins` | Allowed | Not allowed (403) |
| `/sessions` | Allowed | Not allowed (403) |
| `/profile` | Allowed | Allowed |

### Tenant Admin — Scoped Tenant Detail View

When a tenant admin views their tenant detail page, they see:

- Tenant info (name, slug, email, status) — read-only
- Engine status (online/offline) — read-only
- Health metrics — read-only
- **User management section** — this is their primary action area:
  - Create CA users (ca_admin, key_manager, auditor)
  - Create RA users (ra_admin, ra_officer, auditor)
  - View/suspend/delete existing users
  - Each user creation sends a temp password email

They do NOT see:
- Activate/Suspend/Delete tenant buttons
- HSM device access management
- Credential reset buttons (they manage individual users instead)

---

## 3. Tenant Admin Onboarding Flow (End-to-End)

After the platform superadmin creates a tenant:

```
Platform Superadmin                    Tenant Admin                         CA/RA Admin
─────────────────                      ────────────                         ───────────
1. Fill form + click                   
   "Create Tenant"                     
   (~3 seconds)                        
                        ──email──→     2. Receives Platform Portal
                                          credentials (temp password)
                                       
                                       3. Logs in to Platform Portal
                                          → forced password change
                                       
                                       4. Sees their tenant detail
                                          + user management
                                       
                                       5. Creates CA admin account
                                          (role, email)
                                                          ──email──→    6. Receives CA Portal
                                                                           credentials
                                       7. Creates RA admin account
                                          (role, email)
                                                          ──email──→    8. Receives RA Portal
                                                                           credentials
                                       
                                                                        9. CA admin logs in
                                                                           → setup keystores,
                                                                           ceremonies, etc.
                                                                        
                                                                        10. RA admin logs in
                                                                            → setup profiles,
                                                                            service configs, etc.
```

---

## 4. What Gets Removed

| Component | File(s) | Reason |
|-----------|---------|--------|
| Email verification step | `tenant_new_live.ex` (step 2 UI), `EmailVerification` GenServer calls | Replaced by regex validation |
| Step indicator UI | `tenant_new_live.ex` | No longer multi-step |
| Manual activation in onboarding | `tenant_new_live.ex` (step 5 "Next Steps") | Activation happens automatically |
| Auto CA/RA admin creation on activate | `tenant_detail_live.ex` (`:ensure_admins` handler) | Tenant admin creates these via platform portal |
| Credential email on activate | `tenant_detail_live.ex` (`:ensure_admins` → `Mailer.send_email`) | No longer auto-creating CA/RA admins |
| "Resend Credentials" button | `tenant_detail_live.ex` | Superadmin no longer manages tenant-level CA/RA users |
| "Reset CA Admin" button | `tenant_detail_live.ex` | Same |
| "Reset RA Admin" button | `tenant_detail_live.ex` | Same |
| CA Portal `/setup` page | CA portal | Users created via platform portal, not self-serve setup |
| RA Portal `/setup` page | RA portal | Same |

## 5. What Gets Added

| Component | Description |
|-----------|-------------|
| Single-form wizard with progress | New `tenant_new_live.ex` — form + live progress checklist |
| Provisioning chain | Extract + combine provisioning logic into callable sequence |
| `tenant_admin` role | New role in `user_tenant_roles` (portal: `platform`) |
| Platform Portal auth for tenant_admin | Extend login to check `user_tenant_roles` for `tenant_admin` |
| Route scoping | Restrict tenant_admin to their tenant's pages only |
| Scoped tenant detail view | Tenant admin sees user management, not admin-level actions |
| User management UI | Tenant admin creates/manages CA and RA users for their tenant |
| Tenant admin creation in onboarding | Provisioning chain step 4 creates the tenant_admin account |

## 6. What Stays Unchanged

| Component | Notes |
|-----------|-------|
| `tenants_live.ex` (list page) | No changes — superadmin only |
| Tenant detail page (superadmin view) | Keeps Activate/Suspend/Delete for lifecycle management |
| HSM device management | Superadmin only |
| System health, sessions, admins pages | Superadmin only |
| `Provisioner.create_tenant/3` | No changes to the function itself |
| `Provisioner.activate_tenant/1` | No changes |
| `TenantSupervisor`, `TenantProcess`, `TenantRegistry` | No changes |
| Existing user creation flow | Reused by tenant admin for CA/RA user creation |
