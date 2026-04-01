# User Management via Platform Auth — Design Spec

## Overview

Fix CA/RA user management to go through the platform-level auth system (`PlatformAuth` + `UserProfile` + `UserTenantRole`) instead of tenant-level `ca_users`/`ra_users` tables. Add email invitation flow for new users and comprehensive audit logging.

## Current Problem

- The CA/RA Users page creates users in the tenant DB (`ca_users`/`ra_users`), but login authenticates against the platform DB (`user_profiles` + `user_tenant_roles`).
- Users created from the Users page cannot log in.
- No audit logging for user management operations, login, or password changes.

## Data Flow

### Create User

1. CA/RA admin fills form: username, display_name, email (required), role.
2. Backend generates a random 16-character temporary password.
3. Creates `UserProfile` in platform DB with hashed password, `must_change_password: true`, `credential_expires_at: now + 24h`.
4. Creates `UserTenantRole` in platform DB with `tenant_id`, `portal` ("ca" or "ra"), `role`, `status: "active"`.
5. Sends email via `PkiPlatformEngine.Mailer` using `single_admin_credential` template with portal URL, username, and temp password.
6. Logs `user_created` to platform audit table.
7. User logs in via emailed credentials, gets forced to `/change-password`, sets their own password.

### Suspend User

- Sets `UserTenantRole.status = "suspended"`.
- User can no longer log in to this portal (PlatformAuth checks role status).
- Logs `user_suspended`.

### Activate User

- Sets `UserTenantRole.status = "active"`.
- Logs `user_activated`.

### Delete User

- Removes the `UserTenantRole` record.
- `UserProfile` stays (user may have roles in other portals/tenants).
- Logs `user_deleted`.

### Reset Password (admin action)

- Generates new 16-char temp password.
- Updates `UserProfile` password hash, sets `must_change_password: true`, `credential_expires_at: now + 24h`.
- Sends email with new credentials via `single_admin_credential` template.
- Logs `password_reset`.

### List Users

- Query `UserTenantRole` joined with `UserProfile`, filtered by `tenant_id` and `portal`.
- Returns: id, username, display_name, email, role, status, inserted_at.

## Platform Audit Log

### New Table: `platform_audit_events`

In platform DB. Fields:

- `id` — binary_id, UUID7
- `timestamp` — utc_datetime_usec
- `actor_id` — binary_id, nullable (the user performing the action)
- `actor_username` — string (denormalized for display)
- `action` — string
- `target_type` — string ("user_profile", "user_tenant_role")
- `target_id` — binary_id, nullable
- `tenant_id` — binary_id, nullable
- `portal` — string, nullable ("ca", "ra", "admin")
- `details` — map/jsonb
- `inserted_at` — timestamp

### Actions Logged

| Action | Trigger | Actor |
|--------|---------|-------|
| `login` | Successful login | The user |
| `login_failed` | Failed login attempt | null (username in details) |
| `user_created` | Admin creates user | The admin |
| `user_suspended` | Admin suspends user | The admin |
| `user_activated` | Admin activates user | The admin |
| `user_deleted` | Admin deletes user role | The admin |
| `password_reset` | Admin resets password | The admin |
| `password_changed` | User changes own password | The user |
| `profile_updated` | User updates profile | The user |

### Querying

CA/RA portals query platform audit events filtered by `tenant_id` (and optionally `portal`). This ensures tenant isolation — a CA admin only sees events for their own tenant.

## UI Changes

### Users Page (CA & RA portals)

**Create Form:**
- Fields: username, display_name, email (required), role
- No password field (system generates and emails it)
- Submit button: "Create & Send Invite"

**Table Columns:**
- Username, Name, Email, Role, Status, Actions
- Drop "Credentials" column (no longer relevant at platform level)

**Actions per user:**
- Suspend (if active) / Activate (if suspended)
- Reset Password
- Delete

### Audit Log Page

**Category filter added:**
- All
- CA Operations (existing tenant `PkiAuditTrail`)
- User Management (platform `platform_audit_events`)

Combined into one timeline sorted by timestamp. Table format unchanged: timestamp, actor, action, details.

## Backend Changes

### PlatformAuth (modify)

Add functions:
- `list_users_for_portal(tenant_id, portal)` — returns users with their roles
- `create_user_for_portal(tenant_id, portal, attrs)` — creates UserProfile + UserTenantRole, generates temp password, sends email
- `suspend_user_role(role_id)` — sets status to "suspended"
- `activate_user_role(role_id)` — sets status to "active"
- `delete_user_role(role_id)` — deletes the UserTenantRole
- `reset_user_password(user_profile_id)` — generates temp password, updates hash, sends email

### PlatformAudit (new module)

- `PkiPlatformEngine.PlatformAudit`
- `log(action, attrs)` — writes to `platform_audit_events`
- `list_events(filters)` — query with filters: tenant_id, portal, action, date range

### PlatformAuditEvent (new schema)

- `PkiPlatformEngine.PlatformAuditEvent`
- Schema for `platform_audit_events` table

### Migration

- New migration: `create_platform_audit_events` table in platform DB

### EmailTemplates (modify)

Add `user_invitation` template — similar to `single_admin_credential` but worded as an invitation (not a reset).

### CaEngineClient / RaEngineClient

Update behaviour + implementations:
- `create_user` — change to go through PlatformAuth
- `list_users` — change to query platform DB
- `delete_user` — change to delete UserTenantRole
- Add: `suspend_user`, `activate_user`, `reset_password`

### CA/RA Portal LiveViews

- `UsersLive` — update form, table, and actions
- `AuditLogLive` — add category filter, query platform audit events

### Session Controllers (CA/RA)

Add audit logging:
- `login` on successful auth
- `login_failed` on failed auth

### ProfileLive (CA/RA/Admin)

Add audit logging:
- `password_changed` on successful password change
- `profile_updated` on successful profile update

## Scope Boundaries

**In scope:**
- User CRUD via platform DB for CA and RA portals
- Email invitation with temp password
- Platform audit table + logging for all user management + auth actions
- Combined audit log view in CA/RA portals

**Out of scope:**
- Migrating existing tenant DB users to platform DB (manual or future task)
- Crypto credential generation (stays at tenant level for now)
- Platform admin portal audit log page (admin portal has its own admin management)
- Rate limiting on login attempts
