# Forgot Password — All 3 Portals

**Date:** 2026-03-30
**Scope:** Platform Admin Portal, CA Portal, RA Portal

## Overview

Self-service password reset using a 6-digit email verification code. Reuses the existing `EmailVerification` GenServer (ETS-backed, 10-minute expiry) and `Mailer` module (Resend API).

## User Flow

All three portals share the same 3-step flow:

1. **Enter username** — user clicks "Forgot password?" on login page, enters their username
2. **Enter code** — if the username maps to a user with an email on file, a 6-digit code is sent. User sees a code entry form plus new password fields
3. **Submit** — code is validated, password is updated, user is redirected to login with a success flash

Security: if the username is not found or has no email, the same "code sent" message is shown (no user enumeration).

## Schema Changes

### PlatformAdmin

Add optional `email` (string) field. Migration on `pki_platform_engine`.

### CaUser

Add optional `email` (string) field. Migration on `pki_ca_engine`.

### RaUser

Add optional `email` (string) field. Migration on `pki_ra_engine`.

Email is optional because existing users won't have one. Users without an email cannot use forgot password (they must contact their admin for a credential reset).

## Backend Changes

### Per Engine

Each engine's user management module gets two new functions:

- `get_user_by_username(username)` — returns `{:ok, user}` or `:error`. For CA engine, scoped to `ca_instance_id`; for RA engine, scoped to `tenant_id`.
- `reset_password(user_id, new_password)` — updates password hash using the existing password changeset. Clears `must_change_password` and `credential_expires_at` if present.

**CA Engine** — `PkiCaEngine.UserManagement`
- `get_user_by_username(username, ca_instance_id)`
- `reset_password(user_id, new_password, ca_instance_id)`

**RA Engine** — `PkiRaEngine.UserManagement`
- `get_user_by_username(username, tenant_id)`
- `reset_password(user_id, new_password, tenant_id)`

**Platform Engine** — `PkiPlatformEngine.AdminManagement`
- `get_admin_by_username(username)`
- `reset_password(admin_id, new_password)`

### CA/RA Engine API Endpoints

New internal API routes (protected by `INTERNAL_API_SECRET`):

- `GET /api/v1/users/by-username/:username` — returns user ID and email (masked)
- `PUT /api/v1/users/:id/reset-password` — accepts `password` + `password_confirmation`, updates password

### Email Template

New `password_reset_code/1` function in `PkiPlatformEngine.EmailTemplates`. Same visual style as the existing `verification_code/1` template but with "Password Reset" heading and context text.

### Code Generation & Validation

Reuse `PkiPlatformEngine.EmailVerification`:
- `generate_code(email)` — stores 6-digit code in ETS, 10-minute TTL
- `verify_code(email, code)` — validates and deletes code on success

The EmailVerification GenServer is already started by the Platform Engine application. CA and RA portals can call it directly since `pki_platform_engine` is a dependency.

## Portal Changes

### Per Portal: ForgotPasswordController

New controller with these actions:

| Action | Method | Path | Purpose |
|--------|--------|------|---------|
| `new` | GET | `/forgot-password` | Show username form |
| `create` | POST | `/forgot-password` | Look up user, send code, show code form |
| `update` | PUT | `/forgot-password` | Validate code, reset password |

Session state between steps:
- After step 1: store `reset_user_id` and `reset_email` in session
- After step 3: clear reset session keys

### Per Portal: Templates

Three templates in `forgot_password_html/`:
- `new.html.heex` — username input form
- `code.html.heex` — code input + new password + confirmation
- (success redirects to login, no separate template needed)

### Per Portal: Router

Add to the public (unauthenticated) scope:

```elixir
get "/forgot-password", ForgotPasswordController, :new
post "/forgot-password", ForgotPasswordController, :create
put "/forgot-password", ForgotPasswordController, :update
```

### Login Page

Add "Forgot password?" link below the sign-in button on each portal's `login.html.heex`.

## Portal-Specific Details

### Platform Portal

- Calls `PkiPlatformEngine.AdminManagement` directly (no HTTP API)
- Calls `PkiPlatformEngine.EmailVerification` and `Mailer` directly

### CA Portal

- Calls CA Engine HTTP API (`/api/v1/users/by-username/:username`) to look up user
- Calls `PkiPlatformEngine.EmailVerification` and `Mailer` directly for code/email
- Calls CA Engine HTTP API (`/api/v1/users/:id/reset-password`) to update password
- Passes `ca_instance_id` (hardcoded "default" for now, same as login)

### RA Portal

- Calls RA Engine HTTP API (`/api/v1/users/by-username/:username`) to look up user
- Calls `PkiPlatformEngine.EmailVerification` and `Mailer` directly for code/email
- Calls RA Engine HTTP API (`/api/v1/users/:id/reset-password`) to update password
- Needs `tenant_id` — user must also enter tenant ID, or we look up across tenants by username (username is unique per tenant, so we search all and return the match)

### RA Portal Tenant Resolution

RA users are scoped by `tenant_id`. For forgot password, the simplest approach: add a `tenant_id` hidden field or have the RA portal look up the user across all non-suspended tenants by username. Since usernames are unique within a tenant but could collide across tenants, we search all active tenants and:
- If exactly one match: proceed
- If multiple matches: ask user to also provide their tenant name
- If no match: show generic "code sent" message

## Password Validation

Same rules as existing password change:
- Minimum 8 characters
- Password confirmation must match

## Security Considerations

- Generic response on unknown username (no enumeration)
- 10-minute code expiry (existing ETS behavior)
- Code is single-use (deleted on successful verification)
- No rate limiting for now (internal system, small user base)
- Reset clears `must_change_password` and `credential_expires_at`
- Session reset keys are cleared after successful password change

## Out of Scope

- Rate limiting (can add later)
- Password complexity rules beyond minimum length
- Account lockout after failed reset attempts
- Email change/update UI (admin sets email during user creation for now)
