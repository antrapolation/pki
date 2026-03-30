# Tenant Email Verification & Admin Credential Delivery

**Date:** 2026-03-30
**Scope:** Tenant email capture, verification, Resend API integration, CA/RA admin credential email, expiry, suspended tenant login block

---

## Flow

1. Platform admin creates tenant: name, slug, algorithm, **email**
2. System sends verification code to email via Resend API
3. Platform admin enters the code received by tenant contact
4. Tenant created, CA/RA admin accounts auto-generated with temp passwords
5. Credential email sent to tenant email with CA/RA usernames, temp passwords, portal URLs, 24h expiry warning
6. CA/RA admin logs in → forced password change on first login
7. If 24h passes without password change, credentials expire → login rejected
8. If tenant is suspended, all tenant users are blocked from login

## Schema Changes

### Tenant
- Add `email` field (string, required)

### CA User (`ca_users`)
- Add `must_change_password` (boolean, default false)
- Add `credential_expires_at` (utc_datetime, nullable)

### RA User (`ra_users`)
- Add `must_change_password` (boolean, default false)
- Add `credential_expires_at` (utc_datetime, nullable)

## Email Integration

- **Provider:** Resend API
- **API Key:** stored as env var `RESEND_API_KEY`
- **From address:** `noreply@straptrust.com` (configurable)
- **Templates:** Elixir EEx templates rendered to HTML

## Tenant Creation Wizard (3-step)

### Step 1: Tenant Info
- Name, slug, algorithm, email

### Step 2: Email Verification
- System sends 6-digit code to email
- User enters code
- Code expires in 10 minutes

### Step 3: Confirmation
- Auto-generates CA Admin (`ca_admin`) and RA Admin (`ra_admin`) usernames based on slug
- Auto-generates temporary passwords (16-char random)
- Creates tenant + CA/RA admin accounts
- Sends credential email
- Shows success page

## Login Changes

### CA Portal Login
- After successful auth, check `must_change_password`
- If true AND `credential_expires_at` has passed → reject with "Credentials expired"
- If true AND not expired → redirect to `/change-password`
- Check tenant status via tenant_id → if suspended, reject login

### RA Portal Login
- Same logic as CA Portal

## Files

### New
- `pki_platform_engine/lib/pki_platform_engine/mailer.ex` — Resend API client
- `pki_platform_engine/lib/pki_platform_engine/email_templates.ex` — EEx templates
- `pki_platform_engine/lib/pki_platform_engine/email_verification.ex` — verification code logic
- `pki_platform_engine/priv/platform_repo/migrations/TIMESTAMP_add_email_to_tenants.exs`
- `pki_ca_engine/priv/repo/migrations/TIMESTAMP_add_credential_expiry_to_ca_users.exs`
- `pki_ra_engine/priv/repo/migrations/TIMESTAMP_add_credential_expiry_to_ra_users.exs`

### Modified
- `pki_platform_engine/lib/pki_platform_engine/tenant.ex` — add email field
- `pki_platform_portal_web/live/tenant_new_live.ex` — 3-step wizard
- `pki_ca_engine/lib/pki_ca_engine/schema/ca_user.ex` — add must_change_password, credential_expires_at
- `pki_ra_engine/lib/pki_ra_engine/schema/ra_user.ex` — add must_change_password, credential_expires_at
- `pki_ca_portal_web/controllers/session_controller.ex` — check expiry + force password change
- `pki_ra_portal_web/controllers/session_controller.ex` — check expiry + force password change
- `deploy/.env.production` — add RESEND_API_KEY
