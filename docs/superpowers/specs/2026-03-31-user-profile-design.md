# User Profile Page Design

## Overview

Add a self-service `/profile` page to all three portals (Admin, CA, RA) where logged-in users can view their profile info, edit display name/email, and change their password. Single page with two card sections.

## Scope

- Minimal: view/edit profile info + change password
- No avatar, preferences, session management, or 2FA (future phases)
- Admin portal uses `PlatformAdmin` schema (not `UserProfile` — that's for future multi-tenant phase)

## Architecture

Each portal gets its own `ProfileLive` LiveView that talks to its respective engine context:

| Portal   | Schema          | Context Module         | DB             |
|----------|-----------------|------------------------|----------------|
| Admin    | PlatformAdmin   | AdminManagement        | Platform Repo  |
| CA       | CaUser          | CaEngineClient         | Tenant DB      |
| RA       | RaUser          | RaEngineClient         | Tenant DB      |

## Page Layout

Standard app layout with `page_title: "Profile"`. Two stacked cards:

### Card 1: Profile Information

Read-only fields (displayed, not editable):
- Username
- Role (badge)
- Status (badge)

Editable fields:
- Display name (text input)
- Email (email input)

Form: `phx-submit="update_profile"`

### Card 2: Change Password

Fields:
- Current password (required, for verification)
- New password (min 8 chars)
- Confirm new password (must match)

Form: `phx-submit="change_password"`

## Backend Changes

### Admin Portal (PkiPlatformEngine.AdminManagement)

Add:
- `get_admin/1` — fetch admin by ID
- `update_admin_profile/2` — update display_name, email only
- `change_admin_password/3` — verify current password, then update to new password

### CA Engine (PkiCaEngine.UserManagement)

Add:
- `update_user_profile/3` — update display_name, email for a CA user
- `verify_and_change_password/4` — verify current password, then change

Expose via `PkiCaPortal.CaEngineClient`:
- `update_profile/2`
- `change_password/3`

### RA Engine (PkiRaEngine.UserManagement)

Add:
- `update_user_profile/3` — update display_name, email for an RA user
- `verify_and_change_password/4` — verify current password, then change

Expose via `PkiRaPortal.RaEngineClient`:
- `update_profile/2`
- `change_password/3`

## Routing

### All Portals

Add under `:authenticated` live_session:
```elixir
live "/profile", ProfileLive
```

### CA & RA Portals

Redirect existing `/change-password` GET to `/profile`:
```elixir
get "/change-password", PasswordController, :edit  # redirect to /profile
```

### Admin Portal

No existing `/change-password` route — `/profile` is the only entry point.

## Navigation

Add sidebar link in all three portals, positioned at the bottom of the nav list (before footer):
```heex
<.sidebar_link href="/profile" icon="hero-user-circle" label="Profile" current={@page_title} />
```

## Session Update

After profile update, refresh the `current_user` session data so the topbar display name stays in sync. This means the `update_profile` handler must update the socket assigns.

## UI Patterns

Follow existing portal conventions:
- Cards: `card bg-base-100 shadow-sm border border-base-300`
- Inputs: `input input-bordered input-sm w-full`
- Buttons: `btn btn-primary btn-sm`
- Badges: `badge badge-sm badge-success` / `badge-primary` / `badge-warning`
- Labels: `text-xs font-medium text-base-content/60 mb-1`
- Flash messages via existing toast system

## Validation

- Display name: optional, max 100 chars
- Email: optional, valid format
- Current password: required for password change, must match
- New password: min 8, max 100 chars
- Password confirmation: must match new password

## Error Handling

- Invalid current password: flash error "Current password is incorrect"
- Validation errors: inline under fields
- Success: flash info "Profile updated" or "Password changed successfully"
