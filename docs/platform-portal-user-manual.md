# Platform Portal — User Manual

**PQC Certificate Authority System | Antrapolation Technology Sdn Bhd**

---

## Table of Contents

1. [Introduction](#introduction)
2. [First-Time Setup](#first-time-setup)
3. [Login & Session Security](#login)
4. [Dashboard](#dashboard)
5. [Tenant Management](#tenants)
   - [Tenant List](#tenant-list)
   - [Creating a New Tenant](#tenant-create)
   - [Tenant Detail & Configuration](#tenant-detail)
   - [Tenant Lifecycle](#tenant-lifecycle)
   - [Tenant Onboarding Flow](#tenant-onboarding)
   - [User Invite Flow (CA / RA Users)](#user-invite)
6. [HSM Device Management](#hsm-devices)
7. [Platform Admin Management](#admins)
8. [System Health Monitoring](#system-health)
9. [Active Sessions](#sessions)
10. [Profile & Password Management](#profile)
11. [Forgot Password](#forgot-password)
12. [Security Reference](#security)
13. [Troubleshooting](#troubleshooting)

---

## 1. Introduction <a name="introduction"></a>

The **Platform Portal** is the top-level administration interface for the PQC Certificate Authority System. It is used by platform superadmins to:

- **Provision tenants** — Create isolated CA/RA environments for each organization
- **Manage HSM devices** — Register and assign PKCS#11 Hardware Security Modules
- **Monitor infrastructure** — Real-time health checks across all services
- **Manage platform admins** — Invite and control platform administrator accounts
- **Oversee sessions** — Monitor and force-logout active sessions across all portals

Each tenant receives its own isolated database, CA engine, RA engine, and user accounts. The Platform Portal is the control plane that manages all of them.

| Default URL | `https://your-domain:4006` |
|---|---|
| **Audience** | Platform superadmins |
| **Browser requirements** | Modern browser (Chrome, Firefox, Safari, Edge) with JavaScript enabled |

### Navigation

The sidebar provides access to all Platform Portal pages:

| Menu Item | Page |
|-----------|------|
| **Dashboard** | Overview of tenants and service health |
| **Tenants** | Tenant list, creation, and management |
| **HSM Devices** | Hardware Security Module registration |
| **System** | Infrastructure health monitoring |
| **Admins** | Platform administrator accounts |
| **Profile** | Your account settings |

The top bar displays the current page title, your display name, and a **Sign out** button.

---

## 2. First-Time Setup <a name="first-time-setup"></a>

On a fresh deployment, the Platform Portal requires you to create the first administrator account before anything else can be done. All pages redirect to the Setup page until this is complete.

### Steps

1. Navigate to `https://your-domain:4006/setup`
2. You will see the heading **"Platform Setup"** with the subtitle *"Create the first administrator account"*
3. Fill in the form:

| Field | Placeholder | Description |
|-------|-------------|-------------|
| **Username** | `admin` | Login identifier |
| **Display Name** | `Platform Admin` | Full name for display |
| **Password** | — | Minimum 8 characters |
| **Confirm Password** | — | Must match the password |

4. Click **Create Admin Account** (button shows *"Creating account..."* while processing)
5. You are redirected to the login page

No email is required during initial setup. You can add your email later from the **Profile** page after logging in.

> **Note:** The Setup page is only available once. After the first admin is created, all visits to `/setup` redirect to the login page.

> **Automated deployments:** You can bootstrap the initial admin via environment variables `PLATFORM_ADMIN_USERNAME` and `PLATFORM_ADMIN_PASSWORD` instead of using the web form.

---

## 3. Login & Session Security <a name="login"></a>

### Logging In

1. Navigate to `https://your-domain:4006/login`
2. Enter your **Username** and **Password**
3. Click **Sign In**

If your account was created with temporary credentials (via invitation or password reset), you will be redirected to a **Change Password** page and must set a new password before proceeding.

If your temporary credentials have expired, you will see: *"Your temporary credentials have expired. Contact another platform admin."*

### Session Behavior

Once logged in, your session is maintained server-side with the following protections:

| Protection | Details |
|------------|---------|
| **Idle timeout** | Sessions expire after 30 minutes of inactivity |
| **Timeout warning** | A modal appears 5 minutes before expiration: *"Your session will expire in X minutes due to inactivity."* Click **Continue Working** to extend |
| **Rate limiting** | 5 failed login attempts per 5 minutes per IP address |
| **IP pinning** | Sessions are bound to your IP address; changes trigger a security alert |
| **User-agent matching** | If your browser fingerprint changes mid-session, the session is terminated (hijack detection) |

### Logging Out

Click **Sign out** in the top-right corner of any page.

---

## 4. Dashboard <a name="dashboard"></a>

The Dashboard is the landing page after login. It provides a high-level overview of your PKI deployment.

> **Note:** Users whose role is `tenant_admin` are redirected directly to their tenant detail page and do not see the platform-wide dashboard.

### Summary Cards

Cards are arranged in two rows:

**Row 1**

| Card | Description |
|------|-------------|
| **Total Tenants** | Total number of provisioned tenant organizations |
| **Active** | Tenants currently operational (green) |
| **Suspended** | Tenants temporarily disabled (yellow) |
| **Create Tenant** *(quick action)* | Clickable card that navigates to the Tenants page to start the creation workflow |

**Row 2**

| Card | Description |
|------|-------------|
| **Pending Setup** | Tenants provisioned but not yet activated (`initialized` state) |
| **Services** | Healthy services out of total monitored (e.g., `5/6 healthy`). Card turns amber if any service is unhealthy. |

### Recent Tenants

A table showing the 5 most recently created tenants:

| Column | Description |
|--------|-------------|
| **Name** | Tenant display name |
| **Slug** | URL-safe identifier |
| **Status** | Current status badge (active/suspended/initialized) |
| **Email** | Admin contact email |
| **Created** | Date created |

Click **View all** to go to the full Tenants page.

If no tenants exist yet, you will see: *"No tenants yet."* with a link to *"Create your first tenant"*.

---

## 5. Tenant Management <a name="tenants"></a>

### 5.1 Tenant List <a name="tenant-list"></a>

Navigate to **Tenants** in the sidebar. The page header shows **"Tenants"** with the total count.

#### Table

| Column | Description |
|--------|-------------|
| **Name** | Tenant display name |
| **Slug** | URL-safe identifier used in routing |
| **Status** | Badge: **active** (green), **suspended** (yellow), or **initialized** (blue) |
| **Email** | Admin contact email |
| **Created** | Creation date |
| **Actions** | Action icons (see below) |

The table is paginated (10 per page). A status bar shows: *"Showing 1–10 of 25"* with page navigation.

#### Actions

| Icon | Action | Available When |
|------|--------|---------------|
| Eye | **View Details** — Open tenant detail page | Always |
| Play | **Activate** — Start the tenant | Status is initialized or suspended |
| Pause | **Suspend** — Temporarily disable tenant | Status is active or initialized |
| Trash | **Delete** — Permanently remove tenant | Status is suspended only |

Suspend and Delete actions require confirmation:
- Suspend: *"Are you sure you want to suspend this tenant?"*
- Delete: *"Are you sure? This will permanently delete the tenant and its database."*

Click **New Tenant** in the top-right to start the creation workflow.

### 5.2 Creating a New Tenant <a name="tenant-create"></a>

Click **New Tenant** from the tenant list (or **Create Tenant** from the Dashboard) to open the creation page. Click **Back to Tenants** at any time to cancel.

Tenant creation is a two-phase experience: a short form, followed by an automatic provisioning chain that runs in the background while you watch the progress live.

#### Phase 1 — Tenant Form

Heading: *"Create Tenant"*
Subtitle: *"Enter the details for the new Certificate Authority tenant."*

| Field | Required | Placeholder | Validation |
|-------|----------|-------------|------------|
| **Name** | Yes | `Acme Corporation` | Cannot be empty |
| **Slug** | Yes | `acme-corp` | Lowercase alphanumeric + hyphens only; must start and end with a letter or number |
| **Email** | Yes | `admin@acme-corp.com` | Must be a valid email address |

Helper text below Slug: *"Lowercase alphanumeric with hyphens (e.g. `acme-corp`)"*
Helper text below Email: *"Tenant admin credentials will be sent to this email."*

Buttons: **Cancel** | **Create Tenant** (shows *"Creating..."* while submitting)

> **Note:** There is no email verification step. The address you enter is where the initial tenant admin credentials will be sent, so make sure it is correct before submitting.

#### Phase 2 — Provisioning

After you submit, the page switches to a live checklist:

Heading: *"Creating [Name]"*
Subtitle: *"Setting up the tenant environment..."*

The system runs the following steps automatically and updates each row with a spinner → green check in real time:

| # | Step | What Happens |
|---|------|--------------|
| 1 | **Database created** | An isolated PostgreSQL database is created and CA/RA schemas are applied |
| 2 | **Engines started** | Tenant CA and RA engine processes are started under the BEAM tenant supervisor |
| 3 | **CA and RA instances created** | Default instance records are registered inside the tenant database |
| 4 | **Tenant admin account created** | A `tenant_admin` user is provisioned in the **platform portal** for this tenant |
| 5 | **Credentials sent** | An invitation email with a temporary password is sent to the address you entered |

If any step fails, its row turns red, the error is shown in an alert, and a **Retry** button appears. Clicking Retry re-runs the failed step (earlier completed steps are kept).

#### Success State

Once all five steps are green, a success card appears:

> ✓ **Tenant "[Name]" is ready.**
> Credentials sent to [email].

Buttons:
- **View Tenant** — opens the tenant detail page
- **Create Another** — returns to an empty creation form

> **What happens next:** The tenant admin will receive an email containing a temporary password and a link to the Platform Portal. They must sign in, change their password, and can then manage CA and RA users for their tenant. See [§5.5 Tenant Onboarding Flow](#tenant-onboarding).

### 5.3 Tenant Detail & Configuration <a name="tenant-detail"></a>

Click the **View Details** (eye icon) action on any tenant to open its detail page. Click **Back to Tenants** to return to the list.

#### Tenant Information

The top card shows the tenant name, status badge, and a details grid:

| Field | Description |
|-------|-------------|
| **Slug** | URL-safe identifier |
| **Email** | Admin contact email — click the pencil icon to edit inline (super_admin only) |
| **Database** | Internal database name |
| **Created** | Creation date |

Action buttons (shown based on current status and only to super_admins):

| Button | Available When | Behavior |
|--------|----------------|----------|
| **Activate** | `initialized` or `suspended` | Starts the tenant engine processes via the BEAM tenant supervisor and flips the tenant to `active` |
| **Suspend** | `active` | Confirmation: *"Are you sure you want to suspend "[name]"?"* Stops engine processes and blocks tenant user logins. |
| **Delete** | `suspended` | Confirmation: *"This will permanently delete "[name]" and its database. This action cannot be undone. Continue?"* |
| **Refresh** | Always | Re-checks engine connectivity |

#### Engine Status

Real-time status for the tenant's CA and RA engines (checked via the in-process BEAM tenant registry):

| Status | Indicator | Meaning |
|--------|-----------|---------|
| **Online** | Green "Online" badge | Engine processes are running under the tenant supervisor |
| **Offline** | Red "Offline" badge | No engine processes found for this tenant |
| **Checking** | Grey badge with spinner | Lookup in progress |

A small monospace timer next to the badges shows how long the last check took. Click **Refresh** to re-check.

#### User Management

> **Visible only when the tenant status is `active`.**

When a tenant is active, the detail page exposes two user-management cards:

##### CA Portal Users

Heading: **CA Portal Users** with a count badge.

Table columns: **Username**, **Display Name**, **Role**, **Status**, **Actions**.

Click **+ Add User** to reveal an inline form:

| Field | Placeholder | Description |
|-------|-------------|-------------|
| **Username** | `e.g. jdoe` | Unique login identifier |
| **Display Name** | `e.g. Jane Doe` | Full name for the UI |
| **Email** | `jane@example.com` | Where the invitation will be sent |
| **Role** | dropdown | `CA Admin`, `Key Manager`, or `Auditor` |

Buttons: **Cancel** | **Create & Send Invite** (*"Creating..."* while submitting).

On success, you see: *"User created. Credentials sent to [email]."* The user appears in the table, and an invitation email with a temporary password is sent to the portal host defined by `CA_PORTAL_HOST`.

**Row actions:**

| Icon | Action | Confirmation |
|------|--------|--------------|
| Pause | **Suspend user** (when active) | *"Suspend [username]?"* |
| Play | **Activate user** (when suspended) | None |
| Trash | **Remove user** | *"Remove [username] from CA portal?"* |

If there are no users yet, the card shows: *"No CA users yet."*

##### RA Portal Users

Identical layout to the CA Portal Users card, with role dropdown values `RA Admin`, `RA Officer`, `Auditor`, and the portal host defined by `RA_PORTAL_HOST`.

> **Tenant must be active.** If the tenant is not active when you submit the form, you will see the inline error: *"Tenant must be activated before creating users."*

See [§5.6 User Invite Flow](#user-invite) for the end-to-end lifecycle of these invitations.

#### Health Metrics

Loaded asynchronously. Displays operational metrics for the tenant:

| Metric | Description |
|--------|-------------|
| **DB Size** | Storage consumed by the tenant's database |
| **CA Users** | Number of CA portal user accounts |
| **RA Users** | Number of RA portal user accounts |
| **Certs Issued** | Total certificates issued by this CA |
| **Active Certs** | Currently valid (non-revoked, non-expired) certificates |
| **Pending CSRs** | Certificate Signing Requests awaiting review |
| **CA Instances** | Number of CA engine instances |
| **RA Instances** | Number of RA engine instances |

#### HSM Device Access

> **Visible only when the tenant status is `active` and you are a super_admin.**

Heading: *"HSM Device Access"*
Description: *"Assign PKCS#11 HSM devices to this tenant. The tenant's CA admin will see assigned devices when creating HSM-backed keystores."*

Two sections:

**Available Devices** — HSM devices not yet assigned to this tenant. Click **Grant** to assign.

**Assigned Devices** — HSM devices currently accessible by this tenant. Click **Revoke** to remove access.

Each device row shows: Device label, Manufacturer, Slot ID, and an action button.

Revoking shows a confirmation: *"Revoke [device-label] access from this tenant? Existing keystores using this device will still work, but no new keystores can be created with it."*

If no HSM devices are registered, you will see a link: *"Register one first."* which navigates to the HSM Devices page.

### 5.4 Tenant Lifecycle <a name="tenant-lifecycle"></a>

Tenants follow this lifecycle:

```
                 ┌────────────────────┐
                 │                    │
                 ▼                    │
  ┌─────────────────┐    ┌───────────┴───┐    ┌─────────────┐
  │  Initialized    │───▶│    Active      │───▶│  Suspended   │───▶ Deleted
  │  (provisioned)  │    │  (running)     │    │  (disabled)  │
  └─────────────────┘    └───────────────┘    └─────────────┘
          │                                          │
          └──────────────────────────────────────────┘
                       (can also suspend directly)
```

| Transition | What Happens |
|------------|-------------|
| **Initialized → Active** | Tenant engine processes start under the BEAM tenant supervisor. The User Management section of the tenant detail page becomes available so a platform admin or tenant admin can invite CA/RA users. |
| **Active → Suspended** | Engine processes stop. Users can no longer log in to the tenant's CA or RA portals. Existing certificates remain valid. The User Management and HSM Device Access sections are hidden. |
| **Suspended → Active** | Engine processes restart. Users regain access. |
| **Suspended → Deleted** | The tenant database is permanently dropped. All data (users, keys, certificates) is destroyed. **This cannot be undone.** |

> **Note:** During tenant **creation** (§5.2) the provisioning chain already starts engines and creates the initial `tenant_admin` user, so a freshly created tenant lands in `active` state with its tenant admin already invited. You only need the `Initialized → Active` transition if a tenant was explicitly left in the `initialized` state or previously suspended.

> **Important:** A tenant must be **suspended** before it can be deleted. Active tenants cannot be deleted directly.

### 5.5 Tenant Onboarding Flow <a name="tenant-onboarding"></a>

This section describes the end-to-end flow from the moment a platform admin clicks **Create Tenant** to the moment the tenant starts managing their own CA/RA users.

#### Actors

| Actor | Role |
|-------|------|
| **Platform Admin** | A `super_admin` on the Platform Portal |
| **Tenant Admin** | The first user of the new tenant, created automatically during provisioning with the role `tenant_admin` |
| **Email System** | Delivers invitation and credential emails via the platform engine's email transport |

#### Step-by-step

1. **Platform Admin fills the tenant form** — Name, Slug, Email. See [§5.2](#tenant-create).
2. **Provisioning chain runs automatically** — The five steps (database, engines, instances, tenant_admin, credentials) execute in order. The Platform Admin sees a live checklist.
3. **Tenant admin user is created** — During step 4 (`Tenant admin account created`) the platform engine creates a `UserProfile` in the **platform portal** database with:
   - `role = "tenant_admin"`
   - A generated temporary password
   - `must_change_password = true`
4. **Invitation email is sent** — During step 5 (`Credentials sent`) the engine sends an email to the address entered in step 1. The email contains:
   - The tenant name
   - The username and **temporary password**
   - A link to the **Platform Portal** (`https://<PLATFORM_PORTAL_HOST>`)
5. **Tenant Admin receives the email and signs in** — They visit the Platform Portal login page and enter the username and temporary password.
6. **Forced password change** — Because `must_change_password` is `true`, login immediately redirects to `/change-password`. The Tenant Admin enters their current (temporary) password, a new password (minimum 8 characters), and confirms it.
7. **Auto-redirect to tenant detail** — After changing the password, the Tenant Admin lands on the Dashboard. Because their role is `tenant_admin`, they are automatically redirected from the Dashboard to **their** tenant's detail page (`/tenants/:id`).
8. **Tenant Admin manages users from the tenant detail page** — From the User Management section (visible because the tenant is `active`), they invite CA Portal and RA Portal users. See [§5.6](#user-invite).

#### What the Tenant Admin can and cannot see

The `tenant_admin` role is scoped to a **single tenant**. On the Platform Portal they can:

- View their own tenant's detail page
- Invite, suspend, activate, and remove CA/RA portal users for that tenant
- Edit their own profile and password

They **cannot** see the Tenants list, HSM Devices page, System page, Admins page, or any other tenant's data. These navigation items are hidden in the sidebar (which only renders them for `super_admin`).

#### If the invitation is lost or expired

- **Temporary credentials expire after 24 hours.** If the Tenant Admin tries to log in after that window, they will see: *"Your temporary credentials have expired. Contact another platform admin."*
- A Platform Admin can reset the tenant admin by using **Forgot Password** on the Platform Portal, or by deleting and re-inviting the tenant admin via platform tooling.

---

### 5.6 User Invite Flow (CA / RA Users) <a name="user-invite"></a>

This flow describes how CA Portal and RA Portal users are invited from the Platform Portal. Unlike the tenant onboarding flow, these users log in to the **CA Portal** or **RA Portal** — not the Platform Portal.

#### Who can trigger it

- **Platform Admins** (`super_admin`) from any active tenant's detail page
- **Tenant Admins** (`tenant_admin`) from their own tenant's detail page

#### Prerequisites

- The tenant must be in the **`active`** state. If it isn't, the User Management section is hidden, and attempting to create a user will return the error: *"Tenant must be activated before creating users."*
- For CA portal invites, `CA_PORTAL_HOST` must be configured (defaults to `ca.straptrust.com`).
- For RA portal invites, `RA_PORTAL_HOST` must be configured (defaults to `ra.straptrust.com`).

#### Step-by-step

1. **Open tenant detail** — Navigate to the tenant's detail page and scroll to **User Management**.
2. **Choose the portal** — Click **+ Add User** on either the **CA Portal Users** card or the **RA Portal Users** card. An inline form expands.
3. **Fill the form:**
   - **Username** — e.g. `jdoe`
   - **Display Name** — e.g. `Jane Doe`
   - **Email** — where the invitation will be sent
   - **Role** — select from the dropdown:
     - CA portal roles: `CA Admin`, `Key Manager`, `Auditor`
     - RA portal roles: `RA Admin`, `RA Officer`, `Auditor`
4. **Submit** — Click **Create & Send Invite**. The backend (`PlatformAuth.create_user_for_portal/4`) performs the following atomically:
   - Generates a random temporary password
   - Creates a `UserProfile` with `must_change_password = true`
   - Creates a `UserTenantRole` binding the user to this tenant with the chosen portal and role
   - Sends an invitation email containing the tenant name, role, username, temporary password, and the target portal URL
5. **Confirmation flash** — You see: *"User created. Credentials sent to [email]."* The user appears in the portal's user table with status `active`.
6. **Invitee receives the email** — The email links to the CA or RA portal login page and includes the temporary password.
7. **First login** — The invitee signs in to the CA or RA portal with their username and temporary password. The portal detects `must_change_password` and immediately redirects them to its own change-password screen.
8. **Password set** — After confirming a new password, the invitee is granted full access to the portal with their assigned role.

#### Ongoing management

From the same User Management section, the inviter can at any time:

| Action | Effect |
|--------|--------|
| **Suspend** | Sets the user's role status to `suspended`. They can no longer log in. Confirmation: *"Suspend [username]?"* |
| **Activate** | Reverses a suspension. No confirmation. |
| **Remove** | Deletes the `UserTenantRole` record, removing access to this portal. Confirmation: *"Remove [username] from CA portal?"* (or `RA portal`). |

All suspend/activate/remove actions are scoped to the current tenant — the system verifies that the target `UserTenantRole` belongs to the tenant shown on the page before acting. A user with roles in multiple tenants is unaffected in their other tenants.

#### Resending invitations / resetting passwords

If an invitee loses their email or their temporary password expires, the platform engine exposes `PlatformAuth.reset_user_password/2` which regenerates a temporary password and re-sends the credential email. In the current release this is triggered programmatically (e.g. via a console task) rather than from a dedicated button in the Platform Portal UI. Ask your platform engineer to run the reset if needed.

---

## 6. HSM Device Management <a name="hsm-devices"></a>

Navigate to **HSM Devices** in the sidebar to register and manage Hardware Security Modules. HSM devices provide tamper-resistant key storage for CA root and issuer keys.

### Registering a Device

Heading: *"Register HSM Device"*
Description: *"Register any PKCS#11 compatible HSM (SoftHSM2, Thales Luna, YubiHSM 2, etc.). The library will be probed to verify connectivity."*

| Field | Placeholder | Description |
|-------|-------------|-------------|
| **Label** | `SoftHSM2 Dev` | Human-readable name for the device (must be unique across all devices) |
| **PKCS#11 Library Path** | `/opt/homebrew/Cellar/softhsm/2.7.0/lib/softhsm/libsofthsm2.so` | Absolute filesystem path to the PKCS#11 shared library |
| **Slot ID** | `0` | Numeric PKCS#11 slot identifier |

Click **Register & Probe**. The system will:
1. Validate the form inputs
2. Probe the PKCS#11 library to verify it is reachable
3. Read the device manufacturer information
4. Register the device if the probe succeeds

**Success:** *"HSM device registered and verified."*
**Failure:** *"Cannot reach PKCS#11 library. Check the path and try again."*

### Registered Devices Table

Heading: *"Registered HSM Devices"*

| Column | Description |
|--------|-------------|
| **Label** | Device name |
| **Manufacturer** | Auto-detected from PKCS#11 probe |
| **Library Path** | Path to the PKCS#11 shared library |
| **Slot** | Slot ID number |
| **Tenants** | Number of tenants with access to this device |
| **Status** | **active** or **inactive** |
| **Actions** | Probe and Deactivate buttons |

If no devices are registered: *"No HSM devices registered."*

### Device Actions

| Action | Title | Description |
|--------|-------|-------------|
| **Probe** | *"Probe connectivity"* | Re-test PKCS#11 connectivity and update manufacturer info |
| **Deactivate** | *"Deactivate"* | Remove device from rotation |

> **Note:** A device cannot be deactivated if tenants are still assigned to it. You will see: *"Cannot deactivate: [count] tenant(s) still assigned. Revoke all tenant access first."* Remove all tenant assignments from the Tenant Detail page before deactivating.

---

## 7. Platform Admin Management <a name="admins"></a>

Navigate to **Admins** in the sidebar to manage platform administrator accounts.

Heading: *"Platform Admins"*
Subtitle: *"Manage platform administrator accounts."*

### Admin List

The table shows all platform admins:

| Column | Description |
|--------|-------------|
| **Username** | Login identifier. Your own row is marked with a **"you"** badge |
| **Display Name** | Full name |
| **Email** | Email address |
| **Role** | `super_admin` |
| **Status** | **active** (green) or **suspended** (yellow) |
| **Created** | Account creation date |
| **Actions** | Suspend, Activate, Delete icons |

### Creating a New Admin

Click **New Admin** to expand the creation form. Click **Cancel** to collapse it.

Heading: *"Create New Admin"*
Helper: *"A temporary password will be generated and emailed to the new admin. They must change it on first login."*

| Field | Placeholder | Description |
|-------|-------------|-------------|
| **Username** | `e.g. jdoe` | Unique login identifier (3–50 characters) |
| **Display Name** | `e.g. Jane Doe` | Full name for display |
| **Email** | `e.g. jane@example.com` | For invitation delivery |

Click **Create & Send Invite**. The system generates a temporary password and sends an invitation email with login instructions.

**Success:** *"Admin "[username]" created. Invitation email sent to [email]."*

### Admin Actions

| Action | Available When | Confirmation |
|--------|---------------|-------------|
| **Suspend** | Status is active | *"Suspend admin "[username]"? They will lose access immediately."* |
| **Activate** | Status is suspended | (no confirmation) |
| **Delete** | Any status | *"Permanently delete admin "[username]"? This cannot be undone."* |

### Safety Protections

The system prevents locking out all administrators and prevents self-lockout:

- **You cannot suspend or delete yourself.** The Suspend and Delete action icons are hidden on your own row (the row marked with the **"you"** badge).
- **Cannot suspend the last active admin.** You will see: *"Cannot suspend the last active admin."*
- **Cannot delete the last active admin.** You will see: *"Cannot delete the last active admin."*

---

## 8. System Health Monitoring <a name="system-health"></a>

Navigate to **System** in the sidebar to monitor infrastructure health.

Heading: *"System Health"*

The page auto-refreshes every **30 seconds**. Click **Refresh** for an immediate manual check.

### Summary Cards

| Card | Description |
|------|-------------|
| **Services** | Shows *"[healthy]/[total] healthy"*. Green when all healthy, red when any are down. |
| **PostgreSQL** | Database connection status: **Connected** (green) or **Down** (red) |
| **Databases** | Number of tenant databases detected (by counting `pki_*` databases in PostgreSQL) |

### Service List

Each monitored service shows:

| Field | Description |
|-------|-------------|
| **Service name** | Name and port number |
| **Status** | **Healthy** (green), **Unreachable** (red), or **Checking...** (spinner) |
| **Response** | Response time in milliseconds |
| **Checked** | Timestamp of last health check |

**Monitored services:**

| Service | Port | Check Method |
|---------|------|-------------|
| **CA Engine** | 4001 | BEAM process detection, fallback to HTTP |
| **CA Portal** | 4002 | HTTP health endpoint |
| **RA Engine** | 4003 | BEAM process detection, fallback to HTTP |
| **RA Portal** | 4004 | HTTP health endpoint |
| **Validation** | 4005 | HTTP health endpoint |
| **Platform Portal** | 4006 | Self-report (always healthy) |

> **Tip:** If a service shows as unreachable, check that the corresponding application is running and the port is accessible. For CA/RA engines, the system first checks if the engine is running in the same BEAM node before falling back to HTTP.

---

## 9. Active Sessions <a name="sessions"></a>

Visit `/sessions` directly in the browser to monitor and manage active user sessions across **all portals** (CA, RA, and Platform).

> **Note:** In the current release this page is **not linked from the sidebar** — it is only reachable via direct URL. Platform admins who need to use it regularly should bookmark `https://your-domain:4006/sessions`.

Heading: *"Active Sessions"*

The session list updates in **real-time** via PubSub — no manual refresh is needed. It subscribes to the `session_events` topic on all three portal PubSub instances (CA, RA, Platform) and reloads when any session is created, expired, or deleted.

### Session Table

| Column | Description |
|--------|-------------|
| **User** | Username of the logged-in user |
| **Portal** | Which portal — **CA** (primary badge), **RA** (secondary badge), or **PLATFORM** (accent badge), uppercased |
| **Role** | User's role in that portal session |
| **Tenant** | Tenant ID the session belongs to (shown as `—` for platform superadmin sessions). This is the raw tenant UUID, not the tenant name. |
| **IP** | Client IP address |
| **Login Time** | When the session was created |
| **Last Active** | Most recent activity timestamp |
| **Actions** | Force Logout button |

Footer: *"[count] active session(s) across all portals. Updates in real-time."*

If no sessions exist: *"No active sessions"*

### Force Logout

To terminate another user's session:

1. Click the **Force Logout** button on the session row
2. Confirm the dialog: *"Force logout [username] from [portal]?"*
3. The session is immediately terminated

The force logout event is recorded in the platform audit log with full details (actor, target user, portal, IP).

---

## 10. Profile & Password Management <a name="profile"></a>

Navigate to **Profile** in the sidebar to view and manage your own account.

### Profile Information

Heading: *"Profile Information"*

**Read-only fields:**

| Field | Description |
|-------|-------------|
| **Username** | Your login identifier (cannot be changed) |
| **Role** | Your platform role badge |
| **Status** | Your account status badge |

**Editable fields:**

| Field | Description |
|-------|-------------|
| **Display Name** | Your full name as shown in the UI |
| **Email** | Your email address |

Click **Save Changes** to update. You will see: *"Profile updated successfully."*

### Change Password

Heading: *"Change Password"*

| Field | Description |
|-------|-------------|
| **Current Password** | Your existing password (for verification) |
| **New Password** | Minimum 8 characters |
| **Confirm New Password** | Must match the new password |

Click **Change Password** to submit.

**Possible errors:**
- *"Current password is incorrect."*
- *"New password must be at least 8 characters."*
- *"New password and confirmation do not match."*

**Success:** *"Password changed successfully."*

---

## 11. Forgot Password <a name="forgot-password"></a>

If you forget your password:

1. On the login page, click the **Forgot Password** link
2. Enter your **Username** and submit
3. A **6-digit reset code** is sent to your registered email address
4. Enter the code on the verification page
5. Set a **new password** and confirm it
6. Click submit — you will see: *"Password reset successfully. Please sign in."*
7. You are redirected to the login page

**Rate limiting:** Password reset requests are limited to **3 per 15 minutes** per IP address.

**Error scenarios:**
- *"Username is required."* — You submitted without entering a username
- *"Code expired. Please start over."* — The 6-digit code has expired (10-minute window)
- *"Too many failed attempts. Please start over."* — Exceeded code entry attempts
- *"Invalid code. Please try again."* — Wrong code entered

---

## 12. Security Reference <a name="security"></a>

### Authentication

| Feature | Details |
|---------|---------|
| **Password hashing** | Argon2 (memory-hard, resistant to GPU/ASIC attacks) |
| **Minimum password length** | 8 characters |
| **Temporary credentials** | Auto-generated with 24-hour expiration; must be changed on first login |
| **Session storage** | Server-side ETS (not stored in cookies) |

### Rate Limiting

| Action | Limit |
|--------|-------|
| Login attempts | 5 per 5 minutes per IP |
| Password reset requests | 3 per 15 minutes per IP (covers both code request and code submission) |

### Session Security

| Feature | Details |
|---------|---------|
| **Idle timeout** | 30 minutes (configurable) |
| **Timeout warning** | 5 minutes before expiration |
| **IP pinning** | Session invalidated on IP change |
| **User-agent matching** | Session terminated if browser fingerprint changes |
| **Concurrent session detection** | Security alert on multiple simultaneous sessions |
| **New IP detection** | Alert when logging in from a previously unseen IP |

### Audit Trail

All security-relevant actions are logged to the platform audit system, including:

- Successful and failed logins
- Session expirations and forced logouts
- Tenant operations (create, activate, suspend, delete)
- Admin operations (create, suspend, activate, delete)
- HSM device operations (register, probe, deactivate)
- Credential resets and password changes
- Suspicious activity (session hijack attempts, concurrent sessions, new IP logins)

Each audit event records: timestamp, actor, action, target, and details (JSON).

---

## 13. Troubleshooting <a name="troubleshooting"></a>

### "We can't find the internet" / "Attempting to reconnect"

The browser has lost its WebSocket connection to the server. This can happen if:
- The server was restarted
- Your network connection was interrupted
- A proxy or firewall interrupted the connection

The page will automatically attempt to reconnect. If it persists, refresh the browser.

### "Something went wrong!"

An unexpected server error occurred. Try refreshing the page. If the issue persists, check the server logs for details.

### "Your temporary credentials have expired"

Your invitation or password reset credentials have a 24-hour expiration window. Contact another platform admin to issue a new invitation or reset your password.

### Cannot suspend or delete an admin

The system prevents suspending or deleting the **last active platform admin** to avoid lockout. Ensure at least one other admin is active before performing the action.

### Cannot deactivate an HSM device

HSM devices with tenants assigned cannot be deactivated. Go to each assigned tenant's detail page and **revoke** device access first.

### Tenant activation fails

Activation starts the tenant's engine processes under the in-process BEAM tenant supervisor. If it fails, check the platform logs for the specific reason (supervisor startup, database reachability, schema version). The tenant detail page's **Engine Status** should flip to **Online** after a successful activation; click **Refresh** to re-check.

### Tenant provisioning step fails during creation

If any row on the tenant creation checklist turns red, an error alert explains which step failed. Click **Retry** on that step — earlier successful steps are not re-run. Typical causes:

- **Database created** — PostgreSQL not reachable, or the slug collides with an existing database
- **Engines started** — Tenant supervisor failed to start (check logs)
- **Credentials sent** — Email transport misconfigured (check the platform engine's mailer settings)

### Tenant admin didn't receive the invitation email

- Check spam/junk folders
- Confirm the email address on the tenant detail page; it is editable inline by super_admins
- Verify the platform engine's email transport is configured and the mail server is reachable
- As a last resort, a platform engineer can regenerate the tenant admin's temporary password via `PlatformAuth.reset_user_password/2`

### CA or RA user didn't receive their invitation email

- Verify the tenant is in the `active` state
- Confirm the email address in the user form was correct
- Check that `CA_PORTAL_HOST` / `RA_PORTAL_HOST` env vars are set correctly so the invitation link points somewhere reachable
- Ask a platform engineer to run `PlatformAuth.reset_user_password/2` on the user's role to re-issue credentials

### Session expired unexpectedly

Sessions expire after 30 minutes of inactivity. If your session was terminated before the timeout:
- **IP change detected** — Your IP address changed (e.g., VPN reconnect, network switch)
- **Browser change detected** — User-agent mismatch (e.g., browser update mid-session)
- **Force logout** — A platform admin terminated your session from the Active Sessions page
