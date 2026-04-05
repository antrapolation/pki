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

### Summary Cards

| Card | Description |
|------|-------------|
| **Total Tenants** | Total number of provisioned tenant organizations |
| **Active** | Tenants currently operational (green) |
| **Suspended** | Tenants temporarily disabled (yellow) |
| **Pending Setup** | Tenants provisioned but not yet activated (blue) |
| **Services** | Number of healthy services out of total monitored (e.g., "5/6 healthy") |

### Quick Action

A **Create Tenant** card links directly to the tenant creation workflow.

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

The tenant creation wizard guides you through a multi-step process. A step indicator at the top shows your progress: **Tenant Info** → **Verify Email** → **Complete**.

Click **Back to Tenants** at any time to cancel and return to the tenant list.

#### Step 1 — Tenant Information

Heading: *"Tenant Information"*
Subtitle: *"Enter the details for the new Certificate Authority tenant."*

| Field | Required | Placeholder | Validation |
|-------|----------|-------------|------------|
| **Name** | Yes | `Acme Corporation` | Cannot be empty |
| **Slug** | Yes | `acme-corp` | Lowercase alphanumeric + hyphens only; must start and end with a letter or number |
| **Email** | Yes | `admin@acme-corp.com` | Must be a valid email address |

Helper text below Slug: *"Lowercase alphanumeric with hyphens (e.g. acme-corp)"*
Helper text below Email: *"Admin credentials will be sent to this email after verification."*

Buttons: **Cancel** | **Next**

#### Step 2 — Verify Email

Heading: *"Verify Email"*
Subtitle: *"We sent a 6-digit verification code to [email]."*

A green alert confirms: *"Verification code sent to [email]."*

| Field | Description |
|-------|-------------|
| **Verification Code** | 6-digit code sent to the email address |

Buttons: **Back** | **Resend Code** | **Verify**

**Important notes:**
- Codes expire after **10 minutes**. If expired, you will see: *"Verification code has expired. Please resend."*
- Maximum **5 verification attempts**. After that, you must resend a new code.
- Clicking **Resend Code** invalidates the previous code and sends a new one.

#### Step 3 — Provisioning

The system automatically provisions the tenant's infrastructure:
- Creates an isolated PostgreSQL database
- Applies CA and RA schemas (tables, indexes, constraints)
- Sets up audit infrastructure

You will see a spinner with: *"Creating tenant database..."*

If provisioning fails, you will see the heading *"Provisioning Failed"* with the message *"The tenant database could not be created."* Click **Try Again** to retry.

#### Step 4 — Success

Heading: *"Tenant Created"*
Message: *"[TenantName] database has been provisioned successfully."*

A **"Next Steps"** section outlines what to do after creation:

1. **Deploy the CA and RA engines for this tenant**
2. **Verify engines are online from the tenant detail page**
3. **Activate the tenant** — this will create CA/RA admin accounts and send credentials to the tenant's email

Buttons: **View Tenant** (opens tenant detail) | **Back to List** (returns to tenant list)

### 5.3 Tenant Detail & Configuration <a name="tenant-detail"></a>

Click the **View Details** (eye icon) action on any tenant to open its detail page. Click **Back to Tenants** to return to the list.

#### Tenant Information

The top card shows the tenant name, status badge, and key details:

| Field | Description |
|-------|-------------|
| **Slug** | URL-safe identifier |
| **Email** | Admin contact email |
| **Database** | Internal database name |
| **Created** | Creation timestamp |

Action buttons (shown based on current status):
- **Activate** — Start the tenant, create admin accounts, send credentials
- **Suspend** — Temporarily disable the tenant
- **Delete** — Permanently remove (suspended tenants only)
- **Refresh** — Re-check engine connectivity

#### Engine Status

Real-time connectivity status for the tenant's CA and RA engines:

| Status | Indicator | Meaning |
|--------|-----------|---------|
| **Online** | Green dot | Engine is running and reachable |
| **Offline** | Red dot | Engine is unreachable |
| **Checking** | Spinner | Connectivity check in progress |

Click **Refresh** to manually re-check status.

#### Admin Setup Status

Shows whether CA and RA admin accounts have been provisioned:

**CA Admin / RA Admin cards each show:**
- **Configured** (green badge) — Admin account exists, with user count: *"[count] user(s) configured."*
- **Pending** (yellow badge) — Not yet provisioned: *"Activate the tenant first, then admin credentials will be provisioned."*

**Credential actions:**

| Action | Confirmation | Description |
|--------|-------------|-------------|
| **Resend All Credentials** | *"This will reset ALL admin passwords and send new credentials. Continue?"* | Reset and re-send credentials for both CA and RA admins |
| **Reset CA Admin** | *"This will delete the existing CA admin and create a new one with a temporary password. Continue?"* | Reset CA admin credentials |
| **Reset RA Admin** | *"This will delete the existing RA admin and create a new one with a temporary password. Continue?"* | Reset RA admin credentials |

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
| **Initialized → Active** | Tenant engine processes start. CA and RA admin accounts are created. Credentials are emailed to the tenant's contact address. |
| **Active → Suspended** | Engine processes stop. Users can no longer log in to the tenant's CA or RA portals. Existing certificates remain valid. |
| **Suspended → Active** | Engine processes restart. Users regain access. |
| **Suspended → Deleted** | The tenant database is permanently dropped. All data (users, keys, certificates) is destroyed. **This cannot be undone.** |

> **Important:** A tenant must be **suspended** before it can be deleted. Active tenants cannot be deleted directly.

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

The system prevents locking out all administrators:

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

Navigate to **Sessions** in the sidebar (accessible from the Admins section context) to monitor and manage active user sessions across **all portals** (CA, RA, and Platform).

Heading: *"Active Sessions"*

The session list updates in **real-time** via PubSub — no manual refresh is needed.

### Session Table

| Column | Description |
|--------|-------------|
| **User** | Username of the logged-in user |
| **Portal** | Which portal — **CA** (blue), **RA** (purple), or **PLATFORM** (accent) badge |
| **Role** | User's role in that portal session |
| **Tenant** | Tenant the session belongs to (blank for platform sessions) |
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
| Password reset requests | 3 per 15 minutes per IP |
| Email verification attempts | 5 per code |

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

Ensure the CA and RA engines are deployed and reachable for the tenant. Check the **Engine Status** section on the tenant detail page — both engines should show **Online** before activation.

### Email verification code not received

- Check spam/junk folders
- Verify the email address is correct (go **Back** to Step 1 to check)
- Click **Resend Code** to send a new code
- Codes expire after 10 minutes

### Session expired unexpectedly

Sessions expire after 30 minutes of inactivity. If your session was terminated before the timeout:
- **IP change detected** — Your IP address changed (e.g., VPN reconnect, network switch)
- **Browser change detected** — User-agent mismatch (e.g., browser update mid-session)
- **Force logout** — A platform admin terminated your session from the Active Sessions page
