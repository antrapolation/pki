# PQC Certificate Authority System — User Manual

**Version 1.0 | Antrapolation Technology Sdn Bhd**

---

## Table of Contents

1. [Overview](#overview)
2. [Getting Started](#getting-started)
3. [Platform Portal — Tenant & Infrastructure Management](#platform-portal)
   - [First-Time Setup](#platform-first-time-setup)
   - [Login](#platform-login)
   - [Dashboard](#platform-dashboard)
   - [Tenant Management](#platform-tenants)
   - [Creating a Tenant](#platform-tenant-create)
   - [Tenant Detail & Configuration](#platform-tenant-detail)
   - [HSM Device Management](#platform-hsm)
   - [Admin Management](#platform-admins)
   - [System Health Monitoring](#platform-system)
   - [Active Sessions](#platform-sessions)
   - [Profile & Password](#platform-profile)
4. [CA Portal — Certificate Authority Administration](#ca-portal)
   - [First-Time Setup](#ca-first-time-setup)
   - [Login](#ca-login)
   - [Dashboard](#ca-dashboard)
   - [User Management](#ca-user-management)
   - [Keystore Management](#ca-keystore-management)
   - [Key Ceremony](#ca-key-ceremony)
   - [Audit Log](#ca-audit-log)
5. [RA Portal — Registration Authority Administration](#ra-portal)
   - [First-Time Setup](#ra-first-time-setup)
   - [Login](#ra-login)
   - [Dashboard](#ra-dashboard)
   - [User Management](#ra-user-management)
   - [CSR Management](#ra-csr-management)
   - [Certificate Profiles](#ra-certificate-profiles)
   - [Service Configuration](#ra-service-configuration)
   - [API Key Management](#ra-api-key-management)
6. [REST API — Submitting CSRs](#rest-api)
7. [OCSP & CRL — Certificate Validation](#validation)
8. [User Roles & Permissions](#roles)
9. [Glossary](#glossary)

---

## 1. Overview <a name="overview"></a>

The PQC Certificate Authority System is a Post-Quantum Cryptography ready CA infrastructure for issuing and managing digital certificates. It supports:

- **KAZ-SIGN** (Malaysia's local PQC algorithm)
- **ML-DSA** (NIST PQC standard)
- **RSA & ECC** (classical algorithms for backward compatibility)

The system consists of three web portals and supporting services:

| Component | URL | Purpose |
|-----------|-----|---------|
| Platform Portal | `https://your-domain:4006` | Tenant provisioning & infrastructure management |
| CA Portal | `https://your-domain:4002` | Certificate Authority administration |
| RA Portal | `https://your-domain:4004` | Registration Authority administration |
| RA API | `https://your-domain:4003` | REST API for CSR submission |
| OCSP/CRL | `https://your-domain:4005` | Certificate validation services |

---

## 2. Getting Started <a name="getting-started"></a>

### First Access

When the system is deployed for the first time, you will need to create the initial administrator accounts for both the CA and RA portals. Navigate to the **Setup** page to create your first admin account.

### Browser Requirements

- Modern browser (Chrome, Firefox, Safari, Edge)
- JavaScript must be enabled (required for LiveView)

---

## 3. Platform Portal — Tenant & Infrastructure Management <a name="platform-portal"></a>

The Platform Portal is the top-level administration interface used to provision and manage tenants (organizations), register HSM devices, monitor system health, and manage platform administrator accounts. Each tenant receives its own isolated CA and RA environments.

| Default URL | `https://your-domain:4006` |
|---|---|
| **Audience** | Platform superadmins responsible for infrastructure |

### 3.1 First-Time Setup <a name="platform-first-time-setup"></a>

On first deployment, navigate to `/setup` to create the initial platform superadmin account.

**Steps:**
1. Navigate to `https://your-domain:4006/setup`
2. Enter a **Username** (e.g., `admin`)
3. Enter a **Display Name** (e.g., `Platform Admin`)
4. Enter a **Password** (minimum 8 characters)
5. **Confirm Password**
6. Click **Create Admin Account**

No email is required during initial setup. You can add your email later from the **Profile** page.

You will be redirected to the login page. The setup page is only available once — after the first admin is created, all future visits redirect to login automatically.

> **Tip:** You can also bootstrap the initial admin via environment variables (`PLATFORM_ADMIN_USERNAME` and `PLATFORM_ADMIN_PASSWORD`) for automated deployments.

### 3.2 Login <a name="platform-login"></a>

**Steps:**
1. Navigate to `https://your-domain:4006/login`
2. Enter your **Username**
3. Enter your **Password**
4. Click **Sign In**

**Security protections:**
- **Rate limiting** — 5 failed login attempts per 5 minutes per IP address
- **Session timeout** — Sessions expire after 30 minutes of inactivity (with a 5-minute warning)
- **IP pinning** — Sessions are bound to your IP address; a change triggers a security alert
- **User-agent matching** — If your browser fingerprint changes mid-session, the session is terminated (hijack detection)

If your account requires a password change (e.g., first login with temporary credentials), you will be redirected to a **Change Password** page before proceeding.

### 3.3 Dashboard <a name="platform-dashboard"></a>

The dashboard provides an executive overview of your PKI deployment.

**Summary Cards:**

| Card | Description |
|------|-------------|
| **Total Tenants** | Number of provisioned tenant organizations |
| **Active Tenants** | Tenants currently operational |
| **Suspended Tenants** | Tenants that have been temporarily disabled |
| **Pending Setup** | Tenants provisioned but not yet activated |
| **Service Health** | Number of healthy services out of total monitored |

**Recent Tenants Table:**
- Shows the 5 most recently created tenants
- Columns: Name, Slug, Status, Email, Created Date

**Quick Actions:**
- **New Tenant** — Start the tenant creation workflow

### 3.4 Tenant Management <a name="platform-tenants"></a>

Navigate to **Tenants** in the sidebar to view and manage all tenant organizations.

**Tenant List:**
- Paginated list (10 per page) with sortable columns
- Columns: Name, Slug, Status, Email, Created Date
- Status badges:
  - **Active** (green) — Tenant is operational
  - **Suspended** (yellow) — Tenant is temporarily disabled
  - **Initialized** (blue) — Tenant is provisioned but not yet activated

**Inline Actions per Tenant:**

| Action | Icon | Available When |
|--------|------|---------------|
| **View Details** | Eye | Always |
| **Activate** | Play | Status is initialized or suspended |
| **Suspend** | Pause | Status is active or initialized |
| **Delete** | Trash | Status is suspended only |

**Tenant Lifecycle:**

```
Initialized → Active → Suspended → Deleted
      ↓                    ↑
      └────────────────────┘
```

- A tenant must be **suspended** before it can be deleted
- Activating a tenant creates CA and RA admin accounts and sends credentials to the tenant's email

### 3.5 Creating a Tenant <a name="platform-tenant-create"></a>

Click **New Tenant** from the Tenants page or Dashboard to start the multi-step provisioning workflow.

#### Step 1 — Tenant Information

| Field | Required | Description |
|-------|----------|-------------|
| **Name** | Yes | Display name for the organization (e.g., "Acme Corp") |
| **Slug** | Yes | URL-safe identifier used in subdomains and routing. Must be lowercase alphanumeric with hyphens, starting and ending with a letter or number (e.g., `acme-corp`) |
| **Email** | Yes | Admin contact email — credentials will be sent here |

Click **Next** to proceed to email verification.

#### Step 2 — Email Verification

A 6-digit verification code is sent to the email address provided in Step 1.

1. Check the inbox for the verification email
2. Enter the **6-digit code**
3. Click **Verify**

Options:
- **Resend Code** — Sends a new code (previous code expires). Codes are valid for 10 minutes.
- **Back** — Return to Step 1 to correct the email

> **Note:** Verification is limited to 5 attempts. If exceeded, you must resend a new code.

#### Step 3 — Provisioning

The system automatically provisions the tenant:
- Creates an isolated PostgreSQL database
- Applies CA and RA schemas
- Sets up audit infrastructure

A spinner is displayed during provisioning. If an error occurs, a **Retry** button is shown.

#### Step 4 — Success

On completion, you will see:
- Confirmation message with the tenant name
- **Next steps** checklist:
  1. Deploy CA and RA engines for the tenant
  2. Verify engines are online from the tenant detail page
  3. Activate the tenant to create admin accounts and send credentials

Buttons: **View Tenant** (go to detail page) | **Back to List**

### 3.6 Tenant Detail & Configuration <a name="platform-tenant-detail"></a>

Click a tenant's **View** action to open its detail page. This page provides comprehensive management for a single tenant.

#### Tenant Information

Displays the tenant's name, slug, email, and current status. Available actions:

| Action | Description |
|--------|-------------|
| **Resend Credentials** | Re-sends CA and RA admin login credentials to the tenant's email |
| **Reset CA Admin** | Generates new temporary credentials for the CA admin |
| **Reset RA Admin** | Generates new temporary credentials for the RA admin |
| **Delete** | Remove tenant (only available when suspended) |

#### Engine Status

Shows real-time connectivity status for the tenant's CA and RA engines:

| Status | Indicator | Meaning |
|--------|-----------|---------|
| **Online** | Green | Engine is running and reachable |
| **Offline** | Red | Engine is unreachable |
| **Checking** | Spinner | Connectivity check in progress |

Each engine shows its expected setup URL (based on tenant slug). Click **Refresh** to manually re-check status.

#### Metrics

Loaded asynchronously, this section displays operational metrics for the tenant:

| Metric | Description |
|--------|-------------|
| **Database Size** | Storage used by the tenant's database |
| **CA Users** | Number of CA portal users |
| **RA Users** | Number of RA portal users |
| **Certificates Issued** | Total certificates issued |
| **Active Certificates** | Currently valid certificates |
| **Pending CSRs** | CSRs awaiting review |
| **CA Instances** | Number of CA engine instances |
| **RA Instances** | Number of RA engine instances |

#### HSM Device Access

Manage which HSM devices this tenant can use for key storage:

- Table lists all registered HSM devices with their label, manufacturer, slot ID, and current tenant count
- **Grant** — Allow tenant to use a device
- **Revoke** — Remove tenant's access to a device

### 3.7 HSM Device Management <a name="platform-hsm"></a>

Navigate to **HSM Devices** in the sidebar to register and manage Hardware Security Modules.

#### Registering a Device

| Field | Description |
|-------|-------------|
| **Label** | Human-readable name for the device (must be unique) |
| **PKCS#11 Library Path** | Absolute path to the PKCS#11 shared library (e.g., `/opt/homebrew/Cellar/softhsm/2.7.0/lib/softhsm/libsofthsm2.so`) |
| **Slot ID** | Numeric PKCS#11 slot identifier (default: 0) |

When you click **Register**, the system automatically probes the PKCS#11 library to verify connectivity and reads the device manufacturer.

#### Devices Table

| Column | Description |
|--------|-------------|
| **Label** | Device name |
| **Manufacturer** | Auto-detected from PKCS#11 probe |
| **Slot ID** | PKCS#11 slot number |
| **Status** | Active or inactive |
| **Tenants** | Number of tenants with access |
| **Actions** | Probe, Deactivate |

**Actions:**
- **Probe** — Re-test PKCS#11 connectivity and update manufacturer info
- **Deactivate** — Remove device from rotation (only available if no tenants are currently assigned)

### 3.8 Admin Management <a name="platform-admins"></a>

Navigate to **Admins** in the sidebar to manage platform administrator accounts.

#### Admin List

- Shows all platform admins with: Username, Display Name, Email, Role, Status
- Status badges: **Active** (green), **Suspended** (yellow)

#### Creating a New Admin

| Field | Required | Description |
|-------|----------|-------------|
| **Username** | Yes | Unique login identifier (3–50 characters) |
| **Display Name** | Yes | Full name for display |
| **Email** | Yes | Email address for invitation delivery |

Click **Create Admin**. The system generates temporary credentials and sends an invitation email. The new admin must change their password on first login.

#### Admin Actions

| Action | Available When | Description |
|--------|---------------|-------------|
| **Activate** | Status is suspended | Re-enable admin access |
| **Suspend** | Status is active | Temporarily disable access |
| **Delete** | Any | Permanently remove admin |

> **Safety:** The system prevents suspending or deleting the last active platform admin to avoid lockout.

### 3.9 System Health Monitoring <a name="platform-system"></a>

Navigate to **System** in the sidebar to monitor infrastructure health. The page auto-refreshes every 30 seconds.

#### Service Status

Each monitored service shows:
- Service name
- Health indicator (green = healthy, red = unhealthy)
- Response time in milliseconds
- Last checked timestamp

**Monitored Services:**

| Service | Port | Check Type |
|---------|------|-----------|
| CA Engine | 4001 | BEAM process or HTTP |
| CA Portal | 4002 | HTTP |
| RA Engine | 4003 | BEAM process or HTTP |
| RA Portal | 4004 | HTTP |
| Validation | 4005 | HTTP |
| Platform Portal | 4006 | Self |

#### Database Status

- PostgreSQL connection status (Connected / Down)
- Number of tenant databases detected

Click **Refresh** for an immediate manual health check.

### 3.10 Active Sessions <a name="platform-sessions"></a>

Navigate to **Sessions** in the sidebar to monitor and manage active user sessions across all portals.

**Session Table:**

| Column | Description |
|--------|-------------|
| **User** | Username of the logged-in user |
| **Portal** | Which portal (CA, RA, or Platform) — color-coded badges |
| **Role** | User's role in that portal |
| **Tenant** | Tenant the session belongs to |
| **IP** | Client IP address |
| **Login Time** | When the session was created |
| **Last Active** | Most recent activity timestamp |
| **Actions** | Force Logout button |

**Force Logout:**
- Click the **Force Logout** button on any session row
- Confirm the action in the dialog
- The targeted user's session is immediately terminated
- Event is recorded in the platform audit log

The session list updates in real-time via PubSub — no manual refresh needed.

### 3.11 Profile & Password <a name="platform-profile"></a>

Navigate to **Profile** in the sidebar to view and update your own account settings.

#### Profile Information (Read-Only)
- Username
- Role
- Status

#### Editable Fields
- **Display Name** — Update and click **Save Changes**
- **Email** — Update and click **Save Changes**

#### Change Password
1. Enter your **Current Password**
2. Enter a **New Password** (minimum 8 characters)
3. Enter **Confirm Password** (must match)
4. Click **Change Password**

### 3.12 Forgot Password

If you forget your password:
1. Click the **Forgot Password** link on the login page
2. Enter your **Username**
3. A 6-digit reset code is sent to your registered email
4. Enter the code and set a new password
5. You are redirected to the login page

> **Rate limit:** Password reset requests are limited to 3 per 15 minutes per IP address.

---

## 4. CA Portal — Certificate Authority Administration <a name="ca-portal"></a>

The CA Portal is used by system administrators to manage the Certificate Authority, including users, keystores, key ceremonies, and audit logs.

### 4.1 First-Time Setup <a name="ca-first-time-setup"></a>

On first deployment, navigate to `/setup` to create the initial CA administrator account.

![CA Portal Setup](screenshots/ca-setup.png)

**Steps:**
1. Navigate to `https://your-domain:4002/setup`
2. Enter a **Username** (minimum 3 characters)
3. Enter a **Display Name** (optional)
4. Enter a **Password** (minimum 8 characters)
5. **Confirm Password**
6. Click **Create Admin Account**

You will be redirected to the login page. This setup page is only available once — after the first admin is created, it redirects to login automatically.

### 4.2 Login <a name="ca-login"></a>

![CA Portal Login](screenshots/ca-login.png)

**Steps:**
1. Navigate to `https://your-domain:4002/login`
2. Enter your **Username**
3. Enter your **Password**
4. For multi-instance deployments, verify the **CA Instance ID** (defaults to 1)
5. Click **Sign In**

### 4.3 Dashboard <a name="ca-dashboard"></a>

The dashboard provides an overview of the CA engine status.

![CA Dashboard](screenshots/ca-dashboard.png)

**Information displayed:**
- **Engine Status** — Current state of the CA engine (running/stopped)
- **Active Keys** — Number of issuer keys currently active
- **Uptime** — How long the engine has been running
- **Issuer Keys** — Total number of configured issuer keys
- **Recent Ceremonies** — History of key ceremonies with ID, type, status, and algorithm

**Quick Actions:**
- **Initiate Ceremony** — Start a new key ceremony
- **Manage Users** — Go to user management
- **Manage Keystores** — Configure key storage
- **View Audit Log** — Review system events

### 4.4 User Management <a name="ca-user-management"></a>

Manage users who have access to the CA system.

![CA User Management](screenshots/ca-users.png)

**Viewing Users:**
- The user table shows Username, Display Name, Role, Status, and Actions
- Use the **Filter by role** dropdown to filter by: All, CA Admin, Key Manager, Auditor

**Creating a User:**
1. Enter the **Username**
2. Enter a **Display Name**
3. Select a **Role**:
   - **CA Admin** — Full administrative access
   - **Key Manager** — Manages keystores, keys, and ceremonies
   - **Auditor** — Read-only access to audit logs
4. Click **Create User**

**Deleting a User:**
- Click the **Delete** button on the user's row (soft delete — sets status to "suspended")

### 4.5 Keystore Management <a name="ca-keystore-management"></a>

Configure where private keys are stored.

![CA Keystore Management](screenshots/ca-keystores.png)

**Keystore Types:**
- **Software** — Keys stored in the application's database (suitable for development and testing)
- **HSM** — Keys stored in a Hardware Security Module via PKCS#11 (recommended for production)

**Configuring a Keystore:**
1. Select the **Type** (software or hsm)
2. Click **Configure**
3. The new keystore appears in the table with its status

### 4.6 Key Ceremony <a name="ca-key-ceremony"></a>

Key ceremonies are the formal process of generating root CA keys with threshold-based secret sharing (Shamir's Secret Sharing).

![CA Key Ceremony](screenshots/ca-ceremony.png)

**Past Ceremonies:**
- View history of all ceremonies with ID, Type (sync/async), Status, and Algorithm

**Initiating a New Ceremony:**
1. Select the **Algorithm**:
   - **KAZ-SIGN-256** — Malaysia's PQC algorithm
   - **ML-DSA-65** — NIST PQC standard
   - **RSA-4096** — Classical RSA
   - **ECC-P256** — Elliptic Curve
2. Select the **Keystore** to store the generated key
3. Set **Threshold K** — Minimum number of custodians needed to reconstruct the key (must be >= 2)
4. Set **Threshold N** — Total number of key shares to distribute (must be >= K)
5. Optionally enter **Domain Info** for the certificate subject
6. Click **Initiate Ceremony**

After initiation, the ceremony status will show "initiated". The key manager then proceeds to:
- Generate the keypair
- Distribute encrypted shares to N custodians
- Complete the ceremony (as root CA or sub-CA)

### 4.7 Audit Log <a name="ca-audit-log"></a>

Review all security-relevant events in the system.

![CA Audit Log](screenshots/ca-audit-log.png)

**Filtering Events:**
- **Action** — Filter by event type (e.g., login, key_generated, ceremony_initiated)
- **Actor** — Filter by the user who performed the action
- **Date From / Date To** — Filter by date range

**Event Information:**
- Event ID, Timestamp, Node, Actor, Role, Action, Resource Type, Resource ID

---

## 5. RA Portal — Registration Authority Administration <a name="ra-portal"></a>

The RA Portal is used to manage certificate signing requests (CSRs), certificate profiles, API keys, and service configurations.

### 5.1 First-Time Setup <a name="ra-first-time-setup"></a>

Same as CA Portal — navigate to `/setup` on first deployment to create the initial RA admin.

### 5.2 Login <a name="ra-login"></a>

![RA Portal Login](screenshots/ra-login.png)

Enter your **Username** and **Password**, then click **Sign In**.

### 5.3 Dashboard <a name="ra-dashboard"></a>

![RA Dashboard](screenshots/ra-dashboard.png)

**Information displayed:**
- **RA Overview** — Summary statistics
- **Pending CSRs** — Number of CSRs awaiting review
- **Certificate Profiles** — Number of configured profiles
- **Recent CSRs** — Table showing recent certificate signing requests with Subject, Profile, Status, and Submitted date

**Quick Actions:**
- **Manage CSRs** — Review and process CSRs
- **Manage Users** — User administration
- **Certificate Profiles** — Configure cert profiles
- **Service Configs** — Configure OCSP/CRL services
- **API Keys** — Manage API access keys

### 5.4 User Management <a name="ra-user-management"></a>

![RA User Management](screenshots/ra-users.png)

**Roles:**
- **RA Admin** — Full RA administrative access
- **RA Officer** — Reviews and approves/rejects CSRs
- **Auditor** — Read-only access

**Creating and managing users** follows the same pattern as the CA Portal.

### 5.5 CSR Management <a name="ra-csr-management"></a>

Review, approve, or reject Certificate Signing Requests submitted via the REST API.

![RA CSR Management](screenshots/ra-csrs.png)

**Filtering CSRs:**
- Use the **Filter by status** dropdown: All, Pending, Approved, Rejected

**Viewing CSR Details:**
1. Click **View** on any CSR row
2. The detail panel shows: Subject, Status, Profile, Public Key Algorithm, Requestor
3. For pending CSRs, action buttons are available

**Approving a CSR:**
- Click **Approve** on a pending CSR row or in the detail panel
- The CSR status changes to "approved" and is forwarded to the CA for signing

**Rejecting a CSR:**
1. Click **View** on a pending CSR
2. Enter a **Rejection Reason** in the text area
3. Click **Reject**

### 5.6 Certificate Profiles <a name="ra-certificate-profiles"></a>

Define templates for certificate issuance with specific key usage and validity policies.

![RA Certificate Profiles](screenshots/ra-cert-profiles.png)

**Creating a Profile:**
1. Enter **Name** (e.g., "TLS Server", "Code Signing")
2. Enter **Key Usage** (e.g., "digitalSignature,keyEncipherment")
3. Enter **Extended Key Usage** (e.g., "serverAuth,clientAuth")
4. Select **Digest Algorithm** (e.g., SHA-256)
5. Enter **Validity (days)** (e.g., 365)
6. Click **Create Profile**

**Editing a Profile:**
- Click **Edit** on the profile row, modify fields, click **Update**

**Deleting a Profile:**
- Click **Delete** on the profile row

### 5.7 Service Configuration <a name="ra-service-configuration"></a>

Configure the OCSP and CRL distribution services.

![RA Service Configuration](screenshots/ra-service-configs.png)

**Configuring a Service:**
1. Select **Service Type**: OCSP Responder, CRL Distribution, or TSA
2. Enter the **Port** number
3. Enter the **URL** (e.g., `http://pki-validation:4005`)
4. Enter **Rate Limit** (requests per minute)
5. Optionally enter **IP Whitelist** (CIDR notation, e.g., `10.0.0.0/8`)
6. Click **Configure**

Reconfiguring the same service type will update (upsert) the existing configuration.

### 5.8 API Key Management <a name="ra-api-key-management"></a>

Manage API keys used by external clients to submit CSRs via the REST API.

![RA API Key Management](screenshots/ra-api-keys.png)

**Creating an API Key:**
1. Enter a **Name** for the key (e.g., "Production Client")
2. Click **Create Key**
3. The **raw API key** is displayed once — **copy it immediately**
4. Click **Dismiss** to close the key display

**Revoking an API Key:**
- Click **Revoke** on the key's row
- The key status changes to "revoked" and can no longer be used

---

## 6. REST API — Submitting CSRs <a name="rest-api"></a>

External systems submit Certificate Signing Requests via the RA Engine REST API.

### Authentication

All API requests require a Bearer token in the `Authorization` header:

```
Authorization: Bearer <your-api-key>
```

API keys are created in the RA Portal (see [API Key Management](#ra-api-key-management)).

### Submit a CSR

```bash
POST https://your-domain:4003/api/v1/csr
Content-Type: application/json
Authorization: Bearer <your-api-key>

{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
  "cert_profile_id": "<uuid-of-cert-profile>"
}
```

**Response (201 Created):**
```json
{
  "data": {
    "id": "019d2789-f8db-795e-b781-eebfc8fa0b7d",
    "status": "pending",
    "subject_dn": "CN=example.com,O=Example Corp",
    "submitted_at": "2026-03-26T00:27:26Z"
  }
}
```

### List CSRs

```bash
GET https://your-domain:4003/api/v1/csr
Authorization: Bearer <your-api-key>
```

Optional query parameter: `?status=pending|approved|rejected|issued`

### Get CSR by ID

```bash
GET https://your-domain:4003/api/v1/csr/<csr-id>
Authorization: Bearer <your-api-key>
```

### Health Check

```bash
GET https://your-domain:4003/health
```

No authentication required. Returns `{"status": "ok"}`.

---

## 7. OCSP & CRL — Certificate Validation <a name="validation"></a>

### OCSP (Online Certificate Status Protocol)

Query the real-time status of a certificate:

```bash
POST https://your-domain:4005/ocsp
Content-Type: application/json

{
  "serial_number": "<certificate-serial>"
}
```

**Response:**
```json
{
  "status": "good"       // or "revoked" or "unknown"
}
```

If revoked, additional fields are included:
```json
{
  "status": "revoked",
  "reason": "keyCompromise",
  "revoked_at": "2026-06-15T00:00:00Z"
}
```

### CRL (Certificate Revocation List)

Download the current CRL:

```bash
GET https://your-domain:4005/crl
```

**Response:**
```json
{
  "type": "X509CRL",
  "this_update": "2026-03-26T00:00:00Z",
  "next_update": "2026-03-27T00:00:00Z",
  "total_revoked": 0,
  "revoked_certificates": []
}
```

### Health Check

```bash
GET https://your-domain:4005/health
```

Returns `{"status": "ok"}`.

---

## 8. User Roles & Permissions <a name="roles"></a>

### Platform Portal Roles

| Role | Permissions |
|------|-------------|
| **Superadmin** | Full platform access — manage tenants, admins, HSM devices, view system health, manage sessions |

### CA Portal Roles

| Role | Permissions |
|------|-------------|
| **CA Admin** | Manage users, view audit logs, manage CA configuration |
| **Key Manager** | Manage keystores, initiate key ceremonies, manage issuer keys |
| **Auditor** | View audit logs (read-only) |

### RA Portal Roles

| Role | Permissions |
|------|-------------|
| **RA Admin** | Manage users, certificate profiles, service configs, API keys |
| **RA Officer** | View, approve, and reject CSRs |
| **Auditor** | View audit logs (read-only) |

### Security Principles

- **Least Privilege** — Each role has only the permissions needed for its function
- **Separation of Duties** — Key ceremony requires multiple custodians (threshold scheme)
- **Audit Trail** — All actions are logged with actor, timestamp, and details
- **Session Security** — Secure cookies with HSTS, same-site strict, HTTP-only flags

---

## 9. Glossary <a name="glossary"></a>

| Term | Definition |
|------|-----------|
| **Tenant** | An isolated organization instance with its own CA, RA, database, and user accounts |
| **CA** | Certificate Authority — issues and signs digital certificates |
| **RA** | Registration Authority — validates certificate requests before forwarding to CA |
| **CSR** | Certificate Signing Request — a request to have a certificate signed |
| **PQC** | Post-Quantum Cryptography — algorithms resistant to quantum computer attacks |
| **KAZ-SIGN** | Malaysia's local post-quantum digital signature algorithm |
| **ML-DSA** | Module-Lattice Digital Signature Algorithm (NIST FIPS 204) |
| **HSM** | Hardware Security Module — dedicated hardware for key storage |
| **OCSP** | Online Certificate Status Protocol — real-time certificate validation |
| **CRL** | Certificate Revocation List — list of revoked certificates |
| **Shamir's Secret Sharing** | Threshold scheme where K of N custodians are needed to reconstruct a secret |
| **UUIDv7** | Time-sortable universally unique identifier used for all record IDs |
| **PKCS#11** | Standard API for communicating with HSMs |
