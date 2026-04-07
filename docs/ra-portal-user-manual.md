# RA Portal — User Manual

**PQC Certificate Authority System | Antrapolation Technology Sdn Bhd**

---

## Table of Contents

1. [Introduction](#introduction)
2. [Roles & Permissions](#roles)
3. [Login & Session Security](#login)
4. [First-Run Welcome & Setup Wizard](#welcome)
   - [Welcome Screen](#welcome-screen)
   - [Setup Wizard — Step by Step](#setup-wizard)
5. [Dashboard](#dashboard)
6. [CSR Management](#csrs)
   - [Reviewing the Queue](#csrs-list)
   - [CSR Detail Panel](#csrs-detail)
   - [Domain Control Validation (DCV)](#csrs-dcv)
   - [Approving and Rejecting](#csrs-decide)
7. [Certificates](#certificates)
8. [Validation Services](#validation)
9. [Certificate Profiles](#cert-profiles)
10. [CA Connection](#ca-connection)
11. [Validation Endpoints](#service-configs)
12. [API Keys](#api-keys)
13. [RA Instances](#ra-instances)
14. [User Management](#users)
15. [Audit Log](#audit-log)
16. [Profile & Password Management](#profile)
17. [Forgot Password](#forgot-password)
18. [Security Reference](#security)
19. [Troubleshooting](#troubleshooting)

---

## 1. Introduction <a name="introduction"></a>

The **RA Portal** is the operational interface for a single tenant's Registration Authority. The Registration Authority sits in front of the CA and is responsible for **vetting certificate requests** before they are signed. RA staff review Certificate Signing Requests (CSRs), verify subject identity and domain ownership, approve or reject requests, and manage the certificates that have been issued.

Each tenant has its own isolated RA Portal instance. RA users are invited from the Platform Portal's tenant detail page when a tenant is created, and additional users can be added by RA Admins from this portal's [Users](#users) page.

| Default URL | `https://your-domain:4004` |
|---|---|
| **Audience** | RA Admins, RA Officers, Auditors |
| **Tenant scope** | One RA Portal per tenant; users only see their own tenant's data |
| **Browser requirements** | Modern browser (Chrome, Firefox, Safari, Edge) with JavaScript enabled |

### What you can do here

- **Connect to a CA** — Link the RA to one or more issuer keys exposed by the CA Portal so the RA knows which CAs will sign the certificates it approves.
- **Define certificate profiles** — Decide which kinds of certificates this RA can issue (TLS server, TLS client, code signing, S/MIME, custom) and pin their key usage, validity, and approval mode.
- **Review CSRs** — Browse incoming requests, run domain control validation (HTTP-01 / DNS-01), and approve or reject them.
- **Browse and revoke certificates** — View every certificate issued through this RA and revoke active ones with an RFC 5280 reason.
- **Monitor validation services** — Check CRL freshness, OCSP responder health, and look up individual certificate status.
- **Configure validation endpoints** — Register OCSP, CRL, and TSA endpoints to be embedded in issued certificates.
- **Manage API keys** — Create keys for automated CSR submission from external systems with profile, IP, rate-limit, and webhook controls.
- **Audit everything** — Filter, search, and export a tamper-evident record of every operation.

---

## 2. Roles & Permissions <a name="roles"></a>

The RA Portal uses three roles, each scoped to a single tenant. Your role is set when an inviter creates your account.

| Role | Sidebar sections visible | Typical responsibilities |
|------|--------------------------|--------------------------|
| **RA Admin** (`ra_admin`) | Overview, Operations, Configuration, Administration | Configures profiles, CA connection, validation endpoints, API keys, RA instances, invites users, approves/rejects CSRs, revokes certificates |
| **RA Officer** (`ra_officer`) | Overview, Operations | Reviews and approves/rejects CSRs, runs domain control validation, monitors validation services |
| **Auditor** (`auditor`) | Overview, Administration (Audit Log only) | Reviews the audit log for compliance oversight |

### Visibility matrix

| Page | URL | RA Admin | RA Officer | Auditor |
|------|-----|----------|------------|---------|
| Dashboard | `/` | ✓ | ✓ | ✓ |
| CSR Management | `/csrs` | ✓ | ✓ | — |
| Certificates | `/certificates` | ✓ (revoke) | ✓ | — |
| Validation Services | `/validation` | ✓ | ✓ | — |
| Certificate Profiles | `/cert-profiles` | ✓ | — | — |
| CA Connection | `/ca-connection` | ✓ | — | — |
| Validation Endpoints | `/service-configs` | ✓ | — | — |
| API Keys | `/api-keys` | ✓ | — | — |
| RA Instances | `/ra-instances` | ✓ | — | — |
| Users | `/users` | ✓ | — | — |
| Audit Log | `/audit-log` | ✓ | — | ✓ |
| Setup Wizard | `/setup-wizard` | ✓ | — | — |
| My Profile | `/profile` | ✓ | ✓ | ✓ |

> **Note:** Sidebar items are hidden — not just disabled — for roles that lack access. If you don't see a menu item described in this manual, it isn't available to your role.

### Key principle: separation of duties

The RA workflow is intentionally split:

- **RA Admins** configure *what* can be issued (profiles, CA connection) and *who* may submit (users, API keys), but they do not normally vet day-to-day requests.
- **RA Officers** vet requests against the configured profiles. They cannot change profiles or invite new users.
- **Auditors** can review every action via the Audit Log without being able to approve, reject, or change anything.

A request only becomes a certificate after passing the configured validation steps **and** being approved by an officer (or auto-approved when the profile permits it).

---

## 3. Login & Session Security <a name="login"></a>

### First-time login

RA Portal accounts are created by invitation. You receive an email containing the portal URL, your username, a temporary password, and your role. Sign in at `/login`, enter the temporary password, and you will be redirected to `/change-password` to set a permanent one (minimum 8 characters).

> **Temporary credentials expire 24 hours after issue.** If you wait too long you will see *"Your temporary credentials have expired."* — ask your RA Admin to use **Resend Invite** on the [Users](#users) page.

### Returning login

1. Navigate to `https://your-domain:4004/login`
2. Enter your **Username** and **Password**
3. Click **Sign In**

If you forget your password, see [§17 Forgot Password](#forgot-password).

### Session behaviour

| Protection | Details |
|------------|---------|
| **Idle timeout** | Sessions expire after **30 minutes** of inactivity |
| **Timeout warning modal** | A modal titled *"Session Expiring"* appears 5 minutes before expiry: *"Your session will expire in 5:00 due to inactivity."* Click **Continue Working** to extend |
| **Login rate limit** | 5 failed attempts per 5 minutes per IP address |
| **IP pinning** | The session is bound to your IP — switching networks (e.g., VPN reconnect) terminates the session |
| **User-agent matching** | If your browser fingerprint changes mid-session the session is terminated as a hijack precaution |
| **Server-side storage** | Sessions live in a server-side ETS table, not cookies |

### Logging out

Click **Sign out** in the top-right corner of any page. This sends a CSRF-protected `DELETE /logout` and immediately invalidates the session.

---

## 4. First-Run Welcome & Setup Wizard <a name="welcome"></a>

When an RA Admin signs in to a brand-new tenant, the portal needs initial configuration before officers can begin reviewing CSRs. The portal guides you through this with a Welcome screen and a five-step Setup Wizard.

### 4.1 Welcome Screen <a name="welcome-screen"></a>

Visit `/welcome` (or you may be auto-redirected here on first login).

Page title: *"Welcome"*

The welcome page shows a centered card with:

- The RA instance name (or *"Registration Authority"* fallback)
- *"Let's configure your Registration Authority. This will take a few minutes."*
- **Start Setup** button — opens the Setup Wizard at `/setup-wizard`
- **Skip, I'll configure manually** — sends you to the Dashboard

> **Auto-skip:** If the system detects that you already have at least one CA connection AND at least one certificate profile, the welcome page automatically redirects to the Dashboard. The wizard is for fresh tenants.

### 4.2 Setup Wizard — Step by Step <a name="setup-wizard"></a>

Page heading: *"RA Setup Wizard"*
Subtitle: *"Configure your Registration Authority in a few steps"*

The wizard runs at `/setup-wizard` and uses a horizontal step indicator at the top showing progress through five steps:

1. **Connect to CA**
2. **Certificate Profiles**
3. **Invite Team**
4. **Services**
5. **API Keys**

**Step indicator behaviour:**

- The current step is highlighted with the primary colour.
- Completed steps show a green checkmark.
- Locked steps appear dim and cannot be clicked. Step 2 unlocks once you connect a CA key. Steps 3–5 unlock once you create at least one certificate profile.
- You can click any unlocked step to jump back and forth.

#### Step 1 — Connect to CA

*"Step 1: Connect to CA — Link your RA to issuer keys from the Certificate Authority"*

The page shows two cards:

- **Connected Keys** (green) — issuer keys already linked to this RA, with key name, algorithm badge (colour-coded by family: ML-DSA / KAZ-SIGN / RSA / EC), and source CA instance name.
- **Available Keys** — a grid of issuer keys exposed by the CA but not yet connected. Each card has a **Connect** button.

If neither list has anything, you see a warning: *"No CA issuer keys available. Ensure the CA engine is running and has active keys."* — go to the CA Portal first and run a key ceremony to create a key.

**To advance:** Connect at least one key. **Next** stays disabled until you do. Attempting to skip ahead shows the error: *"Connect at least one CA key first"*.

#### Step 2 — Certificate Profiles

*"Step 2: Certificate Profiles — Define what types of certificates this RA can issue"*

Pick a starting template, then fine-tune:

| Template | Defaults |
|----------|----------|
| **TLS Server** | `digitalSignature` + `keyEncipherment`, `serverAuth`, 365 days, **Domain Control Validation required** |
| **TLS Client** | `digitalSignature`, `clientAuth`, 365 days, no DCV |
| **Code Signing** | `digitalSignature`, `codeSigning`, 365 days |
| **Email / S-MIME** | `digitalSignature` + `keyEncipherment`, `emailProtection`, 365 days |
| **Custom** | Empty form, you choose every value |

After clicking a template a card appears titled *"New Profile: [Template Name]"* with the form:

| Field | Required | Notes |
|-------|----------|-------|
| **Profile Name** | Yes | e.g. `Production TLS`. Max 255 characters |
| **Issuer Key** | Yes | Dropdown of the CA keys you connected in Step 1, formatted as `KeyName (algorithm)` |
| **Key Usage** | No | Comma-separated, pre-filled from template |
| **Extended Key Usage** | No | Comma-separated, pre-filled |
| **Digest Algorithm** | No | `SHA-256` (default), `SHA-384`, `SHA-512` |
| **Validity (days)** | No | Default `365`, minimum 1 |
| **Required DN Fields** | No | Comma-separated, e.g. `CN,O,OU` |
| **Optional DN Fields** | No | Comma-separated, e.g. `L,ST,C` |
| **Require Domain Control Validation** | No | Checkbox; pre-checked for TLS Server |

Click **Create Profile**. On success the profile appears in the **Created Profiles** card above. You can create multiple profiles in this step.

**To advance:** Create at least one profile.

#### Step 3 — Invite Team *(optional)*

*"Step 3: Invite Team — Add RA officers and auditors to your team (optional)"*

A simple **Invite a User** form:

| Field | Required | Notes |
|-------|----------|-------|
| **Username** | Yes | Max 50 characters |
| **Display Name** | No | Max 100 characters |
| **Email** | Yes | Where the invitation is sent |
| **Role** | Yes | Dropdown: `RA Officer` or `Auditor`. (You're already an admin; only operational roles can be invited from here.) |

Click **Invite**. Each invited user receives an email with a temporary password and must change it on first login.

This step is optional — you can skip it and invite people later from [§14 User Management](#users).

#### Step 4 — Service Configuration *(optional)*

*"Step 4: Service Configuration — Configure validation and distribution services (optional)"*

These endpoints are embedded into issued certificates so relying parties know where to fetch CRLs and check OCSP. The form:

| Field | Required | Notes |
|-------|----------|-------|
| **Service Type** | Yes | Dropdown: `OCSP Responder`, `CRL Distribution`, `Time Stamping Authority (TSA)` |
| **Port** | No | Default `8080`, range 1–65535 |
| **URL** | No | e.g. `https://ocsp.example.com`. Max 255 characters |

Click **Configure** to save. You can add multiple endpoints. Skip this step if your validation infrastructure isn't ready yet.

#### Step 5 — API Keys *(optional)*

*"Step 5: API Keys — Create API keys for programmatic access (optional)"*

A minimal one-field form:

| Field | Required | Notes |
|-------|----------|-------|
| **Label** | Yes | e.g. `CI/CD Pipeline`. Max 100 characters |

Click **Create Key**. The portal shows a yellow alert with the heading *"Copy this key now -- it will not be shown again!"* and a monospace block containing the raw key. **Copy it immediately.** Once you click **Dismiss** the raw value is discarded — only the hashed version remains.

> **For full API key configuration** — IP allowlists, profile restrictions, rate limits, webhooks, and Service vs Client key types — use the [§12 API Keys](#api-keys) page after the wizard completes. The wizard provides only a quick label-based key for early testing.

#### Completion

After Step 5 (or after clicking **Skip** on it), the wizard shows a summary screen:

Heading: *"Setup Complete — Your Registration Authority is configured and ready to go"*

Five summary cards report what was created:

- CA Connections (with key name + algorithm badge for each)
- Certificate Profiles
- Team Members (or "Skipped")
- Services (or "Skipped")
- API Keys (or "Skipped")

Click **Go to Dashboard** to leave the wizard. The wizard does not auto-resume — re-running configuration is done from the dedicated pages described in §9–§13.

---

## 5. Dashboard <a name="dashboard"></a>

The Dashboard is the landing page after login. Its content is **role-aware** — three different layouts depending on your role.

> **Note:** If your role is something other than `ra_admin`, `ra_officer`, or `auditor`, the page shows *"Dashboard not available for this role."*

### RA Admin view

| Section | Description |
|---------|-------------|
| **System Health** | Three status cards: **CA Engine** (`Connected` / `Unreachable`), **CA Connections** (count of connected issuer keys), **Service Configs** (count of validation endpoints) |
| **Setup: X of 5 complete** | Progress card listing the five setup tasks (CA Connections, Certificate Profiles, Team Members, Service Configurations, API Keys). Each task is required or optional. **Dismiss** hides the card permanently. |
| **Attention Required** | Two action callouts when applicable: **Pending Review** (count of CSRs awaiting decision, with **Review** link) and **Stuck CSRs** (count of approved-but-not-issued CSRs, with **Investigate** link) |
| **Team Activity** | Paginated table (10/page) of recent staff actions — Timestamp, Actor, Action, Details |

### RA Officer view

| Section | Description |
|---------|-------------|
| **My Queue** | A single card showing how many CSRs are awaiting your review, with a **Review CSRs** button |
| **Recent CSRs** | Table of recent submissions — ID, Subject, Profile, Status. Status badges: `pending` (warning), `verified` (info), `approved` (success), `rejected` (error) |

### Auditor view

| Section | Description |
|---------|-------------|
| **Recent Activity** | Table of recent audit events — Timestamp, Actor, Action, Details |
| **Compliance** | Two count cards: **Pending CSRs** and **Approved CSRs** |

---

## 6. CSR Management <a name="csrs"></a>

> **Visible to RA Admins and RA Officers.** Navigate to **CSR Management** in the **Operations** sidebar section.

Page title: *"CSR Management"*

This is where day-to-day request review happens.

### 6.1 Reviewing the Queue <a name="csrs-list"></a>

Two filter controls at the top of the page:

- **Filter by RA Instance** — dropdown showing *All* plus every RA instance configured in this tenant.
- **Filter by status:** — `All`, `Pending`, `Approved`, `Rejected`.

Below them is the CSR table (paginated, 10 per page):

| Column | Description |
|--------|-------------|
| **ID** | Short CSR identifier |
| **Subject** | Subject DN as submitted |
| **Profile** | Certificate profile chosen for this request |
| **Status** | Badge: `pending` (warning), `approved` (success), `rejected` (error) |
| **Submitted** | When the request arrived |
| **Actions** | **Eye** icon (view detail, always visible) and **Check** icon (approve, only when pending) |

### 6.2 CSR Detail Panel <a name="csrs-detail"></a>

Click the eye icon (or anywhere on a row) to open the **CSR Detail** side panel.

The panel shows:

| Field | Description |
|-------|-------------|
| **ID** | Internal CSR ID (monospace, read-only) |
| **Subject** | Subject DN |
| **Status** | Badge with current state |
| **Profile** | The profile selected for this CSR |
| **Public Key Algorithm** | The algorithm of the key being requested |
| **Requestor** | Who submitted the CSR (a user, or an API key) |

A **Close** button at the top dismisses the panel.

### 6.3 Domain Control Validation (DCV) <a name="csrs-dcv"></a>

For profiles where DCV is required (e.g., the TLS Server template), the detail panel includes a **Domain Validation** section.

The current state is shown as a badge: `passed` (success), `pending` (warning), `expired` (error), `failed` (error).

#### If no DCV challenge has been started yet

A small form lets you start one:

| Field | Description |
|-------|-------------|
| **Method** | Dropdown: `HTTP-01` or `DNS-01` |

Click **Start DCV** to issue a challenge.

#### If a challenge is pending

An alert shows the instructions for the challenge type:

- **HTTP-01:**
  > *"Place this content at: `http://{domain}/.well-known/pki-validation/{token}`"*
  > *"Content: {token_value}"*

- **DNS-01:**
  > *"Add TXT record: `_pki-validation.{domain}`"*
  > *"Value: {token_value}"*

After provisioning the challenge response on your side, click **Verify Now** (primary). If verification succeeds you see *"Domain validation passed!"* and the badge flips to `passed`.

> **DCV is only available to RA Admins and RA Officers.** Auditors cannot initiate or verify challenges.

### 6.4 Approving and Rejecting <a name="csrs-decide"></a>

For a `pending` CSR the detail panel shows an **Actions** section:

- **Approve** (green) — submits the request to the CA for issuance.
- **Reject** — opens a textarea labelled **Rejection Reason** (placeholder *"Provide a reason for rejection..."*; required). Click the red **Reject** button to submit.

Flash messages:

- *"CSR approved successfully"*
- *"CSR rejected"*
- Errors include *"Unauthorized"* if you don't have permission, plus sanitized engine errors.

> **Auto-approve mode:** If the certificate profile is configured with **Auto-Approve** and all validations pass, the CSR is approved automatically without going through this manual review. See [§9 Certificate Profiles](#cert-profiles).

---

## 7. Certificates <a name="certificates"></a>

> **Visible to RA Admins and RA Officers. Revocation is restricted to RA Admins.** Navigate to **Certificates** in the **Operations** section.

Page title: *"Certificates"*

### Info banner

> **Issued Certificates** — *"View certificates issued through this Registration Authority. Certificates are issued by the CA after CSR approval. RA administrators can revoke certificates when needed."*

### Filtering

A single dropdown filter:

- **Status** — `All`, `Active`, `Revoked`. The current count is shown next to the dropdown: *"N certificate(s)"*.

### Certificates table

Paginated, **20 per page**.

| Column | Description |
|--------|-------------|
| **Serial** | Certificate serial number, monospace, truncated |
| **Subject DN** | Subject distinguished name |
| **Profile** | Certificate profile that was used |
| **Status** | Badge: `issued` (green) or `revoked` (red) |
| **Issued At** | Local timestamp |

Rows are clickable; click anywhere on a row to open the detail panel.

Empty / loading state: *"Loading..."* or *"No certificates found."*

### Detail panel

Heading: *"Certificate Details"*. Close with the `×` button.

Read-only fields (two-column grid): Serial Number, Status, Subject DN, Certificate Profile, Reviewed By, Submitted At, Issued At.

> **Where are the cryptographic details?** *"Full certificate details (PEM, validity period, fingerprint) are available from the CA Portal. The RA tracks the issuance record linking the original CSR to the issued certificate serial."* — for the SHA-256 fingerprint, key usage, extensions, and PEM, open the same certificate from the CA Portal's Certificates page.

### Revoking a certificate

> **RA Admin only.** A red **Revoke Certificate** section appears at the bottom of the detail panel only when the certificate is `active` and your role is `ra_admin`.

The flow is two-step:

1. Click **Revoke this Certificate** (outline red).
2. A warning appears: *"This action is irreversible. The certificate will be added to the CRL."*
3. Pick a **Revocation Reason** from the dropdown (RFC 5280 reasons): `Unspecified`, `Key Compromise`, `CA Compromise`, `Affiliation Changed`, `Superseded`, `Cessation of Operation`.
4. Click **Confirm Revocation** (red) or **Cancel** (ghost).

Flash messages:

- *"Certificate [serial] has been revoked."*
- *"Only RA administrators can revoke certificates."*
- *"Failed to revoke certificate. Please try again or contact support."*

The newly-revoked certificate is automatically picked up by the next CRL refresh and the OCSP responder.

---

## 8. Validation Services <a name="validation"></a>

> **Visible to RA Admins and RA Officers.** Navigate to **Validation Services** in the **Operations** section.

Page title: *"Validation Services"*

This page monitors the health of the validation service that publishes CRLs and answers OCSP queries.

> *"Monitor the Validation Service health, view current CRL information, and check certificate revocation status via OCSP lookup."*

The page **auto-refreshes every 30 seconds**. Click **Refresh** in the header for an immediate refresh.

### Service Health card

| Field | Value |
|-------|-------|
| **Status** | `Healthy` (success icon) or `Unreachable` (error icon). *"Checking..."* while loading |
| **Subtitle** | *"Validation Service at [validation_url]"* |

### Current CRL card

A two-column grid:

| Field | Description |
|-------|-------------|
| **This Update** | When the CRL was published |
| **Next Update** | When the next CRL is due |
| **Total Revoked** | Number of revoked certificates currently in the CRL |
| **Version** | CRL version number |

If the validation service is unreachable: *"CRL data unavailable."*

### OCSP Lookup

Heading: *"OCSP Lookup"*
Description: *"Check the revocation status of a certificate by serial number."*

A simple form:

| Field | Description |
|-------|-------------|
| **Certificate Serial Number** | Text input, monospace, placeholder *"e.g. 1A2B3C4D..."* |

Click **Check** to query the OCSP responder. The result appears as a coloured alert:

| Status | Colour | Meaning |
|--------|--------|---------|
| `GOOD` | Success (green) | Certificate is valid and not revoked |
| `REVOKED` | Error (red) | Certificate has been revoked. Shows revocation time and reason |
| `ERROR` | Error (red) | Lookup failed. Shows error message |
| Other | Warning (amber) | Unknown / unauthorized |

For revoked certificates the result also includes *"Revoked at: [timestamp]"* and *"Reason: [reason]"*.

---

## 9. Certificate Profiles <a name="cert-profiles"></a>

> **Visible to RA Admins only.** Navigate to **Certificate Profiles** in the **Configuration** section.

Page title: *"Certificate Profiles"*

A certificate profile is a reusable template that defines what kind of certificate the RA will issue, which CA key signs it, and how the RA decides whether to approve a request matching it.

### The profiles table

Paginated, **50 per page**.

| Column | Description |
|--------|-------------|
| **Name** | Profile name |
| **RA Instance** | The RA instance that this profile belongs to |
| **Issuer Key** | The connected CA key + algorithm badge |
| **Key Usage** | Comma-separated key-usage flags |
| **Digest** | Digest algorithm |
| **Validity** | e.g. `365d` |
| **Status** | `active` (green) or `archived` (ghost) |
| **Mode** | `auto` (info) or `manual` (ghost) |
| **Actions** | **Edit** (pencil) and **Archive** (archive box, only on active profiles) |

### Creating a profile

Click **Create Profile** (top right) to open the **Template Picker** — a grid of five preset cards: **TLS Server**, **TLS Client**, **Code Signing**, **Email / S-MIME**, **Custom**. Click **Select** on the template that best matches your use case.

The form expands with all fields pre-filled from the template:

| Field | Required | Description |
|-------|----------|-------------|
| **Name** | Yes | Profile identifier (max 100 chars) |
| **RA Instance** | Yes | Which RA instance this profile belongs to |
| **Issuer Key** | Yes | A connected CA issuer key (see [§10](#ca-connection)). Disabled with a warning if no CA keys are connected. |
| **Key Usage** | No | Checkbox group: `digitalSignature`, `nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `keyCertSign`, `cRLSign`, `encipherOnly`, `decipherOnly` |
| **Extended Key Usage** | No | Dropdown: `Server Authentication (TLS)`, `Client Authentication`, `Code Signing`, `Email Protection (S/MIME)`, `Time Stamping`, `OCSP Signing` |
| **Digest Algorithm** | No | `SHA-256`, `SHA-384`, `SHA-512`, or `Algorithm Default`. **Disabled for PQC issuer keys** with the note *"PQC algorithms use a built-in digest"* (PQC keys like ML-DSA and KAZ-SIGN have a fixed digest baked in) |
| **Validity (days)** | No | Default `365`, range 1–3650 |
| **Approval Mode** | Yes | Radio buttons: `Manual Review` (officer must approve every CSR) or `Auto-Approve` (automatic issuance if all validations pass) |

Click **Create Profile** (or **Update Profile** when editing). The button shows *"Saving..."* while the request is in flight.

### Editing and archiving

- **Edit** (pencil) opens the same form pre-filled with the current values.
- **Archive** (archive box) is destructive in spirit but reversible by support. Confirmation: *"Archive this profile? It will no longer be available for new CSRs, but existing certificates retain their audit trail."*

Archived profiles drop out of dropdowns elsewhere in the portal but remain on this page with the `archived` badge so audit history is preserved.

---

## 10. CA Connection <a name="ca-connection"></a>

> **Visible to RA Admins only.** Navigate to **CA Connection** in the **Configuration** section.

Page title: *"CA Connections"*
Subtitle: *"Manage which CA issuer keys this RA instance can use for certificate issuance"*

Until you connect at least one CA issuer key, the RA cannot issue anything. The page is split into **Connected Keys** (currently linked) and **Available CA Keys** (exposed by the CA but not yet linked).

### Connected Keys table

| Column | Description |
|--------|-------------|
| **Key Name** | The issuer key alias from the CA Portal |
| **Algorithm** | Colour-coded badge — primary for ML-DSA, secondary for KAZ-SIGN, warning for RSA, info for EC, ghost for unknown |
| **CA Instance** | The CA instance (root / sub-CA) the key belongs to |
| **Connected** | When the link was made |
| **Action** | **Disconnect** (red) |

If empty: *"No keys connected yet. Connect a key from the available list below."*

### Available CA keys

A grid of cards (responsive: 1–3 columns) showing every issuer key from the CA that is **not** already connected. Each card has:

- Key name
- Algorithm badge
- CA instance name
- **Connect** button (primary, full width). The button shows a spinner while the connection is being made.

Empty: *"No additional CA keys available to connect."*

Connecting a key makes it available in the **Issuer Key** dropdown of [§9 Certificate Profiles](#cert-profiles). Disconnecting a key prevents future profiles from selecting it but does not affect certificates already issued.

---

## 11. Validation Endpoints <a name="service-configs"></a>

> **Visible to RA Admins only.** Navigate to **Validation Endpoints** in the **Configuration** section.

Page title: *"Validation Endpoints"*

These endpoints get embedded into the certificates the RA approves so relying parties know where to fetch CRLs and check OCSP. This is a configuration page — the actual responder service is monitored from [§8 Validation Services](#validation).

### Configure Endpoint form

| Field | Required | Description |
|-------|----------|-------------|
| **Service Type** | Yes | Dropdown: `OCSP Responder`, `CRL Distribution`, `TSA (Time Stamping)` |
| **URL** | Yes | Full URL, e.g. `http://ocsp.example.com`. Must start with `http://` or `https://` (otherwise: *"URL must start with http:// or https://"*). Max 255 chars |
| **Port** | No | Default `8080`, range 1–65535 |

Click **Configure**. If an endpoint of the same service type already exists it is replaced (not duplicated).

### Endpoints table

Paginated, **50 per page**.

| Column | Description |
|--------|-------------|
| **Service Type** | Human-readable label (e.g. *"OCSP Responder"*) |
| **Port** | Port number |
| **URL** | Full URL, monospace, truncated with ellipsis |
| **Status** | `active` (green) or other (warning) |

---

## 12. API Keys <a name="api-keys"></a>

> **Visible to RA Admins only.** Navigate to **API Keys** in the **Administration** section.

Page title: *"API Keys"*

API keys allow external systems (CI/CD pipelines, cert provisioning tools, monitoring agents) to submit and query CSRs without a human user. Each key is scoped, rate-limited, and optionally bound to a webhook for delivery of issuance events.

### The keys table

Paginated, **50 per page**. Filter by **RA Instance** with the dropdown at the top.

| Column | Description |
|--------|-------------|
| **Label** | Your chosen name |
| **Type** | Badge: `service` (info) or `client` (ghost) |
| **Owner** | The RA user who owns this key |
| **Profiles** | Number of allowed profiles, or `All` |
| **Rate** | Rate limit, e.g. `60/m` |
| **Expiry** | Expiry date. **Bold red if less than 30 days remain.** |
| **Status** | `active` (green) or `revoked` (red) |
| **Actions** | **View / Edit** (pencil) and **Revoke** (no-symbol, only on active keys) |

### Creating a key

Click **Create Key** (top right) to open the multi-section form.

#### Section 1 — Basic Info

| Field | Required | Notes |
|-------|----------|-------|
| **Label** | Yes | Max 100 characters |
| **Key Type** | Yes | Radio buttons: `Client` (submit CSRs, view status) or `Service` (full API access including revoke) |
| **Assign to User** | Yes | Dropdown of RA users — the selected user "owns" this key |
| **Expiry Date** | Yes | `YYYY-MM-DD` |
| **RA Instance** | No | Default *All Instances*; restrict the key to one instance if desired |

#### Section 2 — Access Control

| Field | Description |
|-------|-------------|
| **Allowed Certificate Profiles** | Scrollable checkbox group of every profile. Leave all unchecked to allow any profile |
| **IP Whitelist** | Textarea with one CIDR per line, e.g. `10.0.0.0/8`, `192.168.1.0/24`. Empty = any IP |
| **Rate Limit** | Number input, requests/min. Default `60`, range 1–10000 |

#### Section 3 — Webhook Configuration *(collapsible)*

| Field | Description |
|-------|-------------|
| **Webhook URL** | Optional, must be `https://...`. Max 500 chars. The portal auto-generates a webhook secret which is shown once after creation. |

Click **Create API Key** (the button shows *"Saving..."* while running).

### One-time credentials display

After creation a yellow alert appears at the top of the page:

> **"Copy this key now -- it will not be shown again!"**

The block contains:

- The **raw API key** (in a monospace code block)
- The **webhook secret** (if you provided a webhook URL), used for HMAC signature verification on incoming webhooks

**Copy both values immediately.** When you click **Dismiss**, the values are gone — the database only stores hashed versions. There is no way to retrieve the raw key later. If lost, revoke and create a new key.

### Editing a key

Click **View / Edit** to see read-only fields (ID, Owner, Expiry, RA Instance, Created) plus the same form sections (Label, Key Type, RA Instance, Allowed Profiles, IP Whitelist, Rate Limit, Webhook URL). Click **Save Changes**.

### Revoking a key

Click the **Revoke** icon. Confirmation: *"Revoke this API key? This cannot be undone."*

Once revoked the key is invalid for all future requests but its history (including any issued certificates) remains in the audit log.

### Webhook Delivery Log

If a key has a webhook URL, the detail panel also shows a **Webhook Delivery Log** table:

| Column | Description |
|--------|-------------|
| **Event** | Event type (e.g. `csr.approved`, `cert.issued`) |
| **Status** | Badge: `delivered` (success), `pending` (ghost), `failed` (warning), `exhausted` (error) |
| **Attempts** | Retry attempt count |
| **HTTP** | Last HTTP status code from the webhook target |
| **Time** | Delivery timestamp |
| **Error** | Last error message (truncated; hover for full text) |

If empty: *"No deliveries yet"*.

---

## 13. RA Instances <a name="ra-instances"></a>

> **Visible to RA Admins only.** Navigate to **RA Instances** in the **Administration** section.

Page title: *"RA Instances"*
Subtitle: *"Manage Registration Authority instances"*

An RA instance is an organisational container for certificate profiles and API keys. A single tenant can have multiple RA instances — for example a `Production RA` and a `Staging RA` — each with its own profiles, its own API keys, and its own CSR queue.

### Instance list

Each row in the list shows:

- Instance **name**
- **Status** badge: `active` (success), `inactive` (ghost), `suspended` (warning)
- Profile count
- API key count

Click an instance to open the detail panel below.

Empty state: *"No RA instances configured. Create one to get started."*

### Detail panel

When an instance is selected the panel shows:

- **Header:** Instance name + status badge
- **Assigned Certificate Profiles** card — count badge plus a list of profiles. Each profile entry shows its name and approval mode badge (`auto` or `manual`). Empty: *"No profiles assigned. Go to Certificate Profiles to assign."*
- **Assigned API Keys** card — count badge plus a list. Each key entry shows badges for type (`service` / `client`) and status (`active` / `revoked`). Empty: *"No API keys assigned. Go to API Keys to assign."*

Click the **Close** button to dismiss the panel.

### Creating an instance

Click **New RA Instance** (top right) to open the modal:

| Field | Required | Notes |
|-------|----------|-------|
| **Name** | Yes | Max 100 characters. Placeholder *"e.g. Production RA, Staging RA"* |

Click **Create** or **Cancel**. Press **Esc** to close the modal.

---

## 14. User Management <a name="users"></a>

> **Visible to RA Admins only.** Navigate to **Users** in the **Administration** section.

Page title: *"User Management"*

### Inviting a user

The top of the page is a **Create User & Send Invite** form (always visible):

| Field | Required | Description |
|-------|----------|-------------|
| **Username** | Yes | Max 50 characters |
| **Display Name** | Yes | Max 100 characters |
| **Email** | Yes | Where the invitation is sent |
| **Role** | Yes | Dropdown: `RA Admin`, `RA Officer`, `Auditor` |

Click **Create & Send Invite**. On success: *"User created. Invitation email sent."*

### User list and filtering

A **Filter by role:** dropdown at the top — `All`, `RA Admin`, `RA Officer`, `Auditor` — scopes the table.

The user table is paginated 10 per page.

| Column | Description |
|--------|-------------|
| **Username** | Login identifier |
| **Name** | Display name |
| **Email** | Contact address |
| **Role** | Badge: `ra_admin` (primary), `ra_officer` (info), `auditor` (warning) |
| **Status** | `active` (green) or `suspended` (warning) |
| **Actions** | Per-user icon buttons |

### Per-user actions

**Action icons are hidden on your own row** to prevent self-lockout.

| Icon | Action | Available When | Result |
|------|--------|----------------|--------|
| **Pause** | Suspend | User is `active` | *"User suspended."* |
| **Play** | Activate | User is `suspended` | *"User activated."* |
| **Envelope** | Resend Invitation | User has `must_change_password` | *"Invitation email resent."* |
| **Key** | Reset Password | Always | *"Password reset. New credentials emailed."* |
| **Trash** | Remove User | Always (other than self) | Confirmation: *"Remove this user's access? They will no longer be able to log in to this portal."* — flash: *"User removed."* |

---

## 15. Audit Log <a name="audit-log"></a>

> **Visible to RA Admins and Auditors.** Navigate to **Audit Log** in the **Administration** section.

Page title: *"Audit Log"*

### Compliance banner

> *"Audit Trail — Tamper-evident audit log supporting WebTrust for CAs, ETSI EN 319 401, ISO 27001, and CA/Browser Forum Baseline Requirements..."*

### Filters

| Filter | Description |
|--------|-------------|
| **Action** | Dropdown: `All`, `Login`, `Login Failed`, `User Created`, `User Suspended`, `User Activated`, `User Deleted`, `Password Reset`, `Password Changed`, `Profile Updated`, `CSR Approved`, `CSR Rejected`, `Certificate Issued`, `Certificate Revoked`, `API Key Created`, `API Key Revoked`, `DCV Started`, `DCV Passed` |
| **Actor** | Text search by username |
| **From** / **To** | Date inputs for a date range |

Click **Apply Filter** to reload the table.

### Events table

Paginated, **10 per page**, ordered newest first.

| Column | Description |
|--------|-------------|
| **Timestamp** | Local time |
| **Action** | Ghost badge with the action name |
| **Actor** | Username, truncated |
| **Details** | Event-specific key/value details, truncated |

Pagination shows *"Showing X–Y of Z"* with `«` / `»` controls.

### Exporting

Two export buttons:

| Button | Output |
|--------|--------|
| **CSV** | Downloads `audit-log-<date>.csv`. Columns: Timestamp (with timezone offset and name), Action, Actor, Event ID. RFC 4180 escaping. |
| **JSON** | Downloads `audit-log-<date>.json` (formatted) |

Both exports respect the active filters and are capped at **1000 records**. If your filter selects more than 1000 events, narrow the filter (e.g., a tighter date range) and re-export.

---

## 16. Profile & Password Management <a name="profile"></a>

> **Visible to all roles.** Navigate to **My Profile** in the bottom of the sidebar.

Page title: *"Profile"*

### Profile Information card

**Read-only:**

| Field | Description |
|-------|-------------|
| **Username** | Your login identifier |
| **Role** | Your role badge |
| **Status** | Account status badge |

**Editable form:**

| Field | Description |
|-------|-------------|
| **Display Name** | Your full name (max 100 characters) |
| **Email** | Your email address |

Click **Save Changes**. Success: *"Profile updated successfully."*

### Change Password card

| Field | Description |
|-------|-------------|
| **Current Password** | Required for verification |
| **New Password** | Minimum 8 characters |
| **Confirm New Password** | Must match the new password |

Click **Change Password**. Possible errors:

- *"Current password is incorrect."*
- *"New password must be at least 8 characters."*
- *"New password and confirmation do not match."*

Success: *"Password changed successfully."*

---

## 17. Forgot Password <a name="forgot-password"></a>

If you forget your password:

1. On the login page click **Forgot Password**.
2. Enter your **Username** and submit.
3. A **6-digit reset code** is sent to your registered email.
4. Enter the code on the verification page.
5. Set a new password (minimum 8 characters) and confirm it.
6. Submit. You see *"Password reset successfully. Please sign in."* and are redirected to the login page.

**Rate limit:** 3 password-reset requests per **15 minutes** per IP address (covers both code request and code submission).

**Possible errors:**

- *"Username is required."*
- *"Code expired. Please start over."* (10-minute window)
- *"Too many failed attempts. Please start over."*
- *"Invalid code. Please try again."*

---

## 18. Security Reference <a name="security"></a>

### Authentication

| Feature | Details |
|---------|---------|
| **Password hashing** | Argon2 (memory-hard, GPU/ASIC-resistant) |
| **Minimum password length** | 8 characters |
| **Temporary credentials** | Auto-generated; 24-hour expiration; `must_change_password` enforced on first login |
| **Session storage** | Server-side ETS; not stored in cookies |
| **API key hashing** | Raw API keys are shown once at creation and stored only as hashes |

### Rate limiting

| Action | Limit |
|--------|-------|
| Login attempts | 5 per 5 minutes per IP |
| Password reset requests | 3 per 15 minutes per IP |
| API key requests | Per-key rate limit (default 60/min, max 10000/min) |

### Session security

| Feature | Details |
|---------|---------|
| **Idle timeout** | 30 minutes (configurable) |
| **Timeout warning** | 5 minutes before expiry, modal with **Continue Working** button |
| **IP pinning** | Sessions invalidated on IP change |
| **User-agent matching** | Session terminated if browser fingerprint changes mid-session |

### Operational security

- **Separation of duties** — RA Admins configure, RA Officers approve, Auditors observe.
- **Domain Control Validation (DCV)** — TLS Server profiles require HTTP-01 or DNS-01 verification before approval.
- **Profile-level approval modes** — `Manual Review` forces an officer's signoff; `Auto-Approve` only applies when every validation passes.
- **API key isolation** — Keys can be restricted to a single RA instance, a list of profiles, an IP allowlist, and a rate limit.
- **Webhook signatures** — Webhook payloads are HMAC-signed with the per-key secret so receivers can verify authenticity.
- **Tamper-evident audit log** — Every operation is recorded with timestamp, actor, action, and details.

### Audit trail coverage

The audit log records, at minimum:

- All successful and failed logins
- User invite, suspend, activate, delete, password reset, profile update
- CSR submission, DCV start/pass, approval, rejection
- Certificate issuance and revocation (with reason)
- API key create / revoke
- Profile create / edit / archive
- CA connection / disconnection
- Validation endpoint configuration
- RA instance create / status change
- Suspicious activity (session hijack attempts, concurrent sessions, new IP logins)

---

## 19. Troubleshooting <a name="troubleshooting"></a>

### "We can't find the internet" / "Attempting to reconnect"

The browser has lost its WebSocket connection to the server. This can happen if the server was restarted or your network briefly dropped. The page automatically attempts to reconnect; refresh if it persists.

### "Something went wrong!"

An unexpected server error occurred. Refresh the page; if it persists, ask an RA Admin to check the RA Portal logs.

### "Your temporary credentials have expired"

Your invitation or password reset has a 24-hour window. Ask an RA Admin to use **Resend Invite** or **Reset Password** on the [Users](#users) page.

### Cannot suspend / delete a user

You cannot perform Suspend, Activate, or Delete actions on **your own** row — the action icons are hidden. Ask another RA Admin to do it for you.

### "No CA issuer keys available"

You haven't connected any CA keys yet. Either:

- Run a key ceremony in the CA Portal (see the CA Portal manual §9) so a key exists, then connect it from [§10 CA Connection](#ca-connection); or
- Re-run the setup wizard, which guides you through connecting a key and creating profiles.

### Cannot create a certificate profile (Issuer Key dropdown empty)

The profile form requires at least one connected CA key. Go to [§10 CA Connection](#ca-connection) and connect one first.

### Digest Algorithm field is greyed out

You selected a PQC issuer key (ML-DSA or KAZ-SIGN). PQC algorithms have a built-in digest, so the digest dropdown is locked. This is correct behaviour.

### CSR stuck in "verified" state

A CSR that is `verified` has passed Domain Control Validation but has not yet been approved by an officer (or auto-approved by the profile). Open the CSR and click **Approve**, or change the profile's approval mode to `Auto-Approve` if appropriate.

### CSR stuck in "approved" but no certificate issued

The CSR has been approved by the RA but the CA has not yet returned a certificate. Possible causes:

- The CA engine is unreachable. Check the [Dashboard](#dashboard) **System Health** card.
- The connected issuer key has been suspended in the CA Portal. Reactivate it from the CA Portal's Issuer Keys page.
- The CA's tenant supervisor isn't running for this tenant. Ask a platform admin to check the tenant's engine status.

The **Attention Required** card on the Dashboard surfaces this as *"Stuck CSRs"* with an **Investigate** link.

### Cannot revoke a certificate

Only **RA Admins** can revoke. The Revoke Certificate section is hidden in the certificate detail panel for other roles. Check that you are signed in with the right account.

### "Cannot deactivate: tenant(s) still assigned" when archiving a profile

Archiving a profile is allowed even if certificates have been issued under it — the audit history is preserved. If you see a different error, the profile may be referenced by an active API key whitelist; remove it from the API key first.

### Validation Service shows "Unreachable"

The validation service that publishes CRLs / answers OCSP queries is down. Check with your platform admin whether the validation service (default port 4005) is running. The OCSP Lookup form will not return results until the service is back.

### OCSP lookup returns "ERROR"

This usually means the validation service is reachable but the underlying CA database query failed, or the certificate serial number is malformed. Verify the serial number against the [Certificates](#certificates) table.

### Domain Control Validation challenge fails

For HTTP-01:

- Ensure the file at `http://{domain}/.well-known/pki-validation/{token}` is reachable from the public internet (not just from your office network).
- The file content must match the token value exactly, with no trailing whitespace.

For DNS-01:

- Ensure the TXT record `_pki-validation.{domain}` is propagated globally (try `dig _pki-validation.example.com TXT @8.8.8.8`).
- DNS propagation can take minutes.

If the challenge expires you can click **Start DCV** again to issue a new one.

### Lost API key

API keys are shown only once at creation. If you've lost the raw key, **revoke** the existing key from the [API Keys](#api-keys) page and create a new one. Update the consuming system with the new value.

### Webhook deliveries are failing

Open the API key in the detail panel and check the **Webhook Delivery Log** table:

- `failed` — the webhook target returned a non-2xx HTTP status. The portal will retry until exhausted. Check the HTTP and Error columns for details.
- `exhausted` — all retry attempts have been used up. Fix the receiving service and trigger a new event.
- Verify HMAC signatures using the webhook secret you saved at key creation time.

### Session expired unexpectedly

Sessions expire after 30 minutes of inactivity. Other reasons a session can be terminated before then:

- **IP change detected** — Your IP address changed (VPN reconnect, network switch, mobile handover)
- **Browser change detected** — User-agent mismatch (browser update, profile switch)
- **Force logout** — A platform admin terminated your session from the Platform Portal's Active Sessions page
