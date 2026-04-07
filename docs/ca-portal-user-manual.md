# CA Portal — User Manual

**PQC Certificate Authority System | Antrapolation Technology Sdn Bhd**

---

## Table of Contents

1. [Introduction](#introduction)
2. [Roles & Permissions](#roles)
3. [Login & Session Security](#login)
4. [Dashboard & Setup Guide](#dashboard)
5. [CA Instance Hierarchy](#ca-instances)
6. [User Management](#users)
7. [HSM Devices](#hsm-devices)
8. [Keystores](#keystores)
9. [Key Ceremony](#ceremony)
   - [Overview & Roles](#ceremony-overview)
   - [Initiating a Ceremony — CA Admin](#ceremony-initiate)
   - [My Shares — Custodian Flow](#ceremony-custodian)
   - [Witness Flow — Auditor](#ceremony-witness)
   - [Ceremony Lifecycle & Real-Time Updates](#ceremony-lifecycle)
10. [Issuer Keys](#issuer-keys)
    - [Listing Issuer Keys](#issuer-keys-list)
    - [Activating a Root CA Key](#issuer-keys-root)
    - [Activating a Sub-CA Key (CSR Round-Trip)](#issuer-keys-subca)
    - [Signing CSRs with a Reconstructed Key](#issuer-keys-sign)
    - [Suspend, Reactivate, Archive](#issuer-keys-lifecycle)
11. [Certificates](#certificates)
12. [Audit Log](#audit-log)
13. [Profile & Password Management](#profile)
14. [Forgot Password](#forgot-password)
15. [Quick Setup (Dev/Test Only)](#quick-setup)
16. [Security Reference](#security)
17. [Troubleshooting](#troubleshooting)

---

## 1. Introduction <a name="introduction"></a>

The **CA Portal** is the operational interface for a single tenant's Certificate Authority. It is where CA staff configure CA hierarchies, run threshold key ceremonies, manage issuer keys, sign certificates, and review audit trails.

Each tenant has its own isolated CA Portal instance, its own database, and its own user accounts. Tenants are provisioned by a platform admin from the [Platform Portal](./platform-portal-user-manual.md), and the first CA users are invited from the tenant's detail page in the Platform Portal.

| Default URL | `https://your-domain:4002` |
|---|---|
| **Audience** | CA Admins, Key Managers, Auditors |
| **Tenant scope** | One CA Portal per tenant; users only see their own tenant's data |
| **Browser requirements** | Modern browser (Chrome, Firefox, Safari, Edge) with JavaScript enabled |

### What you can do here

- **Build a CA hierarchy** — Define one or more Root CAs and their subordinate (intermediate / issuing) CAs.
- **Generate root and sub-CA keys safely** — Run multi-party Key Ceremonies that split the private key into Shamir secret shares held by trusted custodians and witnessed by an auditor.
- **Manage issuer keys** — Activate root certificates (self-signed) or sub-CA certificates (signed by parent), suspend / reactivate / archive keys.
- **Sign certificates** — Reconstruct issuer keys on demand from custodian-held shares to sign CSRs.
- **Browse and revoke certificates** — Search, view full X.509 details, and revoke active certificates.
- **Audit everything** — Every operation is recorded in a tamper-evident audit log that can be filtered and exported.
- **Configure storage** — Register Software or HSM-backed keystores per CA instance, using HSM devices assigned to your tenant by the platform admin.

---

## 2. Roles & Permissions <a name="roles"></a>

The CA Portal uses three roles, each scoped to a single tenant. Your role is set when an inviter creates your account from the Platform Portal's tenant detail page (or by another CA Admin from the Users page in this portal).

| Role | Sidebar sections visible | Typical responsibilities |
|------|--------------------------|--------------------------|
| **CA Admin** (`ca_admin`) | Overview, Key Management, Infrastructure, Administration | Initiates ceremonies, manages CA hierarchy, signs certificates, invites users, revokes certificates, reviews audit log |
| **Key Manager** (`key_manager`) | Overview, Key Management, Infrastructure | Acts as a key custodian during ceremonies, configures keystores and HSM devices, views issuer keys and certificates |
| **Auditor** (`auditor`) | Overview, Ceremony (Witness), Administration (Audit Log) | Witnesses ceremonies and signs each phase, monitors compliance via the audit log |

### Visibility matrix

| Page | URL | CA Admin | Key Manager | Auditor |
|------|-----|---------|-------------|---------|
| Dashboard | `/` | ✓ | ✓ | ✓ |
| CA Instances | `/ca-instances` | ✓ (manage) | ✓ (read-only) | ✓ (read-only) |
| Key Ceremony (orchestration) | `/ceremony` | ✓ | — | — |
| My Shares (custodian) | `/ceremony/custodian` | ✓ | ✓ | — |
| Witness | `/ceremony/witness` | ✓ | — | ✓ |
| Issuer Keys | `/issuer-keys` | ✓ | ✓ | ✓ (read) |
| Certificates | `/certificates` | ✓ (revoke) | ✓ | ✓ |
| HSM Devices | `/hsm-devices` | ✓ | ✓ | — |
| Keystores | `/keystores` | ✓ | ✓ | — |
| Users | `/users` | ✓ | — | — |
| Audit Log | `/audit-log` | ✓ | — | ✓ |
| My Profile | `/profile` | ✓ | ✓ | ✓ |

> **Note:** Sidebar items are hidden — not just disabled — for roles that lack access. If you don't see a menu item described in this manual, it isn't available to your role.

### Key principle: separation of duties

The **CA Admin** can never single-handedly use a private key. All issuer keys are protected by Shamir secret sharing — a private key only exists in plaintext for the brief moment when **K of N** custodian passwords are entered together to reconstruct it for a specific signing operation. After the operation, the reconstructed key material is discarded. Auditors witness and attest each ceremony phase to ensure procedure was followed.

---

## 3. Login & Session Security <a name="login"></a>

### First-time login

CA Portal accounts are created by invitation. When a Platform Admin (from the Platform Portal) or a CA Admin (from this portal's [Users](#users) page) invites you, you receive an email containing:

- The portal URL
- Your **username**
- A **temporary password**
- The role you have been assigned

**Steps:**

1. Open the URL from the email and you will land on the login page at `/login`.
2. Enter your **Username** and **temporary Password**.
3. Click **Sign In**.
4. Because the temporary password is flagged `must_change_password`, you are immediately redirected to `/change-password`.
5. Enter the temporary password as **Current Password**, set a new password (minimum 8 characters), confirm it, and submit.
6. You are returned to the portal and signed in.

> **Temporary credentials expire 24 hours after issue.** If you wait too long you will see *"Your temporary credentials have expired."* — ask your CA Admin to use **Resend Invite** on the Users page (see [§6](#users)).

### Returning login

1. Navigate to `https://your-domain:4002/login`
2. Enter your **Username** and **Password**
3. Click **Sign In**

If you forget your password, see [§14 Forgot Password](#forgot-password).

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

## 4. Dashboard & Setup Guide <a name="dashboard"></a>

The Dashboard is the landing page after login. It is visible to **all roles** and gives an at-a-glance view of the tenant's CA state.

### Stat cards

Three cards across the top:

| Card | Description |
|------|-------------|
| **Engine Status** | Health of the tenant's CA engine; shows uptime in seconds |
| **Active Keys** | Number of issuer keys currently in `active` state |
| **Total Keys** | Total issuer keys (any status) |

### Setup Guide *(CA Admin only)*

Until your tenant is fully configured, the Dashboard shows a **Setup Guide** card with a progress badge (e.g., *"2/5 steps"*) and five tasks:

| # | Task | Description | Required? |
|---|------|-------------|-----------|
| 1 | **Invite Team Members** | Add key managers and auditors to participate in ceremonies | Required |
| 2 | **Configure HSM Devices** | Register hardware security modules for key storage | Optional |
| 3 | **Create Keystores** | Set up software or HSM-backed keystores for key material | Required |
| 4 | **Run Key Ceremony** | Generate root or sub-CA keys with threshold secret sharing | Required |
| 5 | **Activate Issuer Keys** | Activate generated keys so they can sign certificates | Required |

Each step has a **Set up** button (or **Done** badge if complete). Click **Dismiss** in the top-right of the card to hide it permanently once setup is complete.

### Recent Ceremonies

A paginated table (10 per page) showing the most recent ceremonies for this tenant:

| Column | Description |
|--------|-------------|
| **ID** | First 8 characters of the ceremony UUID |
| **Type** | Ceremony type (e.g., `root_ca`, `sub_ca`) |
| **Status** | Badge: `initiated`, `in_progress`, `completed`, `failed`, etc. |
| **Algorithm** | The key algorithm being generated |

### Quick Actions

Role-filtered action cards:

| Action | Visible to |
|--------|------------|
| **Initiate Ceremony** | CA Admin, Key Manager |
| **Manage Users** | CA Admin |
| **Manage Keystores** | CA Admin, Key Manager |
| **View Audit Log** | CA Admin, Auditor |

Clicking a card navigates to the corresponding page.

---

## 5. CA Instance Hierarchy <a name="ca-instances"></a>

Navigate to **CA Instances** in the **Overview** sidebar section.

Heading: *"CA Instance Hierarchy"*
Subtitle: *"Manage root and subordinate CA instances"*

A CA Instance is a logical CA — it can be a root, an intermediate, or an issuing CA. Each instance owns its own issuer keys, keystores, and the certificates it issues. The hierarchy is rendered as an indented tree.

### The tree

Each row in the tree shows:

- The instance **name** (CA Admins can rename inline by clicking the name)
- A **role badge**: `root` (primary), `intermediate` (secondary), or `issuing` (accent)
- A **status badge**: `active` (green), `inactive` (ghost), `suspended` (warning)
- An **OFFLINE** warning badge if the CA has been taken offline
- The number of **issuer keys** attached: *"N issuer key(s)"*

### CA Admin actions

When you hover over a row as a CA Admin, action icons appear at the right of the row:

| Icon | Action |
|------|--------|
| **Take Offline / Bring Online** toggle | Pauses or resumes signing for this CA without changing its status. Confirmation: *"Take this CA offline? Certificate signing will be blocked."* / *"Bring this CA online?"* |
| **Activate** | Sets status to `active` (only when current status is not active). Errors with *"Cannot activate: parent CA is suspended. Activate the parent first."* if parent is not active. |
| **Suspend** | Sets status to `suspended`. Cascades: *"CA instance suspended. All child CAs have also been suspended."* |
| **Add Sub-CA** | Opens the create modal pre-filled with this CA as parent |

Click an instance name to enter rename mode; press **Save** (green) or **Cancel** (ghost). Empty names are rejected with *"Name cannot be empty"*.

### Creating a CA

Click **New Root CA** in the page header (CA Admin only) to open the **Create CA Instance** modal:

| Field | Required | Description |
|-------|----------|-------------|
| **Name** | Yes | e.g. `Root CA`, `Intermediate CA 1`. Max 100 characters |
| **Parent CA** | No | Dropdown of existing CAs. Default *"None (Root CA)"*. Selecting a parent makes this an intermediate or issuing CA. |

Buttons: **Cancel** | **Create**.

Success flash: *"CA instance created successfully"*. The new CA appears in the tree and is ready to receive a keystore and a key ceremony.

### Empty state

*"No CA instances configured. Create a Root CA to get started."*

> **Tip:** A typical hierarchy is `Root CA → Issuing Sub-CA`. The Root CA is offline most of the time and only used to sign sub-CA certificates; day-to-day end-entity certificates are issued by sub-CAs.

---

## 6. User Management <a name="users"></a>

> **Visible to CA Admins only.** Navigate to **Users** in the **Administration** sidebar section.

Page title: *"User Management"*

### Inviting a user

The top of the page is a **Create User & Send Invite** form (always visible):

| Field | Required | Description |
|-------|----------|-------------|
| **Username** | Yes | Unique login identifier (max 50 characters) |
| **Display Name** | Yes | Full name as shown in the UI (max 100 characters) |
| **Email** | Yes | Where the invitation will be sent (max 254 characters) |
| **Role** | Yes | Dropdown: `CA Admin`, `Key Manager`, `Auditor` |

Click **Create & Send Invite**. On success: *"User created. Invitation email sent."*

The new user receives an email containing a temporary password. They must change it on first login (see [§3](#login)).

### User list and filtering

Below the form is a paginated user table (10 per page).

| Column | Description |
|--------|-------------|
| **Username** | Login identifier |
| **Name** | Display name |
| **Email** | Contact address |
| **Role** | Badge: `ca_admin` (primary), `key_manager` (info), `auditor` (warning) |
| **Status** | `active` (green) or `suspended` (warning) |
| **Actions** | Per-user icon buttons |

A **Role** dropdown above the table filters by role: `All Roles`, `CA Admin`, `Key Manager`, `Auditor`. The current count is shown as *"N user(s)"*.

### Per-user actions

Action icons are shown at the end of each row. **Action icons are hidden on your own row** to prevent self-lockout.

| Icon | Action | Available When | Result |
|------|--------|----------------|--------|
| **Pause** (amber) | Suspend | User is `active` | *"User suspended."* |
| **Play** (green) | Activate | User is `suspended` | *"User activated."* |
| **Envelope** (violet) | Resend Invite | User has `must_change_password` set | *"Invitation email resent."* — issues a new temp password |
| **Key** (sky) | Reset Password | Always | *"Password reset. New credentials emailed."* — generates a new temp password |
| **Trash** (rose) | Remove | Always (other than self) | *"User removed."* with confirmation: *"Remove this user's access? They will no longer be able to log in to this portal."* |

> **Note:** "Remove" deletes the user's role binding for this tenant. If they have roles in other tenants, those are unaffected.

---

## 7. HSM Devices <a name="hsm-devices"></a>

> **Visible to CA Admins and Key Managers.** Navigate to **HSM Devices** in the **Infrastructure** section.

Page title: *"HSM Devices"*

This page is **read-only** in the CA Portal. HSM devices are owned and registered by the platform administrator. They are then **assigned to your tenant** from the Platform Portal's tenant detail page. Anything assigned to your tenant appears here for use when configuring HSM-backed keystores.

### Info banner

> *"HSM devices are managed by the platform administrator. The devices below have been assigned to your tenant. Contact the platform administrator to add or change HSM device assignments."*

### Assigned HSM Devices table

| Column | Description |
|--------|-------------|
| **Label** | Human-readable device name (set by the platform admin) |
| **Manufacturer** | Auto-detected during PKCS#11 probe (`-` if unavailable) |
| **Slot** | PKCS#11 slot ID |
| **Status** | `active` (green) or other (warning) |
| **Actions** | Probe icon |

### Actions

| Action | Title | What it does |
|--------|-------|--------------|
| **Probe** (signal icon, sky) | *"Test connectivity"* | Re-tests PKCS#11 reachability to the device. Success: *"Device probed: [manufacturer]"* |

### Empty state

*"No HSM devices assigned to your tenant."*

If you need an HSM device that isn't listed here, contact your platform administrator and ask them to register it (HSM Devices page in the Platform Portal) and grant your tenant access (HSM Device Access section on the tenant detail page).

---

## 8. Keystores <a name="keystores"></a>

> **Visible to CA Admins and Key Managers.** Navigate to **Keystores** in the **Infrastructure** section.

Page title: *"Keystore Management"*

A keystore tells the CA engine **where** to store the private key material for a given CA instance. Each CA instance can have a Software keystore and/or an HSM keystore — but only one of each type. The same key material can be backed by either; the Key Ceremony chooses which keystore to use when generating the key.

### Filtering

A **Filter by CA Instance** dropdown at the top scopes the table to a single CA. The default value is *All*.

### Configure Keystore form

Heading: *"Configure Keystore"*

| Field | Required | Description |
|-------|----------|-------------|
| **CA Instance** | Yes | Select the CA this keystore belongs to (placeholder *"Select CA Instance"*) |
| **Type** | Yes | Dropdown: `Software` or `HSM (PKCS#11)` |
| **HSM Device** | Yes (if Type=HSM) | Dropdown of HSM devices assigned to this tenant. Format: `<label> (<manufacturer>)` |

If you select **HSM (PKCS#11)** but no HSM devices are assigned, you will see: *"No HSM devices assigned to your tenant. Contact the platform administrator."*

Click **Configure** to save. Errors:

- *"Please select a CA Instance."*
- *"Please select an HSM device."*
- *"This CA instance already has a [type] keystore."* (duplicate prevention)

Success: *"Keystore configured successfully."*

### Configured Keystores table

Paginated, 10 per page.

| Column | Description |
|--------|-------------|
| **CA Instance** | Owning CA name |
| **Type** | Badge: `software` (info) or `hsm` (warning) |
| **HSM Device** | The assigned device label (or `—` for software keystores) |
| **Status** | `active` (green), `configured` (info), or `inactive` (ghost) |
| **ID** | First 8 characters of the keystore UUID, monospace |
| **Created** | Local time |

Empty state: *"No keystores"*.

---

## 9. Key Ceremony <a name="ceremony"></a>

The Key Ceremony is the most security-critical workflow in the CA Portal. It generates a CA private key inside an HSM (or software keystore) and immediately splits it into encrypted Shamir secret shares, each protected by a custodian's password. **The plaintext key never exists outside the HSM.** Reconstructing it later requires K of N custodians to enter their passwords together.

### 9.1 Overview & Roles <a name="ceremony-overview"></a>

A ceremony involves three actor types:

| Actor | Page | Responsibilities |
|-------|------|-----------------|
| **CA Admin** | `/ceremony` (Key Ceremony) | Initiates the ceremony, picks the algorithm and threshold, assigns custodians and a witness, and monitors live progress |
| **Key Custodian** (Key Manager) | `/ceremony/custodian` (My Shares) | Accepts their assigned share by setting a personal password that encrypts it |
| **Witness** (Auditor) | `/ceremony/witness` (Witness) | Attests each phase of the ceremony (preparation → key generation → completion) by re-authenticating with their password |

All three pages stay synchronised in real time via PubSub — when a custodian accepts their share, the CA Admin's progress dashboard and the Auditor's witness page update immediately.

> **Server-Side HSM Only.** Keys are generated and stored on the server-side HSM via PKCS#11. Nothing is generated client-side.

### 9.2 Initiating a Ceremony — CA Admin <a name="ceremony-initiate"></a>

Navigate to **Key Ceremony** in the **Key Management** section. The page opens in **list view** showing all past ceremonies for the selected CA instance.

#### Pre-flight

The page requires:

1. A **CA instance** to be selected in the top dropdown. If none is selected you see a *"No CA instance selected"* card.
2. At least one **keystore** configured for the selected CA. Otherwise you see an alert linking to `/keystores`.

Click **New Key Ceremony** (shield-check icon, top right) to open the wizard.

#### Step 1 — Initiate Witnessed Key Ceremony

The form has the following fields:

| Field | Required | Description |
|-------|----------|-------------|
| **Algorithm** | Yes | Dropdown of supported algorithms — see [Supported Algorithms](#ceremony-algos) |
| **Keystore** | Yes | The CA instance's available keystores (e.g., *"HSM — hardware-slot-1"*, *"Software"*) |
| **Key Alias** | No | A short identifier for this key, e.g. `root-key-2026` (max 100 chars) |
| **Certificate Type** | Yes | Dropdown: `Root CA (self-signed)` or `Sub-CA (generates CSR)` |
| **Threshold K** | Yes | Minimum custodians needed to reconstruct the key. Min 2. Default 2 |
| **Threshold N** | Yes | Total custodians. Min 2. Default 3 |
| **Key Manager Custodians** | Yes | Checkbox list of all active key managers in this tenant. Select **at least N** of them |
| **Auditor Witness** | Yes | Dropdown of all active auditors in this tenant. Select exactly one |
| **Time Window** | Yes | Dropdown: `1 hour`, `2 hours`, `4 hours`, `8 hours`, `12 hours`, `24 hours`, `2 days`, `3 days`, `1 week`. Default `24 hours`. *"All participants must complete their actions within this window."* |

If no key managers exist: *"No active key managers found. Add key manager users first."*
If no auditors exist: *"No active auditors found. Add auditor users first."*

Submit with **Initiate Ceremony**. The CA engine creates the ceremony record, assigns a share to each chosen custodian, and notifies them. The page transitions to the **Progress Dashboard**.

> **Rate limit:** Tenants are limited to 10 ceremony initiations per hour to prevent accidental loops.

#### Supported Algorithms <a name="ceremony-algos"></a>

| Algorithm | Family | Notes |
|-----------|--------|-------|
| `KAZ-SIGN-128` / `KAZ-SIGN-192` / `KAZ-SIGN-256` | Post-Quantum | Malaysia local PQC algorithm at NIST levels 1, 3, 5 |
| `ML-DSA-44` / `ML-DSA-65` / `ML-DSA-87` | Post-Quantum | NIST FIPS 204 levels 2, 3, 5 |
| `ECC-P256` / `ECC-P384` | Classical | Fast and widely supported / stronger |
| `RSA-2048` / `RSA-4096` | Classical | Legacy compatibility / legacy stronger |

(Additional SLH-DSA variants may be available depending on engine build.)

#### Progress Dashboard

Once initiated, the page shows:

- **Ceremony Progress card** — Ceremony ID, algorithm, threshold (`K of N`), type, current status badge.
- **Participants table** — One row per custodian and the auditor witness, with role badge, status badge, and timestamp of last action.
- **Ceremony Timeline card** — Scrollable activity log of every event (initiated, shares assigned, custodian accepted, witness attested, phase changed, completed).
- **Action panel** — **Back to List** and **Cancel Ceremony**.

Participant statuses you will see during a ceremony:

| Status | Meaning |
|--------|---------|
| `pending` | Custodian has not yet accepted their share |
| `accepted` | Custodian accepted their share and set a password |
| `waiting` | Witness is waiting for participants to act |
| `attested (preparation)` | Witness signed off the preparation phase |
| `attested (key_generation)` | Witness signed off key generation |
| `attested (completion)` | Witness signed off completion |

The dashboard updates live; no refresh needed.

#### Cancellation

Click **Cancel Ceremony** to abort an in-flight ceremony. Confirmation: *"Cancel this ceremony? All pending work will be lost."*

You can also cancel from the history table using the small **x** icon. Confirmation: *"Cancel this ceremony? The pending issuer key will be removed."*

#### History row actions

Each row in the ceremony history table has these icon actions:

| Icon | Action | Available |
|------|--------|-----------|
| **Eye** | View progress dashboard | Always |
| **Play** | Resume an in-progress ceremony | When status is `initiated` / `in_progress` / `preparing` |
| **X** | Cancel ceremony | When status is `initiated` / `in_progress` / `preparing` |
| **Trash** | Delete record | When status is `failed` only. Confirmation: *"Permanently delete this ceremony record?"* |

#### Completion

When all custodians have accepted and the auditor has witnessed all three phases, the ceremony transitions to `completed` and the wizard shows a green confirmation card. Click **Finish Wizard** to return to the list. The new key now appears as a **pending** issuer key on the [Issuer Keys](#issuer-keys) page, ready for activation.

### 9.3 My Shares — Custodian Flow <a name="ceremony-custodian"></a>

> **Visible to CA Admins and Key Managers.** Navigate to **My Shares** in the **Key Management** section.

Page title: *"My Ceremony Shares"*

This is where you, as a custodian, accept the share assigned to you in a ceremony.

#### Info banner

> **Key Custodian Portal** — *"As a key custodian, you accept your share of the threshold key and set a password to protect it. Select a ceremony below to view your assignment."*

#### Assigned ceremonies

The page lists every ceremony for which you have a share. Each ceremony card shows:

- The CA instance
- Algorithm
- Threshold (K of N)
- Your share index
- A countdown of **time remaining** in the ceremony's time window. Once under 1 hour, the countdown turns red.
- A share status badge: `pending` (warning), `accepted` (success), `completed` (info), `failed` (error)

If you have no shares: *"No ceremonies"*.

#### Detail view

Click any ceremony card to open it.

**If your share status is `pending`** you see an **Accept Your Share** card with a form:

| Field | Required | Validation |
|-------|----------|------------|
| **Key Label** | Yes | Alphanumeric and hyphens only (`^[a-zA-Z0-9\-]+$`), max 64 chars. Placeholder *"e.g. my-ceremony-key-1"* |
| **Password** | Yes | Minimum 8 characters. Placeholder *"Minimum 8 characters"* |
| **Confirm Password** | Yes | Must match the password |

Submit with **Accept Share**. On success the card flips to a green **Share Accepted** confirmation showing the key label and accepted timestamp.

> **Important — password storage:** Your password is held in the server's in-memory `CustodianPasswordStore` (ETS) and is **wiped after the key generation phase finishes**. The server never persists it to disk. If you lose the password between accepting your share and the moment of reconstruction, the share is unrecoverable and the ceremony will need to be re-run.

#### Activity log

The detail view also shows an **Activity Log** card with the most recent 50 events for this ceremony — for example *"alice accepted their share"*, *"Ceremony abc12345 status changed to in_progress"*. Updates arrive in real time over PubSub.

### 9.4 Witness Flow — Auditor <a name="ceremony-witness"></a>

> **Visible to CA Admins and Auditors.** Navigate to **Witness** in the **Ceremony** sidebar section (or **Key Management** for CA Admins).

Page title: *"Ceremony Witness"*

#### Info banner

> **Auditor Witness Portal** — *"As an auditor, you witness each phase of key ceremonies to ensure proper procedure is followed. Select a ceremony below to begin witnessing."*

#### Ceremony list

A grid of ceremony cards for which you are the assigned witness. Each card shows the CA instance, algorithm, threshold, status, and initiated time. Click a card to enter the detail view.

#### Detail view — three phases

The detail view shows the ceremony's basic info, a chronological **Ceremony Timeline**, and three **phase cards** stacked top-to-bottom:

| # | Phase | When you can attest |
|---|-------|---------------------|
| 1 | **Preparation** | After **all custodians** have accepted their shares. The card shows each custodian as a small badge: green `accepted` or amber `pending`. |
| 2 | **Key Generation** | After preparation is witnessed AND the keygen result is available. The card shows the resulting key fingerprint, algorithm, and share count. |
| 3 | **Completion** | After key generation is witnessed. The card shows the final state and a summary of all attestations recorded so far. |

Each phase card has a small witness form:

| Field | Description |
|-------|-------------|
| **Re-enter your password to attest** | Your CA Portal password (used for re-authentication) |

Click **I Witness [Phase Name]** (eye icon). While submitting it shows a spinner and *"Attesting..."* and is disabled. The button is enabled only when the phase's preconditions are met.

> **Why re-auth?** Each attestation re-validates the auditor's credentials so an unattended browser cannot be hijacked into approving a ceremony. The password is checked against your hashed credential — no hash is exposed.

#### Automatic key generation

When the auditor attests **Preparation** *and* all custodians are ready, the CA engine **automatically triggers key generation**. The activity log shows *"Key generation triggered automatically."* Once complete, the keygen result is displayed on the Key Generation phase card and the button becomes enabled.

#### Real-time updates

The witness page subscribes to the same PubSub topic as the orchestration and custodian pages, so as soon as a custodian accepts a share or the engine emits a phase change, the relevant card and timeline update without a page refresh.

### 9.5 Ceremony Lifecycle & Real-Time Updates <a name="ceremony-lifecycle"></a>

End-to-end flow:

```
1. CA Admin: Initiate Ceremony
       │
       ▼
2. Custodians: Open My Shares → Accept (set password)
       │
       ▼  (PubSub: custodian_ready)
3. Auditor: Open Witness → I Witness Preparation
       │
       ▼  (engine auto-triggers)
4. Engine: Generate key on HSM, split into N Shamir shares
       │
       ▼
5. Auditor: I Witness Key Generation
       │
       ▼
6. Auditor: I Witness Completion
       │
       ▼
7. Ceremony: completed → New issuer key appears as "pending" in Issuer Keys
```

If **any** step fails or times out, the ceremony moves to `failed`. The custodian password store is wiped, no key material remains, and the failed ceremony can be deleted from the history table.

---

## 10. Issuer Keys <a name="issuer-keys"></a>

> **Visible to all roles.** Navigate to **Issuer Keys** in the **Key Management** section.

Page title: *"Issuer Keys"*

An "issuer key" is a CA's signing key. Its private material lives on the HSM (or software keystore) split into Shamir shares; its public certificate is what other parties trust.

### 10.1 Listing Issuer Keys <a name="issuer-keys-list"></a>

A **CA Instance** dropdown at the top scopes the page to one CA. The keys table below shows:

| Column | Description |
|--------|-------------|
| **Alias** | Your chosen key alias (monospace) |
| **Algorithm** | e.g. `kaz-sign-3`, `ml-dsa`, `rsa-2048`, `ecc-p256` |
| **Root?** | `Yes` for root keys, `No` for sub-CA keys |
| **Status** | `pending` (warning), `active` (success), `suspended` (error), `archived` (ghost) |
| **Certificate** | `Installed` or `—` |
| **Actions** | Per-status icon buttons |

Empty state: *"No issuer keys for this CA instance. Run a key ceremony to create one."*

### 10.2 Activating a Root CA Key <a name="issuer-keys-root"></a>

After a Root CA ceremony completes, the key appears as `pending` with no certificate installed. To activate it:

1. Click the **Upload Certificate** icon (green up-arrow) on the row.
2. The **Upload Certificate** modal opens with the heading *"Upload Certificate for [alias]"* and a non-editable info block (key alias, algorithm, status badge).
3. Paste your **Signed Certificate (PEM)** into the textarea (note: *"Paste the certificate signed by the parent CA."*). For a root CA you generate this self-signed certificate using whatever tooling your organisation prescribes (out of scope for this manual).
4. Click **Upload & Activate**.
5. The key transitions to `active` and the **Certificate** column flips to *"Installed"*.

### 10.3 Activating a Sub-CA Key (CSR Round-Trip) <a name="issuer-keys-subca"></a>

Sub-CA keys are activated by having their parent CA sign them.

#### Step 1 — Get the CSR from the sub-CA

On the **sub-CA's** Issuer Keys page, find the pending key and click **View CSR** (document icon). A modal opens with the heading *"Certificate Signing Request (CSR)"* and a description: *"Copy this CSR and paste it into the Root CA's 'Sign CSR' dialog to issue a certificate for this Sub-CA."*

Click **Copy** to copy the PEM block, or select and copy manually. Click **Close** when done.

#### Step 2 — Sign it on the parent CA

Switch the CA Instance dropdown to the parent CA, find the parent's **active** issuer key, and click **Sign CSR** (pencil icon). The **Sign CSR with [alias]** modal opens. See [§10.4](#issuer-keys-sign) for the full Sign CSR flow.

#### Step 3 — Upload the signed cert back to the sub-CA

After signing, the parent's modal shows a green *"Certificate Signed Successfully"* box with the serial number and the signed PEM. Copy it.

Switch back to the **sub-CA's** Issuer Keys page, click **Upload Certificate** on the pending key, paste the PEM, and click **Upload & Activate**. The sub-CA key transitions to `active`.

### 10.4 Signing CSRs with a Reconstructed Key <a name="issuer-keys-sign"></a>

The **Sign CSR** modal is the place where K custodian passwords are entered together to reconstruct an issuer key for a single signing operation.

The form contains:

- **Key info** — alias and algorithm of the signing key (read-only)
- **CSR (PEM)** — paste the CSR. Placeholder shows the standard `-----BEGIN CERTIFICATE REQUEST-----` markers
- **Validity (days)** — number, default `3650` (10 years)
- **Certificate Type** — dropdown: `CA Certificate` (default) or `End-Entity`
- **Key Custodian Passwords** — labelled *"Key Custodian Passwords (need K of N shares)"*. One password input per share row, each labelled with the custodian's short ID. Placeholder *"Custodian's secret password"* (max 100 chars)

Click **Reconstruct Key & Sign**. The button is disabled while processing. The CA engine:

1. Looks up the K shares for this issuer key.
2. Decrypts each share with the corresponding custodian password.
3. Reconstructs the private key in memory.
4. Signs the CSR.
5. **Wipes the reconstructed key from memory.**

On success the modal flips to a green **Certificate Signed Successfully** box showing the serial number and a read-only PEM textarea. A note reminds you: *"Copy this certificate and upload it to the Sub-CA issuer key to activate it."*

Click **Done** to close.

If reconstruction fails (e.g., wrong password), the operation aborts and an error alert appears.

> **In practice:** Each custodian enters their **own** password. Either run the dialog with all custodians physically present, or use the share-by-share workflow your organisation has approved. The portal does not currently expose a remote-collection mode for individual custodian passwords; passwords must be entered together in the Sign CSR dialog.

### 10.5 Suspend, Reactivate, Archive <a name="issuer-keys-lifecycle"></a>

The Issuer Keys table also exposes lifecycle actions on the row:

| Icon | Action | Available When | Confirmation |
|------|--------|----------------|--------------|
| **Pause** (amber) | Suspend | Status is `active` | *"Are you sure you want to suspend this key? It will not be usable until reactivated."* |
| **Play** (green) | Reactivate | Status is `suspended` | *"Reactivate this key?"* |
| **Archive box** (rose) | Archive | Status is `pending`, `active`, or `suspended` | *"Are you sure you want to archive this key? This action cannot be undone."* |

`archived` is a terminal state — the key cannot sign anything and cannot be reactivated. The Shamir shares remain in storage so the key history is auditable, but no further use is possible.

> **Note:** Suspending an issuer key does not invalidate certificates already issued by it. Use [§11 Certificates](#certificates) to revoke individual certificates if needed.

---

## 11. Certificates <a name="certificates"></a>

> **Visible to all roles.** **Revocation is restricted to CA Admins.** Navigate to **Certificates** in the **Key Management** section.

Page title: *"Certificates"*

### Filtering and search

The top filter card has:

| Filter | Description |
|--------|-------------|
| **CA Instance** | Dropdown of all CA instances in the tenant |
| **Issuer Key** | Text search with live autocomplete (300 ms debounce). Shows matching keys; click one to select. The selection appears as a small badge with an `×` to clear it. |
| **Status** | Dropdown: `All`, `Active`, `Revoked` |

Click **Search** (magnifying glass) to apply. The result count is shown next to the button: *"N certificate(s)"*.

### Certificates table

Paginated, **20 per page**.

| Column | Description |
|--------|-------------|
| **Serial** | Serial number, monospace, truncated |
| **Subject DN** | Subject distinguished name, truncated |
| **Issuer Key** | The signing key alias |
| **Valid Until** | Local timestamp |
| **Status** | Badge: `active` (green) or `revoked` (red) |
| **Remaining** | Colour-coded countdown: green if >30 days, amber if `<30d (expiring soon)`, red if `Expired` or `Expires today` |
| **Actions** | Eye icon (view) — only for active certs |

Click anywhere on a row (or the eye icon) to open the **Certificate Details** side panel.

Empty / loading: *"Loading..."* or *"No certificates found."*

### Certificate detail panel

The panel slides in from the side and is closed with the `×` button.

**Basic information:**

- Serial Number
- Status (with revocation timestamp and reason if revoked)
- Subject DN
- Not Before / Not After (with colour-coded remaining days)
- SHA-256 Fingerprint (colon-separated hex)

**X.509 Details** (shown when parseable):

- Issuer DN
- Signature Algorithm
- Public Key Algorithm
- Serial (Hex)
- Basic Constraints — e.g. *"CA: Yes, Path Length: 1"*
- Key Usage — rendered as a row of badges (`digital_signature`, `key_encipherment`, etc.)
- Extensions — list of OID, name, critical flag

**Certificate PEM** — read-only textarea with the full PEM (when available).

### Revoking a certificate

> **CA Admin only.** A red **Revoke Certificate** section appears at the bottom of the detail panel only when the certificate is `active` and your role is `ca_admin`. Other roles will not see this section.

| Field | Description |
|-------|-------------|
| **Reason** | Dropdown of RFC 5280 reasons: `Unspecified`, `Key Compromise`, `CA Compromise`, `Affiliation Changed`, `Superseded`, `Cessation of Operation` |

Click **Revoke** (no-symbol icon, red). Confirmation: *"Are you sure you want to revoke this certificate? This action cannot be undone."*

If a non-admin attempts to revoke (e.g., via a stale UI state) the engine returns: *"Only CA administrators can revoke certificates."*

After revocation the certificate's status flips to `revoked` and the panel shows the revocation timestamp and reason. The audit log records the actor and reason.

---

## 12. Audit Log <a name="audit-log"></a>

> **Visible to CA Admins and Auditors.** Navigate to **Audit Log** in the **Administration** section.

Page title: *"Audit Log"*

### Compliance banner

> *"Audit Trail — Tamper-evident record of all CA operations and user management events. Compliant with WebTrust for CAs, ETSI EN 319 401, ISO 27001, and CA/Browser Forum Baseline Requirements."*

### Filters

A single filter form with:

| Filter | Type | Notes |
|--------|------|-------|
| **CA Instance** | Dropdown | Default *All* |
| **Category** | Dropdown | `All`, `CA Operations`, `User Management` |
| **Action** | Dropdown | `All`, `Login`, `Key Generated`, `Ceremony Initiated`, `Login Failed`, `User Created`, `User Suspended`, `User Activated`, `User Deleted`, `Password Reset`, `Password Changed`, `Profile Updated` |
| **Actor** | Text search | Substring match against the actor username |
| **From / To** | Date inputs | Inclusive date range |

Click **Apply Filter** (funnel icon) to reload the table. Active filters are reflected in the URL so you can bookmark or share specific views.

### Events table

Paginated, **10 per page**, ordered newest first.

| Column | Description |
|--------|-------------|
| **Timestamp** | Local time |
| **Category** | Badge: `CA Ops` (info) or `User Mgmt` (secondary) |
| **Action** | Ghost badge with the action name |
| **Actor** | Username of the user who performed the action |
| **Event ID** | Unique event UUID for traceability |

Pagination shows *"Showing X–Y of Z"* with `«` / `»` controls.

### Exporting

Two export buttons next to **Apply Filter**:

| Button | Output |
|--------|--------|
| **CSV** (document-arrow-down icon) | Downloads `audit-log-<date>.csv`. Columns: Timestamp (with timezone offset and name), Category, Action, Actor, Event ID |
| **JSON** (code-bracket icon) | Downloads `audit-log-<date>.json` (formatted) |

Both exports respect the active filters and are capped at **1000 records** per request. If your filter selects more than 1000 events you will see: *"Exported [limit] of [total] records. Narrow your filters to export the rest."* Tighten the filter (e.g., shorten the date range) and re-export.

---

## 13. Profile & Password Management <a name="profile"></a>

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

## 14. Forgot Password <a name="forgot-password"></a>

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

## 15. Quick Setup (Dev/Test Only) <a name="quick-setup"></a>

> **Only available when `enable_quick_setup` is true in the CA Portal config.** In production this page is disabled and a visit is redirected to `/` with the error *"Quick Setup is disabled in this environment."*

Navigate to **Quick Setup** (route `/quick-setup`).

Page title: *"Quick CA Hierarchy Setup"*

### Warning banner

> *"Dev/Test Only — This page runs a full CA hierarchy setup in one click. Not for production use."*

### Form

| Field | Description |
|-------|-------------|
| **Root CA Name** | Default *"Root CA"* |
| **Root CA Algorithm** | Dropdown of every supported algorithm with a one-line description (e.g., *"KAZ-SIGN-128 — Post-Quantum — Malaysia local PQC"*) |
| **Sub-CA Name** | Default *"Issuing CA"* |
| **Sub-CA Algorithm** | Same dropdown as above |

Click **Run Quick Setup**. The button shows a spinner and *"Running..."* while a single backend operation creates:

1. Root CA instance
2. Software keystore for the Root CA
3. Root CA key ceremony (auto-completed with synthetic custodians)
4. Sub-CA instance under the Root CA
5. Software keystore for the Sub-CA
6. Sub-CA key ceremony (auto-completed)

A **Setup Log** card streams progress with colour-coded entries:

- ✓ Green for success — e.g. *"Created Root CA: [name] ([id])"*, *"Root CA key ceremony complete — [algo], key: [key_alias]"*
- − Grey for skipped
- ✗ Red for errors

On success: *"Setup complete! Go to CA Instances to see your hierarchy."* with **View CA Instances** and **View Ceremonies** buttons. On failure: *"Setup completed with errors. Check above."*

> **Why this exists:** It is a convenience for developers and integration tests. The synthetic ceremony bypasses the multi-party Shamir flow described in [§9](#ceremony) and should never be enabled in production environments.

---

## 16. Security Reference <a name="security"></a>

### Authentication

| Feature | Details |
|---------|---------|
| **Password hashing** | Argon2 (memory-hard, GPU/ASIC-resistant) |
| **Minimum password length** | 8 characters |
| **Temporary credentials** | Auto-generated; 24-hour expiration; `must_change_password` enforced on first login |
| **Session storage** | Server-side ETS; not stored in cookies |
| **Witness re-authentication** | Auditors must re-enter their password for every ceremony attestation |

### Rate limiting

| Action | Limit |
|--------|-------|
| Login attempts | 5 per 5 minutes per IP |
| Password reset requests | 3 per 15 minutes per IP (covers request and code submission) |
| Ceremony initiations | 10 per hour per tenant |

### Session security

| Feature | Details |
|---------|---------|
| **Idle timeout** | 30 minutes (configurable via `session_idle_timeout_ms`) |
| **Timeout warning** | 5 minutes before expiry, modal with **Continue Working** button |
| **IP pinning** | Sessions invalidated on IP change |
| **User-agent matching** | Session terminated if browser fingerprint changes mid-session |
| **Concurrent session detection** | Security alert on multiple simultaneous sessions |

### Key material protection

- **Private keys never exist outside the HSM**, except briefly in memory during reconstruction for a signing operation. After reconstruction, the in-memory key is wiped.
- **Custodian passwords** are held in an in-memory ETS store only for the duration of the ceremony preparation phase, then wiped.
- **Shamir secret sharing** ensures that no single custodian or admin can use a key. Reconstruction requires K of N custodian passwords entered together.
- **Auditor witnessing** of every ceremony phase enforces separation of duties.
- **Tamper-evident audit log** records every CA operation with timestamp, actor, action, target, and structured details.

### Audit trail coverage

The audit log records, at minimum:

- All successful and failed logins
- All session expirations and forced logouts
- CA instance create / activate / suspend / online / offline / rename
- All ceremony lifecycle events (initiate, custodian accept, witness attest, key generation, completion, failure, cancellation)
- Issuer key generate / activate / sign / suspend / reactivate / archive
- Certificate sign and revoke (with reason)
- Keystore configure
- HSM device probe
- User invite / activate / suspend / delete / password reset / profile update
- Suspicious activity (session hijack attempts, concurrent sessions, new IP logins)

Each event has a unique event ID for cross-system traceability.

---

## 17. Troubleshooting <a name="troubleshooting"></a>

### "We can't find the internet" / "Attempting to reconnect"

The browser has lost its WebSocket connection to the server. This can happen if the server was restarted or your network briefly dropped. The page automatically attempts to reconnect; refresh if it persists.

### "Something went wrong!"

An unexpected server error occurred. Refresh the page; if it persists, ask a CA Admin to check the CA Portal logs.

### "Your temporary credentials have expired"

Your invitation or password reset has a 24-hour window. Ask a CA Admin to use **Resend Invite** on the [Users](#users) page (or **Reset Password** for an existing user). The platform admin can also reset users from the Platform Portal.

### Cannot suspend / delete a user

You cannot perform Suspend, Activate, or Delete actions on **your own** row — the action icons are hidden. Ask another CA Admin to do it for you.

### "No active key managers found" / "No active auditors found" when initiating a ceremony

You need at least one active key manager and one active auditor in this tenant before you can initiate a ceremony. Invite them from the [Users](#users) page first.

### "No HSM devices assigned to your tenant"

HSM devices are owned by the platform admin. Contact them and ask them to grant your tenant access to a registered HSM device from the Platform Portal's tenant detail page.

### "This CA instance already has a [type] keystore"

A CA instance can have at most one Software keystore and one HSM keystore. If you need to change keystores, suspend or archive the existing one first (or create the keystore on a different CA instance).

### Custodian forgot their password

The share is unrecoverable. The ceremony will need to be cancelled and re-initiated. Cancel the failed ceremony from the history table and start a new one with a fresh set of custodians (or a new password from the same custodian).

### Ceremony stuck in "preparing"

This usually means one or more custodians have not yet accepted their share. Open the ceremony in the Progress Dashboard (eye icon) and check the Participants table for `pending` rows. Contact those custodians directly. If the time window expires, the ceremony will move to `failed` and can be deleted and re-initiated.

### Witness button is greyed out

The witness button is enabled only when its phase's preconditions are met:

- **Witness Preparation** — All custodians must show as `accepted`.
- **Witness Key Generation** — Preparation must be witnessed AND the keygen result must be present.
- **Witness Completion** — Key generation must be witnessed.

If you believe all conditions are met but the button is still disabled, refresh the page (the PubSub connection may have stalled).

### Sign CSR fails with reconstruction error

Most likely a wrong custodian password was entered. The engine cannot tell which one was wrong (by design, to avoid leaking information). Re-open the modal and have each custodian re-enter their password carefully. If the failure persists, the share material may be corrupted — this is a serious incident; contact your platform administrator and audit the ceremony's history.

### Cannot revoke a certificate

Only **CA Admins** can revoke. The Revoke Certificate section is hidden in the certificate detail panel for other roles. Ask a CA Admin, or check that you are signed in with the right account.

### Quick Setup page redirects to "/"

Quick Setup is disabled by default. It is intended for development and integration testing only and is enabled by setting `enable_quick_setup: true` in the CA Portal application config. Do not enable this in production.

### Session expired unexpectedly

Sessions expire after 30 minutes of inactivity. Other reasons a session can be terminated before then:

- **IP change detected** — Your IP address changed (VPN reconnect, network switch, mobile handover)
- **Browser change detected** — User-agent mismatch (browser update, profile switch)
- **Force logout** — A platform admin terminated your session from the Platform Portal's Active Sessions page
