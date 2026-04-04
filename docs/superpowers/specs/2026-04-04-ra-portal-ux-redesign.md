# RA Portal UX Redesign — Setup Wizard, Role-Adaptive Dashboard, Sidebar Reorganization

## Overview

Redesign the RA Portal user experience to guide technical RA administrators through a sequential setup workflow on first login, provide role-adaptive dashboards for daily operations, and reorganize navigation by purpose.

**Target user:** Technical PKI administrator (IT security staff, understands X.509, DN policies, key usage). Needs efficiency, not hand-holding.

**Deployment context:** Platform Admin creates tenant + RA instance + first RA admin account. RA Admin receives invitation, logs in, changes password, then configures the RA independently.

---

## 1. First-Login Flow

### Trigger

After the RA admin changes their password (existing `must_change_password` flow), the system detects whether setup is needed by checking:

- Zero `ra_ca_connections` for this tenant
- Zero `cert_profiles` for this tenant

If both are true → show the **Welcome Screen**. Otherwise → go to dashboard.

### Welcome Screen

Full-page, no sidebar. Shows:

- RA instance name (e.g., "JPJ Registration Authority")
- Brief message: "Let's configure your Registration Authority."
- **[Start Setup]** button → launches wizard at Step 1
- **[Skip, I'll configure manually]** link → goes to dashboard with setup checklist

The welcome screen appears only once. After dismissal (either path), the dashboard handles any remaining incomplete steps via the embedded checklist.

---

## 2. Setup Wizard

### Interaction Pattern

Full-page layout, sidebar hidden. Step indicator at the top showing progress (Step 1 of 5). Each step has **[Next]** and **[Skip]** buttons (where skippable). Final step shows a summary and **[Go to Dashboard]**.

### Steps

#### Step 1: Connect to CA (required)

- Query CA Engine for available leaf issuer keys via `GET /api/v1/issuer-keys?leaf_only=true`
- Display keys as selectable cards: key name, algorithm (ECC-P256, RSA-2048, KAZ-SIGN), parent CA instance name, status
- Admin selects one or more keys to connect
- Creates records in `ra_ca_connections` table
- **Done signal:** At least one active connection exists
- **Not skippable** — everything downstream depends on this

#### Step 2: Certificate Profiles (required)

- Template picker: TLS Server, TLS Client, Code Signing, Email/S-MIME, Custom
- Selecting a template pre-fills the form with smart defaults (see Section 7)
- All fields editable after template selection
- Issuer key dropdown filtered to keys connected in Step 1
- Admin can create multiple profiles (repeat within this step)
- **Done signal:** At least one cert profile exists
- **Not skippable** — officers need profiles to process CSRs

#### Step 3: Invite Team (skippable)

- Form to add RA officers and auditors (username, display name, email, role)
- Shows the invitation flow — users receive email with temporary password
- Admin can add multiple users
- **Done signal:** At least one non-admin user exists (or explicitly skipped)
- **Skippable** — admin can work solo initially

#### Step 4: Service Configuration (skippable)

- Configure OCSP responder URL, CRL distribution point, TSA endpoint
- Pre-fill with defaults if validation service is detected at standard port
- **Done signal:** At least one service config exists (or explicitly skipped)
- **Skippable** — can defer to later

#### Step 5: API Keys (skippable)

- Create API keys for external systems that will submit CSRs programmatically
- Explain use case: "Automated CSR submission from your organization's servers"
- **Done signal:** At least one API key exists (or explicitly skipped)
- **Skippable** — only needed for automation

### Wizard Summary

After the last step (completed or skipped), show a summary card:

- CA Connection: Connected to [key name] ([algorithm])
- Cert Profiles: [N] profiles created
- Team: [N] users invited (or "Skipped — you can add users from Administration > Users")
- Services: Configured (or "Skipped")
- API Keys: [N] created (or "Skipped")
- **[Go to Dashboard]** button

---

## 3. Sidebar Redesign

### Grouped by Purpose

Replace the current flat list with purpose-grouped sections. Section headers are non-clickable labels.

```
OVERVIEW
  Dashboard

OPERATIONS
  CSR Management
  Certificates
  Validation Services

CONFIGURATION
  Certificate Profiles
  CA Connection
  Service Configs

ADMINISTRATION
  Users
  API Keys
  RA Instances
  Audit Log

──────────
  My Profile
```

### Role-Based Visibility

Menu items are hidden (not grayed out) for roles that cannot access them.

| Section | RA Admin | RA Officer | Auditor |
|---------|----------|------------|---------|
| OVERVIEW | Dashboard | Dashboard | Dashboard |
| OPERATIONS | All 3 | All 3 | None |
| CONFIGURATION | All 3 | None | None |
| ADMINISTRATION | All 4 | None | Audit Log only |
| My Profile | Yes | Yes | Yes |

**Auditor sidebar:** Overview (Dashboard), Compliance (Audit Log), My Profile.

---

## 4. Role-Adaptive Dashboard

The dashboard renders different content based on `current_user.role`.

### RA Admin Dashboard

**Row 1 — System Health** (3 cards):
- CA Engine: connected/unreachable (checks `/health` on CA)
- Issuer Key: active/inactive (checks connected keys via CA API)
- Validation Services: OCSP healthy/unreachable, CRL status

**Row 2 — Setup Completeness** (conditional, auto-hides when complete):
- Progress bar: "Setup: 3 of 5 complete"
- Links to each incomplete step (e.g., "Configure services →")
- Dismissible after all required steps (1-2) are done

**Row 3 — Attention Required** (alert cards):
- Stuck CSRs: count of CSRs in "approved" status for >5 minutes (CA forwarding may have failed)
- Expiring DCV: challenges expiring within 24 hours
- Expiring Certificates: certs expiring within 30 days

**Row 4 — Team Activity**:
- Recent actions by officers: "Officer A approved CSR for CN=example.com (2 min ago)"
- Last 10 events, compact feed format

### RA Officer Dashboard

**Row 1 — My Queue** (primary card, large):
- Count of CSRs in "verified" status awaiting review
- Direct button: "Review CSRs →" (links to CSR Management filtered to verified)

**Row 2 — DCV Status**:
- Pending DCV challenges initiated by this officer
- Count + status of each (pending/passed/expired)

**Row 3 — My Recent Actions**:
- Last 5 approve/reject actions today
- Shows CSR subject DN, action, time

**Row 4 — Quick Stats**:
- CSRs processed today (count)
- Approval rate this week (percentage)

### Auditor Dashboard

**Row 1 — Recent Activity** (primary, tall):
- Last 20 audit events across all users
- Shows: timestamp, action, actor, target
- Link: "View full audit log →"

**Row 2 — Compliance Alerts**:
- Certificates expiring within 30 days (count)
- CSRs in abnormal states (stuck in approved, count)

**Row 3 — Quick Filters**:
- Buttons linking to pre-filtered audit log views: "Approvals today", "Rejections this week", "Revocations", "User changes"

---

## 5. New Data Model

### Table: `ra_ca_connections`

```sql
CREATE TABLE ra_ca_connections (
  id              binary_id PRIMARY KEY,
  ra_instance_id  binary_id NOT NULL REFERENCES ra_instances(id),
  issuer_key_id   VARCHAR NOT NULL,
  issuer_key_name VARCHAR,
  algorithm       VARCHAR,
  ca_instance_name VARCHAR,
  status          VARCHAR NOT NULL DEFAULT 'active',
  connected_at    TIMESTAMPTZ NOT NULL,
  connected_by    binary_id,
  inserted_at     TIMESTAMPTZ NOT NULL,
  updated_at      TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX ra_ca_connections_instance_key
  ON ra_ca_connections (ra_instance_id, issuer_key_id);
```

**Fields:**
- `issuer_key_id` — the CA Engine's issuer key UUID (string, not FK — lives in CA's database)
- `issuer_key_name`, `algorithm`, `ca_instance_name` — cached from CA Engine at connection time for display without re-querying CA
- `status` — `active` or `revoked` (revoking a connection prevents new cert profiles from using that key)
- `connected_by` — the RA admin who established the connection

**Usage:**
- Cert profile creation: issuer key dropdown filtered by `ra_ca_connections WHERE status = 'active' AND ra_instance_id = current_ra_instance`
- Dashboard health check: iterate connections to verify each key is still active on CA side
- Wizard step 1 completion: check `count(ra_ca_connections) > 0`

---

## 6. Setup Completeness Detection

No new schema needed. The dashboard checks existing tables on each load:

| Step | "Done" check | Query |
|------|-------------|-------|
| 1. CA Connection | `ra_ca_connections` count > 0 for tenant | `Repo.aggregate(where status = 'active')` |
| 2. Cert Profiles | `cert_profiles` count > 0 for tenant | `CertProfileConfig.list_profiles(tenant_id) != []` |
| 3. Team | Non-admin users exist | `UserManagement.list_users(tenant_id, []) |> Enum.any?(& &1.role != "ra_admin")` |
| 4. Services | `service_configs` count > 0 | `ServiceConfig.list_service_configs(tenant_id) != []` |
| 5. API Keys | `ra_api_keys` count > 0 | `ApiKeyManagement` count check |

Steps 1-2 are required. Steps 3-5 are optional — the checklist shows them as "recommended" with a skip/dismiss option.

The setup checklist card on the dashboard auto-hides when steps 1-2 are done AND the admin has either completed or explicitly dismissed steps 3-5.

---

## 7. Certificate Profile Templates

Pre-defined templates with industry-standard defaults:

### TLS Server
```
name: (admin enters)
key_usage: digitalSignature, keyEncipherment
ext_key_usage: serverAuth
digest_algo: sha256
validity_days: 365
subject_dn_policy:
  required: [CN]
  optional: [O, OU, L, ST, C]
  require_dcv: true
```

### TLS Client
```
name: (admin enters)
key_usage: digitalSignature
ext_key_usage: clientAuth
digest_algo: sha256
validity_days: 365
subject_dn_policy:
  required: [CN]
  optional: [O, OU, E]
  require_dcv: false
```

### Code Signing
```
name: (admin enters)
key_usage: digitalSignature
ext_key_usage: codeSigning
digest_algo: sha256
validity_days: 365
subject_dn_policy:
  required: [CN, O]
  optional: [OU, L, ST, C]
  require_dcv: false
```

### Email / S-MIME
```
name: (admin enters)
key_usage: digitalSignature, keyEncipherment
ext_key_usage: emailProtection
digest_algo: sha256
validity_days: 365
subject_dn_policy:
  required: [CN, E]
  optional: [O, OU]
  require_dcv: false
```

### Custom
All fields empty except `digest_algo: sha256` and `validity_days: 365`.

After template selection, all fields are editable. The admin must also select an issuer key from the connected CA keys dropdown.

---

## 8. Pages Summary

### New Pages
| Page | Route | Description |
|------|-------|-------------|
| Welcome Screen | `/welcome` | First-login only, full-page, launches wizard or skips |
| Setup Wizard | `/setup-wizard` | Full-page, 5 steps, no sidebar |
| CA Connection | `/ca-connection` | Manage RA↔CA issuer key connections |

### Modified Pages
| Page | Changes |
|------|---------|
| Dashboard | Role-adaptive content, setup checklist card |
| Cert Profiles (create) | Template picker before form, issuer key dropdown filtered by connections |
| App Layout | Sidebar grouped by purpose with role-based visibility |

### Unchanged Pages
CSR Management, Certificates, Validation Services, Users, API Keys, RA Instances, Service Configs, Audit Log, My Profile — functionality stays the same, only sidebar placement changes.

---

## 9. Error States

### Wizard Error Handling
- **CA Engine unreachable at Step 1:** Show error with retry button. "Cannot reach CA Engine at [URL]. Check that the CA Engine is running and the connection is configured correctly."
- **No leaf issuer keys available:** "No active leaf issuer keys found on the CA Engine. A CA administrator must complete a key ceremony first."
- **Profile creation fails:** Inline validation errors on the form. Admin stays on Step 2.
- **Invitation email fails:** Show warning but allow proceeding. "User account created but invitation email could not be sent. Share the temporary password manually."

### Dashboard Health Errors
- **CA Engine unreachable:** Red status card with last-checked timestamp. Auto-refreshes every 30 seconds.
- **Issuer key deactivated:** Warning card: "Issuer key [name] is no longer active on the CA Engine. New certificates cannot be signed with this key."
- **Stuck CSRs detected:** Amber alert: "[N] CSRs approved but not yet issued. CA Engine may be unreachable or issuer key may be inactive."
