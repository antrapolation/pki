# Multi-CA / Multi-RA Design — Beta 3

**Date:** 2026-03-30
**Status:** Draft
**Version:** 1.0.0-beta.3

## Overview

Evolve the PKI system from a single implicit CA/RA per tenant to supporting multiple CA instances (with hierarchy) and multiple RA instances per tenant. This enables enterprise PKI deployments where a single organization operates multiple CAs across algorithm families and multiple RAs for different departments or partners.

## Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Portal separation | Platform Admin = tenants, CA Portal = CA instances, RA Portal = RA instances | Clean separation of concerns; each portal serves its role |
| Tenant `signing_algorithm` | Removed | Algorithm belongs on issuer keys, not the org container |
| CA hierarchy model | `parent_id` self-reference, structurally unlimited depth | Supports Root → Intermediate → Issuing chains |
| Depth enforcement | Runtime check against `tenant.max_ca_depth` (default: 2) | Billing/subscription hook; data model is unrestricted |
| CA instance role | Derived from hierarchy position, not stored | Root = no parent; Intermediate = has parent + children; Issuing = has parent + no children |
| Root CA issuing | Strict — root CA never issues end-entity certs | Must create at least Root → Issuing Sub-CA before cert issuance |
| RA-to-CA binding | Via `cert_profile.issuer_key_id` | No separate join table; cert profile is the natural binding point |
| RA issuer key discovery | RA fetches available keys from CA Engine API at profile creation time | Filtered to active keys from leaf CA instances within same tenant |
| Cert profile to issuer key | 1:1 (one profile = one issuer key) | Algorithm-specific policies; RA instance has multiple profiles for multiple algorithms |
| Standalone Root CA | Not allowed to issue end-entity certs | Enforces proper hierarchy |
| Tenant provisioning | Keep auto-creating CA/RA admins | Admins create instances after first login |
| Approach | Evolve in-place (Approach A) | Existing schemas are close; gaps are relationships, not fundamentally wrong models |

## Data Model Changes

### Platform Database

#### `tenants` (modified)

| Field | Change |
|---|---|
| `signing_algorithm` | **REMOVED** — algorithm lives on `issuer_keys` |
| `kem_algorithm` | **REMOVED** — same reason |
| `max_ca_depth` | **NEW** — integer, default 2. Billing/subscription hook for CA hierarchy depth limit |

### Tenant Database — CA Schema

#### `ca_instances` (modified)

| Field | Change |
|---|---|
| `parent_id` | **NEW** — uuid FK, self-referencing. `NULL` = Root CA. Points to parent CA instance |

New associations:
- `has_many :children, CaInstance, foreign_key: :parent_id`
- `belongs_to :parent, CaInstance, foreign_key: :parent_id`

Derived properties (computed, not stored):
- **is_root?** — `parent_id == nil`
- **is_leaf?** — has no children
- **is_intermediate?** — has parent AND has children
- **depth** — count of ancestors to root

Validation rules:
- On create with `parent_id`: depth of new instance must not exceed `tenant.max_ca_depth`
- On create child under an existing leaf CA that has issued end-entity certs: warn admin that the parent will no longer be able to issue end-entity certs

#### `issuer_keys` (unchanged)

Already has `ca_instance_id` FK and per-key `algorithm`. No changes needed.

#### `issued_certificates` (unchanged)

Already linked to `issuer_key_id`. No changes needed.

### Tenant Database — RA Schema

#### `ra_instances` (NEW)

| Field | Type | Notes |
|---|---|---|
| `id` | uuid PK | Auto-generated UUIDv7 |
| `name` | string, unique | e.g. "JPJ Registration Authority" |
| `status` | string | "initialized", "active", "suspended" |
| `created_by` | string | Username of creator |
| `timestamps` | | inserted_at, updated_at |

Associations:
- `has_many :ra_users`
- `has_many :cert_profiles`
- `has_many :ra_api_keys`

#### `ra_users` (modified)

| Field | Change |
|---|---|
| `ra_instance_id` | **NEW** — uuid FK to `ra_instances`. Scopes user to an RA instance |

#### `ra_api_keys` (modified)

| Field | Change |
|---|---|
| `ra_instance_id` | **NEW** — uuid FK to `ra_instances`. Scopes API key to an RA instance |

#### `cert_profiles` (modified)

| Field | Change |
|---|---|
| `ra_instance_id` | **NEW** — uuid FK to `ra_instances`. Scopes profile to an RA instance |
| `issuer_key_id` | **NEW** — string (uuid reference to CA Engine's issuer key). Determines which CA instance and algorithm signs certs under this profile |

#### `csr_requests` (unchanged)

Already linked to `cert_profile_id`. The issuer key is resolved transitively via the cert profile.

## API Changes

### CA Engine API

#### Modified Endpoints

| Endpoint | Change |
|---|---|
| `GET /api/v1/issuer-keys` | Add `?leaf_only=true` filter to return only keys from leaf CA instances |
| `POST /api/v1/certificates/sign` | Add validation: reject if issuer key's CA instance has children (not a leaf) |

#### New Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v1/ca-instances` | POST | Create CA instance (with optional `parent_id`) |
| `/api/v1/ca-instances` | GET | List all CA instances (returns hierarchy tree) |
| `/api/v1/ca-instances/:id` | GET | Get single CA instance with children + issuer keys |
| `/api/v1/ca-instances/:id` | PATCH | Update CA instance (name, status) |
| `/api/v1/ca-instances/:id/children` | GET | List direct children of a CA instance |

#### Validation Logic

- `POST /api/v1/ca-instances` with `parent_id`: check depth does not exceed `tenant.max_ca_depth`
- `POST /api/v1/certificates/sign`: reject if issuer key belongs to a non-leaf CA instance

### RA Engine API

#### Modified Endpoints

| Endpoint | Change |
|---|---|
| `POST /api/v1/cert-profiles` | Require `ra_instance_id` and `issuer_key_id` |
| `GET /api/v1/cert-profiles` | Filter by `ra_instance_id` |
| `POST /api/v1/csrs/:id/forward` | Resolve `issuer_key_id` from cert profile instead of global config |
| `POST /api/v1/api-keys` | Require `ra_instance_id` |
| `POST /api/v1/users` | Require `ra_instance_id` |

#### New Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v1/ra-instances` | POST | Create RA instance |
| `/api/v1/ra-instances` | GET | List RA instances |
| `/api/v1/ra-instances/:id` | GET | Get single RA instance with summary |
| `/api/v1/ra-instances/:id` | PATCH | Update RA instance (name, status) |
| `/api/v1/available-issuer-keys` | GET | Proxy to CA Engine — active keys from leaf CAs for cert profile creation |

### Platform Admin API

| Change | Detail |
|---|---|
| Tenant creation | Remove `signing_algorithm` and `kem_algorithm` from form/changeset |
| Tenant detail metrics | Aggregate across all CA and RA instances |
| `max_ca_depth` | Add to tenant schema, default 2, not exposed in UI yet (billing hook) |

### CSR Forwarding Flow (Updated)

Current flow: `CsrValidation.forward_to_ca/1` → `HttpCaClient.sign_certificate/2` → uses global `default_issuer_key_id` config.

New flow:
1. `forward_to_ca/1` loads the CSR's cert profile
2. Reads `cert_profile.issuer_key_id`
3. Passes `issuer_key_id` to `HttpCaClient.sign_certificate/2`
4. CA Engine signs with that specific key

The `CaEngineConfig` GenServer global config for `default_issuer_key_id` is no longer needed. The `HttpCaClient.resolve_issuer_key_id/1` function already supports reading `issuer_key_id` from the cert profile map — this just needs to be wired up.

## UI/UX Changes

### Platform Admin Portal

**Tenant Creation Wizard:**
- Remove "Default Signing Algorithm" dropdown from Step 1
- Keep: Name, Slug, Email, verification flow, provisioning
- No other changes

**Tenant Detail Page:**
- Update metrics cards: show CA Instances count, RA Instances count (new)
- Metrics aggregate across all instances: total certs issued, total pending CSRs

### CA Portal

**New: CA Instances Page (replaces or augments Dashboard)**
- Tree/hierarchy view showing Root → Sub-CAs
- Auto-computed badges: "Root", "Intermediate", "Issuing" based on position
- "+ New Root CA" button at top level
- "+ Sub-CA" button on each CA instance
- Each instance shows: name, status, issuer key count, algorithm summary
- Click to drill into instance detail (existing issuer key management, key ceremony, etc.)

**New: Create CA Instance Dialog**
- Fields: Name (required), Parent CA (dropdown, "None" for Root CA)
- Validation: depth check against `max_ca_depth`
- Algorithm is NOT set here — it's set when creating issuer keys via Key Ceremony

**Existing pages — scoped to CA instance:**
- Keystores page: filter by CA instance
- Key Ceremonies page: filter by CA instance
- Users page: no change (CA users are tenant-scoped, not instance-scoped)
- Audit Logs page: add CA instance filter dropdown

### RA Portal

**New: RA Instances Page**
- List view showing all RA instances
- Each instance shows: name, status, cert profile count, API key count, pending CSR count
- "+ New RA Instance" button
- Click to drill into instance detail

**New: Create RA Instance Dialog**
- Fields: Name (required)
- Simple creation, status defaults to "initialized"

**Updated: Cert Profile Creation**
- Add "RA Instance" dropdown (required)
- Add "Issuer Key" picker (required) — fetched from CA Engine API
  - Shows: key alias, CA instance name, algorithm
  - Filtered to: active keys from leaf CA instances only
- Existing fields unchanged (subject DN policy, key usage, validity, etc.)

**Existing pages — scoped to RA instance:**
- CSR Requests page: filter by RA instance (via cert profile)
- API Keys page: filter by RA instance
- Service Configs page: no change (tenant-scoped, not instance-scoped)
- Users page: filter by RA instance
- Audit Logs page: add RA instance filter dropdown

## Audit Trail Updates

### New Audit Actions

| Action | When | Resource Type |
|---|---|---|
| `ca_instance_created` | CA admin creates Root or Sub-CA | `ca_instance` |
| `ca_instance_status_changed` | CA instance activated/suspended | `ca_instance` |
| `ra_instance_created` | RA admin creates RA instance | `ra_instance` |
| `ra_instance_status_changed` | RA instance activated/suspended | `ra_instance` |
| `cert_profile_created` | RA admin creates profile with issuer key binding | `cert_profile` |
| `cert_profile_updated` | RA admin changes profile (especially issuer key) | `cert_profile` |
| `hierarchy_modified` | Sub-CA added under existing CA | `ca_instance` |
| `issuer_key_rotation_started` | New key created in CA that already has active keys | `issuer_key` |
| `cert_profile_issuer_key_changed` | Cert profile switched to a different issuer key | `cert_profile` |
| `issuer_key_archived` | Old issuer key archived after rotation | `issuer_key` |

### Context Enrichment

Add `ca_instance_id` field to `AuditEvent` schema for direct filtering. This enables the core auditor query: "show me all events for this CA instance."

RA instance context goes in the existing `details` map since RA-side actions are less security-critical.

### Portal Audit Views

- **CA Portal Audit Logs:** Add CA instance filter dropdown. Auditor role can view all CA instances within their tenant.
- **RA Portal Audit Logs:** Add RA instance filter dropdown. Auditor role can view all RA instances within their tenant.

## Basic Key Rotation Support

Key rotation is a core PKI security requirement. Beta.3 supports **manual key rotation** — the admin-driven process of replacing an issuer key within a CA instance. Automated/scheduled rotation is out of scope.

### How It Works

A CA instance can have multiple issuer keys (different aliases, same or different algorithms). Rotation is creating a new key and switching cert profiles to use it:

1. **CA Admin** creates new issuer key in the same CA instance (e.g. "gov-kaz-128-2026")
2. **CA Admin** runs key ceremony → new key becomes active
3. **RA Admin** updates cert profile(s) → changes `issuer_key_id` to the new key
4. **CA Admin** archives old key when no longer needed for new signings

Old certificates signed by the archived key remain valid until they expire. The chain of trust is maintained because the old key's certificate is still verifiable.

### Design Implications

- **Cert profile `issuer_key_id` is mutable** — RA admin can update it to point to a new issuer key. This is the switchover mechanism.
- **Multiple active issuer keys per CA instance is allowed** — during the overlap period, both old and new keys are active. Some cert profiles use the old key, others use the new one.
- **Archiving a key does not revoke its certs** — archived means "no longer signs new certs", not "certs are invalid". Existing certs continue to validate.
- **Archiving a key that is still referenced by cert profiles is blocked** — the system must reject archiving an issuer key if any active cert profile still points to it. The RA must switch profiles first.

### Audit Actions for Key Rotation

| Action | When | Resource Type |
|---|---|---|
| `issuer_key_rotation_started` | New issuer key created in a CA instance that already has active keys | `issuer_key` |
| `cert_profile_issuer_key_changed` | Cert profile's `issuer_key_id` updated to a different key | `cert_profile` |
| `issuer_key_archived` | Old issuer key archived after rotation | `issuer_key` |

### Validation Rules

- On `IssuerKey` status transition to `archived`: check no active `cert_profiles` reference this key (query via RA Engine API or cross-schema check)
- On `CertProfile` update of `issuer_key_id`: new key must be active and belong to a leaf CA instance

## End-to-End Flow: Tenant Setup to First Certificate

1. **Platform Admin** creates tenant "Gov Malaysia" (name, slug, email)
2. **CA Admin** logs into CA Portal → creates Root CA instance "MyGov Root"
3. **CA Admin** runs Key Ceremony on Root CA → generates root issuer key (KAZ-Sign-256)
4. **CA Admin** creates Sub-CA "PQC Issuing CA" under Root
5. **CA Admin** runs Key Ceremony on Sub-CA → generates issuer key (KAZ-Sign-128)
6. **CA Admin** Root CA signs Sub-CA's certificate → Sub-CA becomes active
7. **RA Admin** logs into RA Portal → creates RA instance "JPJ RA"
8. **RA Admin** creates Cert Profile → picks issuer key "gov-kaz-128" from PQC Issuing CA
9. **RA Officer** receives CSR → validates → approves → forwards to CA
10. **CA Engine** signs cert with "gov-kaz-128" key → returns cert to RA

## Migration Notes

Since the system is pre-production, migrations are straightforward:

1. Add `parent_id` column to `ca_instances` (nullable FK to self)
2. Create `ra_instances` table in RA schema
3. Add `ra_instance_id` column to `ra_users`, `ra_api_keys`, `cert_profiles` (nullable — RA admins created at tenant provisioning time exist before any RA instance; they gain `ra_instance_id` when they create or are assigned to an RA instance)
4. Add `issuer_key_id` column to `cert_profiles` (required for new records — every cert profile must specify which issuer key signs its certs)
5. Remove `signing_algorithm` and `kem_algorithm` from `tenants`
6. Add `max_ca_depth` to `tenants` (default 2)
7. Add `ca_instance_id` to `audit_events` (nullable)
8. Add new audit actions to `PkiAuditTrail.Actions`

## Future: SSDID Wallet Integration

This design enables future integration with the SSDID wallet ecosystem. The integration model:

- **Wallet** authenticates with a **Business App** (DID server) via existing SSDID flows
- **Business App** is registered as an **RA** (has API key for a tenant)
- **Business App** forwards cert requests to the PKI CA on behalf of the wallet
- **Algorithm matching**: wallet's DID Document contains the algorithm in `verificationMethod.type`; the business app selects the cert profile with the matching issuer key algorithm

The multi-RA model naturally supports this — a business app is just another RA instance with its own API key, cert profiles, and quota. No PKI-side changes needed beyond what this design specifies.

## Out of Scope

- Billing/subscription system (only the `max_ca_depth` hook is included)
- SSDID wallet integration implementation (research complete, design compatible)
- Cross-tenant CA sharing (each tenant is fully isolated)
- Automated/scheduled key rotation (manual rotation is in scope)
- Automated certificate renewal
- OCSP/CRL service configuration changes (service configs remain tenant-scoped)
