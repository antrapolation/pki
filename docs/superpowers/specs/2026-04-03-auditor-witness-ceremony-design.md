# Auditor Witness & Async Key Ceremony Design

**Date:** 2026-04-03
**Status:** Approved
**Goal:** Transform the key ceremony from a single-operator wizard into a multi-participant async flow with auditor attestation, independent custodian share acceptance, and time-windowed completion.

---

## 1. Participant Model

Four roles participate in a ceremony, each with their own page:

| Role | Page | Responsibility |
|------|------|----------------|
| ca_admin | `/ceremony` (existing, modified) | Initiates ceremony, selects participants, monitors progress |
| key_manager | `/ceremony/custodian` (new) | Accepts assigned share with self-chosen key label + password |
| auditor | `/ceremony/witness` (new) | Witnesses each phase gate before it can proceed |

Only `ca_admin` can initiate a ceremony. Key managers and auditors are selected by the admin during initiation.

---

## 2. Ceremony Lifecycle

### Phases

```
INITIATED → PREPARING → GENERATING → COMPLETED
                                   ↘ FAILED
```

**Phase 1: INITIATED (ca_admin)**

Admin creates the ceremony with:
- Algorithm, keystore, key alias, cert type (root/sub-CA)
- Threshold k-of-n
- Selected key managers (n custodians)
- Selected auditor (1 person)
- Time window (default 24 hours, configurable 1-168 hours)

System creates:
- `KeyCeremony` record (status: "initiated")
- `IssuerKey` record (status: "pending")
- `ThresholdShare` placeholder records (status: "pending", one per custodian)
- Sends notification emails to all participants
- Computes `window_expires_at`

Status transitions to: **"preparing"**

**Phase 2: PREPARING (key_managers + auditor, async)**

Each assigned key manager independently:
1. Logs into CA Portal
2. Navigates to `/ceremony/custodian`
3. Sees their assigned ceremony
4. Enters key label (e.g., "alice-root-2026") and password
5. Clicks "Accept Share"
6. Share record updated: status → "accepted", key_label stored, password held in ETS (not DB)

Progress visible to all participants in real-time via PubSub.

When ALL custodians have accepted:
- Auditor notified: "All custodians ready, please witness preparation"
- Auditor reviews participant list, reviews who accepted when
- Auditor clicks "I Witness Preparation" (re-enters password to confirm)
- `CeremonyAttestation` record created for phase "preparation"

Status transitions to: **"generating"**

**Phase 3: GENERATING (automatic, seconds)**

Triggered automatically when all custodians ready + auditor witnessed preparation.

Atomic operation:
1. Generate keypair (private_key, public_key)
2. Compute fingerprint (SHA-256 of public key)
3. If root CA: self-sign certificate. If sub-CA: generate CSR.
4. Split private key: `Shamir.split(private_key, k, n)`
5. For each share: encrypt with custodian's password from ETS
6. Update each `ThresholdShare` with encrypted_share data
7. Wipe: private key, all custodian passwords from ETS, raw shares from memory
8. Store: certificate/CSR and fingerprint on ceremony/issuer_key records

Total key exposure: < 1 second.

Auditor notified: "Key generation complete, please witness"
- Auditor reviews: fingerprint, algorithm, share count, certificate/CSR details
- Auditor clicks "I Witness Key Generation"
- `CeremonyAttestation` record created for phase "key_generation"

**Phase 4: COMPLETION**

Auditor notified: "Please provide final witness"
- Auditor reviews: full ceremony log, all participants, all attestations, certificate/CSR
- Auditor clicks "I Witness Completion"
- `CeremonyAttestation` record created for phase "completion"

Status transitions to: **"completed"**

For root CA: `IssuerKey` status → "active" (certificate activated)
For sub-CA: `IssuerKey` remains "pending" (awaiting parent CA cert upload)

**FAILED path:**

If the time window expires before all participants have acted:
- Status → "failed"
- All custodian passwords wiped from ETS
- Pending share records cleaned up
- Notification sent to all participants + ca_admin
- Audit log entry: "ceremony_failed", reason: "window_expired"

---

## 3. Database Changes

### Modify `key_ceremonies` table

New columns:
- `auditor_user_id` (binary_id) — assigned auditor
- `time_window_hours` (integer, default 24) — deadline for participants

Existing column used: `window_expires_at` (utc_datetime) — computed at initiation.

New statuses: `"initiated"`, `"preparing"`, `"generating"`, `"completed"`, `"failed"`

### Modify `threshold_shares` table

New columns:
- `key_label` (string, nullable) — custodian-chosen label
- `status` (string, default "pending") — "pending" or "accepted"
- `accepted_at` (utc_datetime, nullable) — when custodian submitted

Existing flow change: shares are created as "pending" placeholders at initiation (with custodian assignment but no encrypted data). Updated to "accepted" with encrypted_share when custodian submits their password.

### New `ceremony_attestations` table

| Column | Type | Purpose |
|--------|------|---------|
| `id` | binary_id (UUIDv7) | PK |
| `ceremony_id` | FK → key_ceremonies | Which ceremony |
| `auditor_user_id` | binary_id | Who attested |
| `phase` | string | "preparation", "key_generation", "completion" |
| `attested_at` | utc_datetime | When |
| `details` | map | Snapshot of what was witnessed |

---

## 4. Custodian Password Storage (ETS)

Custodian passwords are held in ETS during the preparation phase, never written to DB or disk.

- Table: `:ceremony_custodian_passwords` (owned by a GenServer)
- Key: `{ceremony_id, user_id}`
- Value: password encrypted with a per-ceremony ephemeral key
- Wiped: immediately after share encryption (step 3.5 above), or on window expiry, or on app restart

This follows the same pattern as the current private key handling — sensitive material lives in memory only, for the minimum time needed.

---

## 5. Real-Time Communication

Each ceremony gets a PubSub topic: `"ceremony:<ceremony_id>"`

All three participant pages subscribe on mount. Events broadcast:

| Event | Trigger | Who sees it |
|-------|---------|-------------|
| `custodian_ready` | Key manager accepts share | All participants |
| `witness_attested` | Auditor witnesses a phase | All participants |
| `phase_changed` | Status transition | All participants |
| `ceremony_failed` | Window expired | All participants |

Each page shows a live activity log: timestamped entries of who did what.

---

## 6. Notifications

| Event | Recipients | Content |
|-------|-----------|---------|
| Ceremony initiated | All participants | "Assigned to Ceremony X. Complete within Y hours." |
| Custodian accepted | ca_admin | "Alice accepted share (2/3 ready)" |
| All custodians ready | auditor | "All custodians ready. Please witness preparation." |
| Auditor witnessed step | ca_admin | "Auditor witnessed preparation" |
| Ceremony completed | All participants | "Ceremony X completed successfully" |
| 1 hour warning | Participants who haven't acted | "Ceremony X expires in 1 hour" |
| Window expired | All participants + ca_admin | "Ceremony X failed: deadline expired" |

Sent async via existing `Mailer` + `EmailTemplates` infrastructure using `Task.Supervisor`.

---

## 7. Time Window Enforcement

- Default: 24 hours, configurable 1-168 hours at initiation
- `CeremonyWatchdog` GenServer checks every minute for expired ceremonies
- On expiry: status → "failed", ETS passwords wiped, notifications sent, audit logged
- The `window_expires_at` column already exists on `key_ceremonies`

---

## 8. Page Details

### ca_admin — `/ceremony` (modified)

**Initiation form adds:**
- Key manager multi-select (from CA instance users with key_manager role)
- Auditor select (from CA instance users with auditor role)
- Time window selector (hours)

**After initiation — progress dashboard:**
- Ceremony details (algorithm, threshold, cert type)
- Participant status table: name, role, status (pending/ready/witnessed), timestamp
- Time remaining countdown
- Live activity log
- Cancel button (fails the ceremony, wipes everything)

### key_manager — `/ceremony/custodian` (new)

**My Ceremonies list:**
- Shows ceremonies where this user is assigned as custodian
- Status badge: pending action / accepted / completed / failed

**Accept Share form:**
- Ceremony summary (algorithm, threshold, cert type, time remaining)
- Key Label input (required, user-chosen)
- Password input + confirmation (required, min 8 chars)
- Submit button
- After acceptance: confirmation message, live log of ceremony progress

### auditor — `/ceremony/witness` (new)

**My Ceremonies list:**
- Shows ceremonies where this user is assigned as auditor
- Status badge: awaiting witness / witnessed / completed / failed

**Witness view:**
- Full ceremony log (all events, timestamped)
- Current phase needing attestation
- Phase details to review (participant list, fingerprint, certificate, etc.)
- "I Witness This Phase" button (requires password re-entry)
- After all phases witnessed: ceremony marked fully attested

---

## 9. RBAC Changes

Update `auth_hook.ex` role_pages:

| Role | New access |
|------|-----------|
| ca_admin | `/ceremony` (already has), `/ceremony/custodian` (no — admin doesn't accept shares) |
| key_manager | `/ceremony/custodian` (new — replaces direct ceremony access) |
| auditor | `/ceremony/witness` (new) |

Key managers lose access to `/ceremony` (the admin page). They only see `/ceremony/custodian`.

---

## 10. What's NOT In Scope

- **Multi-auditor quorum** — One auditor per ceremony. Multi-auditor is future work.
- **Video/photo evidence** — Physical ceremony documentation is out of scope.
- **Hardware token authentication** — Auditor/custodian auth uses existing session + password re-entry. HSM-backed auth is future.
- **Ceremony templates** — No saved configurations. Each ceremony is configured from scratch.
- **Async ceremony GenServer rewrite** — The existing `AsyncCeremony` GenServer is not modified. The new flow uses `SyncCeremony` backend with async participant collection on the portal side.
