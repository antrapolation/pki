# Spec Amendment — Key Ceremony v1.1

**Amends**: `docs/Product.Spec-PQC.CA.System-v1.0.docx`
**Effective**: Phase E ship date (TBD)
**Status**: Approved by engineering, pending product sign-off

This amendment supersedes the **Key Ceremony**, **Issuer Key Management**, and **Private Key Store Management** sections of v1.0. All other sections of v1.0 remain in force.

## 1. Summary of changes

| Area | v1.0 | v1.1 |
|---|---|---|
| Default keystore | Software (encrypted file shares) | HSM (key never leaves) |
| Software keystore in production | Permitted | **Refused at boot** (developer/test only) |
| Key activation model | Per-operation reconstruction | **Lease-based session** (4h / 100 ops default, configurable) |
| Sub-CA key generation modes | Threshold scheme implied | **Three modes**: `threshold`, `password`, `single_custodian` |
| Single-custodian sub-CA | Allowed without warning | **Warning displayed**: "Does not meet WebTrust §6.2.2 dual-control" |
| Auditor role | Witness (passive) | **Quorum participant** (must accept invitation before keygen) |
| Ceremony transcript | Printed log, ink signatures | **Hash-chained + auditor-signed** (printed log + ink signatures preserved) |
| Custodian share | AES-256-GCM encrypted | **Encrypted AND digitally signed** (signed-share envelope) |
| Custodian artifact (HSM mode) | Password file on USB | **Smart card** (Phase E5+); SoftHSM PIN as stand-in until then |

## 2. New schema fields

### `KeyCeremony`
- `keystore_mode :: "software" | "softhsm" | "hsm"` — selected at initiation, persisted

### `IssuerKey`
- `key_role :: "root" | "issuing_sub" | "operational_sub"` — determines which key_modes are allowed
- `key_mode :: "threshold" | "password" | "single_custodian"` — root MUST be `threshold`
- `crl_strategy :: "per_interval" | "pre_signed"` — controls CRL publication semantics

### `ThresholdShare`
- `share_signature :: binary()` — system-key signature over the encrypted share (for offline custodian verification)

### `CeremonyTranscript`
- `prev_hash :: binary()`, `event_hash :: binary()` — hash chain over entries
- `auditor_signature :: binary()`, `auditor_public_key :: binary()`, `signed_at :: DateTime.t()` — auditor's attestation at ceremony close

### New struct `ActivationSession`
- Tracks lease state for each issuer key activation
- Fields: `id, issuer_key_id, status, custodians_authenticated, lease_expires_at, ops_remaining`
- Status transitions: `awaiting_custodians → active → expired | cancelled`

### New struct `PreSignedCrl`
- Holds CRLs pre-signed at ceremony close for offline-root scenarios
- Fields: `issuer_key_id, valid_from, valid_until, crl_der`

## 3. Updated flows

### 3.1 Key Ceremony — production (HSM mode, threshold key_mode)

**Pre-conditions:**
- At least one HSM keystore configured by Key Manager (else `{:error, :no_keystore}` and stop).
- Auditor user (`global_role: "auditor"`) registered in tenant.

**Flow:**

1. **Initiate** — CA admin or Key Manager opens ceremony wizard, picks: `keystore_mode = "hsm"`, `key_role = "root"`, `key_mode = "threshold"`, `(k, n)` threshold, custodian names, auditor.
2. **Auditor accept** — Ceremony moves to `awaiting_auditor_acceptance`. Auditor opens witness page, clicks "Accept and witness". Ceremony moves to `preparing`. Audit event `auditor_accepted` recorded.
3. **Custodian slot entry** — Each custodian inserts smart card (PED), enters PIN on the card's pinpad. Portal sees only "slot N: identity verified", never the PIN. (SoftHSM stand-in: PIN entered on host; documented limitation.)
4. **Keygen** — When all n slots filled, system claims ceremony status `generating`, calls `Dispatcher.authorize_session(...)`. HSM grants leased session. HSM generates keypair internally, derives per-custodian wrap-shares, writes shares to custodian smart cards via HSM-native cloning API.
5. **Self-sign or CSR** — If `root` role: HSM signs root cert internally; cert registered. If `sub-rooted-externally`: HSM produces CSR; key marked `pending`.
6. **Auto-sub-CA** (root only) — Immediately after root self-sign succeeds, system generates a sub-CA keypair and signs its cert with the still-active root lease. Both keys marked `active`.
7. **Transcript close** — Hash-chained transcript finalized. Auditor signs transcript digest with their own key (uploaded out-of-band or via QR-code-and-sign flow). Printed transcript with ink signatures preserved.
8. **Lease state** — Root key auto-offlines (existing behavior). Sub-CA key remains active in HSM for the remaining lease duration (then expires; future signings require new activation ceremony).

### 3.2 Key Ceremony — non-threshold sub-CA (password or single_custodian mode)

**Pre-conditions:**
- `key_role` MUST be `issuing_sub` or `operational_sub`. Hard-block if `root`.
- UI displays banner: *"This mode does not meet WebTrust §6.2.2 dual-control. Use only for internal/private CAs not intended for public trust stores."*
- Auditor still required as quorum participant.

**Flow:**

1. **Initiate** — Key Manager picks `key_mode = "password"` or `"single_custodian"`, sets a single password (password mode) or just provides their identity (single_custodian mode).
2. **Auditor accept** — Same as 3.1 step 2.
3. **Keygen** — No Shamir split. Single-officer authentication to HSM. HSM generates key, signs CSR or cert.
4. **Audit log enrichment** — Every cert signed by a `password` or `single_custodian` key emits a `low_assurance_signing` event with elevated severity. Cert metadata may include CPS reference noting the activation mode in the certificate's policies extension (configurable).

### 3.3 External-cert activation (sub-CA rooted to external root)

**Pre-condition:** An `IssuerKey` with `status: "pending"` and a previously-generated CSR.

**Flow:**

1. CA admin obtains the signed cert from the external CA out-of-band.
2. CA admin uploads the cert via the portal.
3. System validates: (a) cert chains to the declared external root, (b) public key matches the pending key's pub key, (c) validity dates sane, (d) signature algorithm matches.
4. On valid: cert stored; `IssuerKey.status` flipped `pending → active`; audit event `key_activated_with_external_cert` recorded.
5. On invalid: error with specific reason; key remains `pending`.

### 3.4 Lease-based activation (operational signing)

**Pre-condition:** `IssuerKey.status: "active"` and (after first ceremony) lease may be expired.

**Flow:**

1. CA admin opens activation page: "I need to sign N certs in the next 4 hours."
2. k custodians (per the key's `key_mode`) attend, insert cards, enter PINs.
3. HSM grants lease (configurable: default 4 hours / 100 operations).
4. CA admin can sign within the lease window. Each signing operation decrements `ops_remaining`.
5. Lease expires (timeout OR ops exhausted) → session closes; new activation ceremony required for further signings.

### 3.5 OCSP and CRL signing

- **OCSP**: requires active lease for the issuer key. Without lease: returns `tryLater` per RFC 6960 §2.3 (does not silently sign with a software key).
- **CRL**: two strategies via `IssuerKey.crl_strategy`:
  - `per_interval`: each scheduled publication requires active lease at that moment (high friction, suits issuing CAs with daily ceremonies).
  - `pre_signed`: at ceremony close, system pre-signs N future CRLs (e.g., one per week for the next 90 days), stores in `PreSignedCrl` table, serves at publication time. Suits offline root CAs.

## 4. Updated user role responsibilities

| Role | v1.0 responsibilities | v1.1 changes |
|---|---|---|
| **CA Admin** | Manage CA engine, user management | Initiate ceremonies, upload external certs to activate pending keys |
| **Key Manager** | Configure keystores, hold key role | Conduct activation ceremonies, hold password (in password mode) or single_custodian role |
| **RA Admin** | Manage RA admins, assign key access | (unchanged) |
| **Auditor** | View audit log, **participate in Key Ceremony** | **Required to accept ceremony invitation before keygen**; signs ceremony transcript with own key at close |

## 5. Hardware support tiers

| Tier | Hardware | Custodian artifact | WebTrust eligible |
|---|---|---|---|
| Development | Software keystore (in-process) | Password file | No (boot-refused in prod) |
| Testing / CI | SoftHSM2 | PIN (host) | No |
| Hardware validation | Nitrokey HSM 2 / YubiHSM 2 | Single PIN per token (no m-of-n) | No (no real m-of-n) |
| Production (entry) | Thales Luna PCIe / Entrust nShield Solo | PED keys / OCS cards (FIPS 140-3 L3) | Yes |
| Production (full) | 2 × Thales Luna USB HSM 7 (geo-separated) | PED keys + safe deposit boxes | Yes (commercial public CA) |

## 6. Backward compatibility

- Existing software-keystore tenants in **non-production** environments continue to work unchanged.
- Production tenants with software keystores must migrate before next release. Migration window: opt-in via `:allow_software_keystore_in_prod` config flag with deprecation warnings.
- Existing Phase D HSM-backed tenants gain the lease layer transparently (deprecated `KeyActivation.submit_share/4` shimmed; removed in a later release).

## 7. Out of v1.1 scope

- Cert renewal flow (deferred to v1.2 / Phase F).
- Configure keypair access UI (existing `keypair_access` schema; UI work, separate).
- HSM cloning ceremony for DR backup HSM (Phase E5+, hardware-blocked).
- WebTrust audit submission (post-pilot).

---

*This amendment is intentionally additive: v1.0 customer commitments are preserved, with v1.1 strengthening security defaults and clarifying the multi-tier customer model (internal PKI vs. public trust CA).*
