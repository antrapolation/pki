# CA Module — Use Cases

## Actors

| Actor | Role | Description |
|-------|------|-------------|
| CA Admin | `ca_admin` | Manages users, auditors, views audit logs |
| Key Manager | `key_manager` | Manages keystores, keys, ceremonies, keypair access |
| Auditor | `auditor` | Views audit logs, participates in ceremonies |
| System | — | Automated processes (timeouts, scheduled tasks) |

---

## UC-CA-00A: Bootstrap — First-Run Setup Page

**Actor:** First user (becomes CA Admin)
**Precondition:** Clean database, no users exist, service running
**Trigger:** Navigate to `/setup`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/setup` | Setup form displayed with title "CA Portal Setup" |
| 2 | Verify form fields | Username, Display Name, Password, Confirm Password fields present |
| 3 | Enter username (min 3 chars) | Field populated |
| 4 | Enter display name (optional) | Field populated |
| 5 | Enter password (min 8 chars) | Field populated |
| 6 | Enter matching password confirmation | Field populated |
| 7 | Click "Create Admin Account" | Admin user created with role `ca_admin` |
| 8 | Verify redirect | Redirected to `/login` with flash "Admin account created. Please sign in." |

**Error Cases:**
- Password mismatch → "Passwords do not match" error displayed
- Password too short (< 8 chars) → "Password must be at least 8 characters" error displayed
- Duplicate username → changeset error displayed

---

## UC-CA-00B: Bootstrap — Setup Page Blocked After Initial Setup

**Actor:** Any user
**Precondition:** Admin user already created (UC-CA-00A completed)
**Trigger:** Navigate to `/setup`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/setup` | Redirected to `/login` |
| 2 | Verify flash message | "System already configured." |
| 3 | POST to `/setup` with valid params | Redirected to `/login` with error "System already configured." |

---

## UC-CA-01: Login to CA Portal

**Actor:** CA Admin / Key Manager / Auditor
**Precondition:** Service running, user has valid DID
**Trigger:** User navigates to `/login`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/login` | Login form displayed with DID and role fields |
| 2 | Enter DID and select role | Form populated |
| 3 | Click "Login" | Redirected to Dashboard (`/`) |
| 4 | Verify session | Session cookie set, user identity in nav bar |

**Error Cases:**
- Empty DID → validation error
- Invalid role → validation error

---

## UC-CA-02: View Dashboard

**Actor:** Any authenticated user
**Precondition:** Logged in
**Trigger:** Navigate to `/`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Page loads | Engine status card displayed |
| 2 | — | Active key count shown |
| 3 | — | Total key count shown |
| 4 | — | Recent ceremonies table populated |
| 5 | — | Quick action links to Users, Keystores, Ceremony visible |

---

## UC-CA-03: Create CA User

**Actor:** CA Admin
**Precondition:** Logged in as `ca_admin`
**Trigger:** Navigate to `/users`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/users` | User list table and create form displayed |
| 2 | Enter DID (e.g., `did:example:km-1`) | DID field populated |
| 3 | Enter display name | Name field populated |
| 4 | Select role: `key_manager` | Role dropdown set |
| 5 | Click "Create User" | New user appears in table |
| 6 | Verify user row | Shows DID, display name, role, active status |

**Error Cases:**
- Duplicate DID → changeset error displayed
- Missing required fields → validation error

---

## UC-CA-04: Filter Users by Role

**Actor:** CA Admin
**Precondition:** Multiple users exist with different roles
**Trigger:** On `/users` page

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Select "key_manager" from role filter | Only key managers shown |
| 2 | Select "auditor" from role filter | Only auditors shown |
| 3 | Select "all" from role filter | All users shown |

---

## UC-CA-05: Delete (Suspend) CA User

**Actor:** CA Admin
**Precondition:** User exists in active state
**Trigger:** On `/users` page

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Locate user in table | User row visible |
| 2 | Click "Delete" button on user row | User removed from list |
| 3 | Verify in database | User status set to "suspended" (soft delete) |

---

## UC-CA-06: Configure Software Keystore

**Actor:** Key Manager
**Precondition:** Logged in as `key_manager`
**Trigger:** Navigate to `/keystores`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/keystores` | Keystore list and config form displayed |
| 2 | Select type: "software" | Type dropdown set |
| 3 | Click "Configure" | New keystore appears in table |
| 4 | Verify keystore row | Shows type=software, status=active, provider name |

---

## UC-CA-07: Configure HSM Keystore

**Actor:** Key Manager
**Precondition:** SoftHSM2 or real HSM available
**Trigger:** Navigate to `/keystores`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Select type: "hsm" | Type dropdown set |
| 2 | Click "Configure" | New HSM keystore in table |
| 3 | Verify keystore row | Shows type=hsm, status=active |

---

## UC-CA-08: Initiate Synchronous Key Ceremony

**Actor:** Key Manager
**Precondition:** Keystore configured, at least K+1 key managers exist
**Trigger:** Navigate to `/ceremony`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/ceremony` | Ceremony form and history table displayed |
| 2 | Select algorithm: "RSA-4096" | Algorithm dropdown set |
| 3 | Select keystore from dropdown | Keystore selected |
| 4 | Enter threshold K: 2 | Min shares field set |
| 5 | Enter threshold N: 3 | Total shares field set |
| 6 | Optionally enter domain info | Textarea populated |
| 7 | Click "Initiate Ceremony" | Ceremony status displayed: "initiated" |
| 8 | Verify ceremony in history table | New ceremony row with status, algorithm, timestamps |

**Validation:**
- K must be >= 2
- K must be <= N
- Keystore must exist and be active

**Error Cases:**
- K < 2 → `{:error, :invalid_threshold}`
- K > N → `{:error, :invalid_threshold}`
- Invalid keystore → `{:error, :not_found}`

---

## UC-CA-09: Initiate Key Ceremony with PQC Algorithm

**Actor:** Key Manager
**Precondition:** Same as UC-CA-08
**Trigger:** Navigate to `/ceremony`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Select algorithm: "KAZ-SIGN-256" | PQC algorithm selected |
| 2 | Complete remaining fields as UC-CA-08 | — |
| 3 | Click "Initiate Ceremony" | Ceremony created with PQC algorithm |

**Also test with:** ML-DSA-65, ECC-P256

---

## UC-CA-10: Generate Keypair During Ceremony

**Actor:** Key Manager (via API/IEx)
**Precondition:** Ceremony initiated (UC-CA-08)
**Trigger:** Key Manager initiates keypair generation

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Call `SyncCeremony.generate_keypair(adapter, algorithm)` | Returns `{:ok, %{public_key: binary, private_key: binary}}` |
| 2 | Verify public_key is binary | Non-empty binary |
| 3 | Verify private_key is binary | Non-empty binary |
| 4 | Verify private_key is DER-encoded | Can be decoded by `:public_key.der_decode` |

---

## UC-CA-11: Distribute Threshold Shares

**Actor:** Key Manager (via API/IEx)
**Precondition:** Keypair generated (UC-CA-10), custodians identified
**Trigger:** Key Manager distributes shares

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Prepare custodian_passwords list: `[{user1_id, "pass1"}, ...]` | N custodian-password pairs |
| 2 | Call `SyncCeremony.distribute_shares(ceremony, private_key, passwords, adapter)` | Returns `{:ok, N}` |
| 3 | Verify N ThresholdShare records in DB | Each has encrypted_share, share_index, custodian_user_id |
| 4 | Verify shares are encrypted (not plaintext) | encrypted_share != private_key fragment |

**Error Cases:**
- Wrong custodian count (not equal to N) → `{:error, :wrong_custodian_count}`

---

## UC-CA-12: Complete Ceremony as Root CA

**Actor:** Key Manager (via API/IEx)
**Precondition:** Shares distributed (UC-CA-11)
**Trigger:** Key Manager completes ceremony

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Generate self-signed root certificate from private key | cert_der, cert_pem binaries |
| 2 | Call `SyncCeremony.complete_as_root(ceremony, cert_der, cert_pem)` | Returns `{:ok, ceremony}` |
| 3 | Verify ceremony status = "completed" | Status updated in DB |
| 4 | Verify issuer_key status = "active" | Key activated with certificate |
| 5 | Verify issuer_key has certificate_der and certificate_pem | Non-nil fields |

---

## UC-CA-13: Complete Ceremony as Sub-CA

**Actor:** Key Manager (via API/IEx)
**Precondition:** Shares distributed (UC-CA-11)
**Trigger:** Key Manager completes ceremony for sub-CA

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Call `SyncCeremony.complete_as_sub_ca(ceremony)` | Returns `{:ok, {ceremony, csr}}` |
| 2 | Verify ceremony status = "completed" | Status updated |
| 3 | Verify issuer_key status = "pending" | Key awaits external CA signing |
| 4 | CSR placeholder returned | Binary CSR data |

---

## UC-CA-14: Activate Key via Threshold Shares

**Actor:** Custodians (K of N)
**Precondition:** Ceremony completed, key has shares in DB
**Trigger:** Signing operation requires active key

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Custodian 1: Submit share with password | Returns `{:ok, :share_accepted}` |
| 2 | Custodian 2: Submit share with password | Returns `{:ok, :key_activated}` (threshold K=2 met) |
| 3 | Verify `KeyActivation.is_active?(issuer_key_id)` | Returns `true` |
| 4 | Verify `KeyActivation.get_active_key(issuer_key_id)` | Returns `{:ok, private_key_binary}` |

**Error Cases:**
- Wrong password → `{:error, :decryption_failed}`
- Duplicate custodian submission → `{:error, :already_submitted}`
- Share not found → `{:error, :share_not_found}`

---

## UC-CA-15: Key Auto-Deactivation on Timeout

**Actor:** System
**Precondition:** Key activated (UC-CA-14)
**Trigger:** Timeout expires (default: 1 hour)

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Wait for timeout to expire | — |
| 2 | Verify `KeyActivation.is_active?(issuer_key_id)` | Returns `false` |
| 3 | Attempt to sign certificate | Returns `{:error, :key_not_active}` |

---

## UC-CA-16: Explicit Key Deactivation

**Actor:** Key Manager
**Precondition:** Key activated
**Trigger:** Key Manager deactivates key

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Call `KeyActivation.deactivate(issuer_key_id)` | Returns `:ok` |
| 2 | Verify key is no longer active | `is_active?` returns `false` |
| 3 | Attempt to sign | Returns `{:error, :key_not_active}` |

---

## UC-CA-17: Sign Certificate with Active Key

**Actor:** System (triggered by RA)
**Precondition:** Issuer key active, CSR data available
**Trigger:** RA forwards approved CSR

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Call `CertificateSigning.sign_certificate(issuer_key_id, csr_pem, profile)` | Returns `{:ok, issued_cert}` |
| 2 | Verify issued_cert.serial_number | Non-nil hex string |
| 3 | Verify issued_cert.cert_der | Valid DER binary |
| 4 | Verify issued_cert.cert_pem | Valid PEM string starting with `-----BEGIN CERTIFICATE-----` |
| 5 | Verify issued_cert.subject_dn | Matches CSR or profile subject |
| 6 | Verify issued_cert.status = "active" | Active status |
| 7 | Verify issued_cert.not_before <= now <= not_after | Valid date range |

---

## UC-CA-18: Sign Certificate with Real CSR

**Actor:** System
**Precondition:** Same as UC-CA-17, but with a real PEM-encoded CSR
**Trigger:** CSR submitted with valid PEM

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Generate a real CSR using `X509.CSR.new(key, subject)` | Valid CSR PEM |
| 2 | Sign certificate with real CSR | Certificate issued |
| 3 | Verify subject_dn extracted from CSR | Matches CSR subject |
| 4 | Verify cert_der is a valid X.509 DER | Decodable by `:public_key.der_decode` |

---

## UC-CA-19: Revoke Certificate

**Actor:** CA Admin / Key Manager
**Precondition:** Certificate issued and active
**Trigger:** Revocation request

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Call `CertificateSigning.revoke_certificate(serial, "keyCompromise")` | Returns `{:ok, cert}` |
| 2 | Verify cert.status = "revoked" | Status updated |
| 3 | Verify cert.revoked_at | Non-nil timestamp |
| 4 | Verify cert.revocation_reason = "keyCompromise" | Reason stored |

**Error Cases:**
- Non-existent serial → `{:error, :not_found}`

---

## UC-CA-20: List Certificates with Filters

**Actor:** CA Admin
**Precondition:** Multiple certificates issued

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Call `list_certificates(issuer_key_id)` | All certs for key returned |
| 2 | Call `list_certificates(issuer_key_id, status: "active")` | Only active certs |
| 3 | Call `list_certificates(issuer_key_id, status: "revoked")` | Only revoked certs |

---

## UC-CA-21: Issuer Key Status Transitions

**Actor:** Key Manager
**Precondition:** Issuer key exists

| Step | Transition | Expected Result |
|------|-----------|-----------------|
| 1 | pending → active (via `activate_by_certificate`) | Success |
| 2 | active → suspended (via `update_status`) | Success |
| 3 | suspended → active (via `update_status`) | Success |
| 4 | active → archived (via `update_status`) | Success (terminal) |
| 5 | pending → archived (via `update_status`) | Success (terminal) |
| 6 | archived → active (via `update_status`) | Error: invalid transition |
| 7 | pending → suspended (via `update_status`) | Error: invalid transition |

---

## UC-CA-22: View Audit Log

**Actor:** CA Admin / Auditor
**Precondition:** Audit events exist
**Trigger:** Navigate to `/audit-log`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/audit-log` | Audit events table displayed |
| 2 | Filter by action: "ceremony_initiated" | Only ceremony events shown |
| 3 | Filter by actor DID | Only events by that actor |
| 4 | Filter by date range | Events within range |
| 5 | Clear filters | All events shown |

---

## UC-CA-23: Async Key Ceremony with Timeout

**Actor:** Custodians
**Precondition:** Async ceremony started with short window
**Trigger:** Ceremony window expires before all shares collected

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Start async ceremony with 2-second window | Process started |
| 2 | Submit 1 of 3 shares | Returns `{:ok, :share_accepted}` |
| 3 | Wait for window to expire | Process exits |
| 4 | Verify ceremony status = "failed" | Timeout failure recorded |
| 5 | Verify key material wiped | No key in memory |

---

## UC-CA-24: Async Key Ceremony Success

**Actor:** Custodians
**Precondition:** Async ceremony started
**Trigger:** All N shares submitted within window

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Start async ceremony | Process started, ceremony status = "in_progress" |
| 2 | Custodian 1 submits share | `{:ok, :share_accepted}` |
| 3 | Custodian 2 submits share | `{:ok, :share_accepted}` |
| 4 | Custodian 3 submits share (N=3) | `{:ok, :ceremony_complete}` |
| 5 | Verify all shares stored in DB | 3 ThresholdShare records |
| 6 | Verify ceremony status shows complete | `get_status` returns complete=true |

---

## UC-CA-25: Authorization Enforcement

**Actor:** Various roles
**Precondition:** Users with different roles exist

| Step | Role | Permission | Expected |
|------|------|-----------|----------|
| 1 | ca_admin | manage_ca_admins | Authorized |
| 2 | ca_admin | manage_keystores | Unauthorized |
| 3 | key_manager | manage_keystores | Authorized |
| 4 | key_manager | manage_keys | Authorized |
| 5 | auditor | view_audit_log | Authorized |
| 6 | auditor | manage_keystores | Unauthorized |
| 7 | suspended user | any permission | Unauthorized |

---

## UC-CA-26: Logout

**Actor:** Any authenticated user
**Trigger:** Click logout

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Click "Logout" | DELETE `/logout` called |
| 2 | — | Session cleared |
| 3 | — | Redirected to `/login` |
| 4 | Navigate to `/` | Redirected to `/login` (auth required) |

---

## UC-CA-27: HSM Keystore — Generate Key on SoftHSM2

**Actor:** Key Manager
**Precondition:** HSM keystore configured (UC-CA-07), SoftHSM2 container running
**Trigger:** Key ceremony with HSM keystore

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Verify SoftHSM2 is healthy | `softhsm2-util --show-slots` shows PkiCA token |
| 2 | Verify CA engine has HSM env vars | `PKCS11_LIB_PATH`, `HSM_PIN`, `HSM_SLOT` set |
| 3 | Verify library accessible from CA engine | `/hsm/lib/libsofthsm2.so` exists |
| 4 | Verify token directory accessible | `/hsm/tokens/` contains token files |
| 5 | Initiate ceremony with HSM keystore | Ceremony created referencing HSM keystore |
| 6 | Generate keypair via PKCS#11 | Key generated on HSM, handle returned |
| 7 | List objects on HSM | New key visible via `pkcs11-tool --list-objects` |

---

## UC-CA-28: HSM Keystore — Sign with HSM Key

**Actor:** System
**Precondition:** HSM key generated (UC-CA-27), key activated
**Trigger:** Certificate signing request

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Activate key via threshold shares | Key activated |
| 2 | Sign certificate with HSM-backed key | Signing operation delegated to PKCS#11 |
| 3 | Verify certificate is valid X.509 | DER-decodable, valid signature |
| 4 | Verify HSM key not exported | Key material stays on HSM |

---

## UC-CA-29: Ceremony Threshold Validation — Edge Cases

**Actor:** Key Manager
**Precondition:** Keystore exists
**Trigger:** Initiate ceremony with invalid thresholds

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Initiate with K=1, N=3 | `{:error, :invalid_threshold}` (K must be >= 2) |
| 2 | Initiate with K=4, N=3 | `{:error, :invalid_threshold}` (K must be <= N) |
| 3 | Initiate with K=0, N=0 | `{:error, :invalid_threshold}` |
| 4 | Initiate with K=2, N=2 | Success (minimum valid threshold) |
| 5 | Initiate with K=5, N=5 | Success (K equals N) |

---

## UC-CA-30: Key Activation — Error Cases

**Actor:** Custodians
**Precondition:** Ceremony completed with shares distributed

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Submit share with wrong password | `{:error, :decryption_failed}` |
| 2 | Submit share for non-existent issuer_key_id | `{:error, :share_not_found}` |
| 3 | Same custodian submits twice | `{:error, :already_submitted}` |
| 4 | Submit share for custodian not assigned to this key | `{:error, :share_not_found}` |
| 5 | Get active key for non-activated key | `{:error, :not_active}` |
| 6 | Deactivate already-deactivated key | `{:error, :not_active}` |

---

## UC-CA-31: Sign Certificate — Error Cases

**Actor:** System
**Precondition:** Various error conditions

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Sign with non-existent issuer_key_id | `{:error, :issuer_key_not_found}` |
| 2 | Sign when key not activated | `{:error, :key_not_active}` |
| 3 | Sign with unsupported algorithm on issuer key | `{:error, {:unsupported_algorithm, _}}` |
| 4 | Revoke non-existent serial | `{:error, :not_found}` |
| 5 | Get non-existent certificate | `{:error, :not_found}` |
| 6 | List certs for non-existent key | Empty list `[]` |

---

## UC-CA-32: Keystore Provider Module Lookup

**Actor:** System
**Precondition:** Keystore types defined

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | `get_provider_module("software")` | `{:ok, "StrapSoftPrivKeyStoreProvider"}` |
| 2 | `get_provider_module("hsm")` | `{:ok, "StrapSofthsmPrivKeyStoreProvider"}` |
| 3 | `get_provider_module("unknown")` | `{:error, :unknown_provider}` |

---

## UC-CA-33: Issuer Key — Invalid State Transitions (Exhaustive)

**Actor:** Key Manager
**Precondition:** Keys in various states

| Step | From | To | Expected |
|------|------|-----|----------|
| 1 | pending | suspended | `{:error, {:invalid_transition, ...}}` |
| 2 | archived | active | `{:error, {:invalid_transition, ...}}` |
| 3 | archived | suspended | `{:error, {:invalid_transition, ...}}` |
| 4 | archived | pending | `{:error, {:invalid_transition, ...}}` |
| 5 | active | pending | `{:error, {:invalid_transition, ...}}` |
| 6 | suspended | pending | `{:error, {:invalid_transition, ...}}` |
