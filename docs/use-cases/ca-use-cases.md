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

---

## UC-CA-00C: First-Run Bootstrap with Credentials (Beta.2)

**Actor:** First user (becomes CA Admin)
**Precondition:** Tenant database created (via Platform Portal), no users exist, service running
**Trigger:** Navigate to `/setup`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/setup` | Setup form displayed with title "CA Portal Setup" |
| 2 | Enter name, login (username), password, org name | Form populated |
| 3 | Click "Create Admin Account" | Bootstrap process begins |
| 4 | System creates CA Admin user with password hash (Argon2) | User record created with role `ca_admin` |
| 5 | System generates signing keypair (algorithm per tenant config, e.g., ML-DSA-65) | Signing public key stored plain |
| 6 | System encrypts signing private key with password-derived key (PBKDF2 + HKDF) | Encrypted private key stored |
| 7 | System generates KEM keypair (e.g., ML-KEM-768) | KEM public key stored plain |
| 8 | System encrypts KEM private key with password-derived key | Encrypted private key stored |
| 9 | System self-certifies admin's public keys (no higher authority) | Certificates created |
| 10 | System creates Keypair ACL credential (signing + KEM keypairs, random password) | ACL random password encrypted with admin's KEM public key |
| 11 | System grants admin activation rights on Keypair ACL | Grant record in `keypair_grants` |
| 12 | System creates 4 bootstrap keypairs: `:root`, `:sub_root`, `:strap_ca_remote_service_host_signing_key`, `:strap_ca_remote_service_host_cipher_key` | All random passwords encrypted with admin's KEM public key |
| 13 | Tenant status updated to "active" | Transition recorded |
| 14 | Redirected to `/login` with flash "Admin account created. Please sign in." | Success |

**Error Cases:**
- Password too short (< 8 chars) → validation error
- Username too short (< 3 chars) → validation error
- Keypair generation failure → error with full rollback (no partial state)
- Setup page visited after bootstrap → redirected to `/login` with "System already configured."

---

## UC-CA-01A: Login with Credentials (Beta.2)

**Actor:** CA Admin / Key Manager / Auditor
**Precondition:** User exists with credentials configured (signing + KEM keypairs)
**Trigger:** Navigate to `/login`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/login` | Login form with username and password fields |
| 2 | Enter username | Field populated |
| 3 | Enter password | Field populated |
| 4 | Click "Login" | Authentication begins |
| 5 | System verifies password hash (Argon2) | Fast check passes |
| 6 | System derives session_key from password (HKDF) | Session key derived |
| 7 | System decrypts signing private key with session_key | Proves key ownership (decrypt test) |
| 8 | session_key stored in encrypted session cookie | Cookie set |
| 9 | Redirected to Dashboard (`/`) | User identity in nav bar |

**Error Cases:**
- Wrong password → "Invalid credentials" (Argon2 check fails)
- Correct password but corrupt signing key → "Credential error" (decrypt test fails)
- User status = "suspended" → "Account suspended"
- User has no credentials configured → falls back to password-only login (backward compat)

---

## UC-CA-03A: Create User with Credentials (Beta.2)

**Actor:** CA Admin
**Precondition:** Logged in as `ca_admin` with active session_key
**Trigger:** Navigate to `/users`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/users` | User list table and create form displayed |
| 2 | Enter username | Username field populated |
| 3 | Enter display name | Name field populated |
| 4 | Select role (e.g., `key_manager`) | Role dropdown set |
| 5 | Enter password for new user | Password field populated |
| 6 | Click "Create User" | User creation with credential generation begins |
| 7 | System generates signing keypair (per tenant algorithm config) | Signing keypair created |
| 8 | System generates KEM keypair | KEM keypair created |
| 9 | System encrypts both private keys with new user's password-derived key (PBKDF2) | Private keys encrypted per-user |
| 10 | Admin signs new user's public keys (attestation via admin's signing key) | Certificates created for new user |
| 11 | User appears in table | Shows username, display name, role, active status |
| 12 | User row shows "Credentials: configured" badge | Both signing and KEM keys present |

**Error Cases:**
- Duplicate username → changeset error displayed
- Password too short → "Password must be at least 8 characters"
- Admin session_key expired/invalid → "Session expired, please re-login"
- Keypair generation failure → error with rollback

---

## UC-CA-34: View User Credentials

**Actor:** CA Admin
**Precondition:** Users exist with various credential states
**Trigger:** Navigate to `/users`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/users` | User list table displayed |
| 2 | View user row for user with full credentials | "Signing: configured" and "KEM: configured" badges shown |
| 3 | View user row for user without credentials (legacy) | "Signing: not set" and "KEM: not set" badges shown |
| 4 | View user row for user with partial credentials | Appropriate badge per key type |

---

## UC-CA-35: Key Ceremony with Multi-Manager + Auditor (Beta.2)

**Actor:** Key Managers (multiple), Auditor
**Precondition:** Multiple Key Managers exist (policy-driven, e.g., 2 required), Auditor exists, keystore configured
**Trigger:** Key Managers and Auditor initiate ceremony

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Key Manager 1 logs in with credentials | Authenticated session with session_key |
| 2 | Key Manager 2 logs in with credentials | Second authenticated session |
| 3 | Auditor logs in with credentials | Auditor session active |
| 4 | Key Manager starts ceremony with authorized session list | System verifies all sessions and roles |
| 5 | System returns ceremony Process ID (PID) | GenServer process started, ceremony status = "setup" |
| **Phase: Key Generation** | | |
| 6 | Key Manager: `KeyCeremonyManager.generate_keypair(pid, keyspec)` | Keypair generated, encrypted with random password |
| 7 | Keypair status set to "pending" | Status recorded |
| **Phase: Certificate Binding** | | |
| 8a | (Root) `KeyCeremonyManager.gen_self_sign_cert(pid, subject, profile)` | Self-signed certificate created, keypair status → "active" |
| 8b | (Sub) `KeyCeremonyManager.gen_csr(pid, subject)` | CSR generated, keypair stays "pending" |
| **Phase: Custodian Assignment** | | |
| 9 | Key Manager: `assign_custodians(pid, custodians, activation_policy)` | Random password split per activation policy |
| 10 | Each custodian provides their password | Encrypted shares returned to custodians |
| 11 | Shares NOT stored in database | Only custodians hold shares |
| **Phase: Finalization** | | |
| 12 | Auditor: `KeyCeremonyManager.finalize(pid, auditor_session)` | Audit trail signed by Auditor's signing key |
| 13 | Signed audit trail returned for safekeeping | Auditor receives signed audit record |
| 14 | Ceremony marked complete | Status = "completed" |

**Error Cases:**
- Insufficient Key Managers for policy → `{:error, :insufficient_managers}`
- No Auditor present → `{:error, :auditor_required}`
- Session expired mid-ceremony → `{:error, :session_expired}`
- Auditor refuses to finalize → ceremony stays in "pending_finalization" state

---

## UC-CA-36: Keypair ACL Activation

**Actor:** CA Admin
**Precondition:** Keypair ACL initialized (via bootstrap), admin has KEM credentials
**Trigger:** Admin needs to activate a keypair or grant access

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Admin's session_key decrypts admin's KEM private key | KEM private key available |
| 2 | Admin's KEM key decrypts Keypair ACL's random password | ACL password recovered |
| 3 | ACL password activates Keypair ACL's KEM private key | ACL KEM key available |
| 4 | ACL KEM key decrypts target keypair's random password | Keypair password recovered |
| 5 | Keypair password activates target keypair's signing private key | Keypair ready for use |

**Error Cases:**
- Admin KEM key decryption fails → `{:error, :credential_decryption_failed}`
- ACL password decryption fails → `{:error, :acl_activation_failed}`
- Target keypair not found → `{:error, :keypair_not_found}`
- Admin not authorized on ACL → `{:error, :not_authorized}`

---

## UC-CA-37: Key Vault — Register Keypair with Protection Mode

**Actor:** Key Manager (via ceremony or API)
**Precondition:** Key Vault initialized, Keypair ACL active
**Trigger:** Keypair generated during ceremony or operational key creation

### Mode: `credential_own` (Operational/Leaf Issuer Keys)

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Generate keypair | Public + private key pair |
| 2 | Generate random password | Random password created |
| 3 | Encrypt private key with random password | Encrypted key stored in keystore |
| 4 | Encrypt random password with Keypair ACL's KEM public key | Password protected by ACL |
| 5 | Register keypair in Key Vault | Keypair record with protection_mode = "credential_own" |

### Mode: `split_auth_token` (Root/Sub-Root Keys in HSM)

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Generate keypair | Public + private key pair |
| 2 | Generate random password, encrypt private key | Encrypted key stored |
| 3 | Split random password via Shamir (threshold=required, shares=N) | Password shares created |
| 4 | Each custodian provides their password | Share encrypted per-custodian |
| 5 | Encrypted shares returned to custodians | Shares NOT stored in DB |
| 6 | Register keypair in Key Vault | protection_mode = "split_auth_token" |

### Mode: `split_key` (Software-Only Root/Sub-Root Keys)

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Generate keypair | Public + private key pair |
| 2 | Split PRIVATE KEY itself via Shamir (threshold=required, shares=N) | Key shares created |
| 3 | Each custodian provides their password | Key share encrypted per-custodian |
| 4 | Encrypted key shares returned to custodians | Shares NOT stored in DB |
| 5 | Private key wiped from memory | Key only exists as shares |
| 6 | Register keypair in Key Vault | protection_mode = "split_key" |

---

## UC-CA-38: Grant Keypair Access

**Actor:** CA Admin
**Precondition:** Keypair ACL active, target keypair registered, target user has credentials
**Trigger:** Admin grants a user access to a specific keypair

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Admin activates Keypair ACL (UC-CA-36) | ACL signing key available |
| 2 | ACL signing key constructs grant envelope: `{keypair_id, allowed_credential_id, granted_at}` | Envelope assembled |
| 3 | ACL signing key signs the grant envelope | Cryptographic signature created |
| 4 | Signed grant stored in `keypair_grants` table | Grant record persisted |
| 5 | Verify grant is valid | Signature verification passes against ACL public key |

**Error Cases:**
- Target user credential not found → `{:error, :credential_not_found}`
- Target keypair not found → `{:error, :keypair_not_found}`
- ACL not activated → `{:error, :acl_not_active}`
- Duplicate grant → `{:error, :grant_already_exists}`

---

## UC-CA-39: Start Key Ceremony via API

**Actor:** Key Manager
**Precondition:** CA instance running, multiple Key Managers exist (policy-driven), valid API authentication
**Trigger:** POST `/api/v1/ceremonies/start`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/api/v1/ceremonies/start` with body `{sessions: [{user_id, role, username}, ...], ca_instance_id}` | Request accepted |
| 2 | System verifies all sessions have valid roles (at least one `key_manager`) | Role check passes |
| 3 | System starts KeyCeremonyManager GenServer process | Process started |
| 4 | System generates ceremony_id (UUID) and registers PID | Ceremony registered |
| 5 | Response: 201 with `{ceremony_id: "<uuid>"}` | UUID returned |

**Error Cases:**
- Insufficient Key Managers for policy → `{:error, :insufficient_managers}`
- Invalid session roles → 422 error
- CA instance not found → 422 error

---

## UC-CA-40: Generate Keypair in Ceremony

**Actor:** Key Manager
**Precondition:** Ceremony started (UC-CA-39), ceremony GenServer running
**Trigger:** POST `/api/v1/ceremonies/:id/generate-keypair`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/api/v1/ceremonies/:id/generate-keypair` with body `{algorithm, protection_mode, threshold_k, threshold_n}` | Request accepted |
| 2 | System validates protection_mode is one of: `credential_own`, `split_auth_token`, `split_key` | Validation passes |
| 3 | System calls `KeyCeremonyManager.generate_keypair(pid, algorithm, protection_mode, opts)` | Keypair generated |
| 4 | Keypair status set to "pending" | Status recorded |
| 5 | Response: 200 with `{keypair_id, algorithm, public_key (base64)}` | Keypair data returned |

**Error Cases:**
- Ceremony not found → 404 `ceremony_not_found`
- Invalid protection_mode → 422 `invalid_protection_mode`
- Keypair generation failure → 422 error

---

## UC-CA-41: Self-Sign Certificate in Ceremony

**Actor:** Key Manager
**Precondition:** Keypair generated in ceremony (UC-CA-40)
**Trigger:** POST `/api/v1/ceremonies/:id/self-sign`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/api/v1/ceremonies/:id/self-sign` with body `{subject_info, cert_profile}` | Request accepted |
| 2 | System calls `KeyCeremonyManager.gen_self_sign_cert(pid, subject_info, cert_profile)` | Self-signed root certificate generated |
| 3 | Keypair status transitions to "active" | Status updated |
| 4 | Response: 200 with `{certificate_pem}` | PEM-encoded certificate returned |

**Error Cases:**
- Ceremony not found → 404 `ceremony_not_found`
- No keypair generated yet → 422 error
- Invalid subject_info → 422 error

---

## UC-CA-42: Generate CSR in Ceremony

**Actor:** Key Manager
**Precondition:** Keypair generated in ceremony (UC-CA-40)
**Trigger:** POST `/api/v1/ceremonies/:id/csr`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/api/v1/ceremonies/:id/csr` with body `{subject_info}` | Request accepted |
| 2 | System calls `KeyCeremonyManager.gen_csr(pid, subject_info)` | CSR generated for sub-CA issuer |
| 3 | Keypair status remains "pending" (awaits external CA signing) | Status unchanged |
| 4 | Response: 200 with `{csr_pem}` | PEM-encoded CSR returned |

**Error Cases:**
- Ceremony not found → 404 `ceremony_not_found`
- No keypair generated yet → 422 error
- Invalid subject_info → 422 error

---

## UC-CA-43: Assign Custodians in Ceremony

**Actor:** Key Manager
**Precondition:** Keypair generated in ceremony (UC-CA-40)
**Trigger:** POST `/api/v1/ceremonies/:id/assign-custodians`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/api/v1/ceremonies/:id/assign-custodians` with body `{custodians: [{user_id, password}, ...], threshold_k}` | Request accepted |
| 2 | System splits keypair random password into shares (Shamir threshold scheme) | Shares created |
| 3 | Each share encrypted with custodian's provided password | Per-custodian encryption |
| 4 | Encrypted shares returned to custodians (NOT stored in DB) | Shares distributed |
| 5 | Response: 200 with `{status: "custodians_assigned"}` | Assignment confirmed |

**Error Cases:**
- Ceremony not found → 404 `ceremony_not_found`
- Wrong custodian count (< threshold_k) → 422 error
- No keypair generated yet → 422 error

---

## UC-CA-44: Finalize Ceremony (Auditor)

**Actor:** Auditor
**Precondition:** Ceremony phases complete (keypair generated, certificate bound, custodians assigned)
**Trigger:** POST `/api/v1/ceremonies/:id/finalize`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/api/v1/ceremonies/:id/finalize` with body `{auditor_session: {user_id, role, username}}` | Request accepted |
| 2 | System verifies auditor has "auditor" role | Role check passes |
| 3 | System calls `KeyCeremonyManager.finalize(pid, auditor_session)` | Audit trail signed by Auditor |
| 4 | Signed audit trail returned for safekeeping | Audit record created |
| 5 | Ceremony marked complete | Status = "finalized" |
| 6 | GenServer process stops | PID unregistered |
| 7 | Response: 200 with `{status: "finalized", audit_trail_count}` | Finalization confirmed |

**Error Cases:**
- Ceremony not found → 404 `ceremony_not_found`
- User does not have "auditor" role → 422 error
- Ceremony not in finalizable state → 422 error

---

## UC-CA-45: Get Ceremony Status

**Actor:** Key Manager / Auditor
**Precondition:** Ceremony started (UC-CA-39), GenServer running
**Trigger:** GET `/api/v1/ceremonies/:id/status`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | GET `/api/v1/ceremonies/:id/status` | Request accepted |
| 2 | System calls `KeyCeremonyManager.get_status(pid)` | Status retrieved from GenServer state |
| 3 | Response: 200 with `{phase, ca_instance_id, keypair_id, protection_mode, audit_trail_count}` | Current ceremony state returned |

**Error Cases:**
- Ceremony not found (invalid ID or GenServer stopped) → 404 `ceremony_not_found`

---

## UC-CA-46: Register Managed Keypair

**Actor:** Key Manager
**Precondition:** Key Vault initialized, valid API authentication
**Trigger:** POST `/api/v1/keypairs/register`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/api/v1/keypairs/register` with body `{name, algorithm, protection_mode, ca_instance_id}` | Request accepted |
| 2 | For `credential_own` mode: body includes `acl_kem_public_key` (base64) | ACL key provided |
| 3 | For `split_auth_token` / `split_key` modes: body includes `threshold_k`, `threshold_n` | Threshold params provided |
| 4 | System calls appropriate `KeyVault.register_keypair*` function | Keypair generated and registered |
| 5 | Response: 201 with keypair record `{id, name, algorithm, protection_mode, status, public_key}` | Keypair returned |
| 6 | For split modes: `shares_generated: true` flag included | Shares created (distributed out-of-band) |

**Error Cases:**
- Invalid base64 for acl_kem_public_key → 422 `invalid_base64`
- Validation error (missing name, algorithm) → 422 `validation_error`
- Duplicate name within ca_instance → 422 error

---

## UC-CA-47: Grant Keypair Access

**Actor:** CA Admin / Key Manager
**Precondition:** Keypair registered (UC-CA-46), target credential exists
**Trigger:** POST `/api/v1/keypairs/:id/grant`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/api/v1/keypairs/:id/grant` with body `{credential_id, acl_signing_key (base64), acl_signing_algo}` | Request accepted |
| 2 | System calls `KeyVault.grant_access(keypair_id, credential_id, acl_signing_key, acl_signing_algo)` | Signed grant envelope created |
| 3 | Grant record stored in `keypair_grants` table | Grant persisted |
| 4 | Response: 201 with `{id, managed_keypair_id, credential_id}` | Grant returned |

**Error Cases:**
- Invalid base64 for acl_signing_key → 422 `invalid_base64`
- Keypair not found → 422 error
- Credential not found → 422 error
- Duplicate grant → 422 error

---

## UC-CA-48: Activate Keypair

**Actor:** Key Manager / Custodians
**Precondition:** Keypair registered, grant exists (for credential_own) or shares available (for split modes)
**Trigger:** POST `/api/v1/keypairs/:id/activate`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1a | For `credential_own`: POST with `{protection_mode: "credential_own", acl_kem_private_key (base64)}` | KEM key provided |
| 1b | For `split_auth_token` / `split_key`: POST with `{protection_mode: "split_auth_token", shares: [...] (base64)}` | Shares provided |
| 2 | System calls appropriate `KeyVault.activate_*` function | Private key recovered |
| 3 | Response: 200 with `{status: "activated"}` | Activation confirmed |
| 4 | Private key NOT returned over HTTP | Security enforced |

**Error Cases:**
- Invalid base64 for shares or KEM key → 422 `invalid_base64`
- Insufficient shares for threshold → 422 error
- Invalid KEM private key → 422 error
- Keypair not found → 422 error

---

## UC-CA-49: Revoke Keypair Grant

**Actor:** CA Admin
**Precondition:** Grant exists for keypair (UC-CA-47)
**Trigger:** POST `/api/v1/keypairs/:id/revoke-grant`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/api/v1/keypairs/:id/revoke-grant` with body `{credential_id}` | Request accepted |
| 2 | System calls `KeyVault.revoke_grant(keypair_id, credential_id)` | Grant soft-revoked |
| 3 | Response: 200 with `{status: "revoked"}` | Revocation confirmed |

**Error Cases:**
- Grant not found → 404 `grant_not_found`
- Keypair not found → 422 error

---

## UC-CA-50: List Managed Keypairs

**Actor:** Key Manager / CA Admin
**Precondition:** Keypairs registered for ca_instance
**Trigger:** GET `/api/v1/keypairs?ca_instance_id=...`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | GET `/api/v1/keypairs?ca_instance_id=<id>` | Request accepted |
| 2 | System calls `KeyVault.list_keypairs(ca_instance_id)` | Keypairs retrieved |
| 3 | Response: 200 with `{data: [{id, name, algorithm, protection_mode, status, public_key}, ...]}` | List returned |
| 4 | No private keys included in response | Security enforced |

---

## UC-CA-51: Get Managed Keypair

**Actor:** Key Manager / CA Admin
**Precondition:** Keypair exists
**Trigger:** GET `/api/v1/keypairs/:id`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | GET `/api/v1/keypairs/:id` | Request accepted |
| 2 | System calls `KeyVault.get_keypair(keypair_id)` | Keypair retrieved |
| 3 | Response: 200 with keypair details `{id, name, algorithm, protection_mode, status, public_key}` | Keypair returned |
| 4 | No private key included in response | Security enforced |

**Error Cases:**
- Keypair not found → 404 `not_found`
