# End-to-End Cross-Module — Use Cases

These use cases span multiple modules and test the full system working together.

## Actors

| Actor | Description |
|-------|-------------|
| CA Admin | CA portal user (manages CA) |
| Key Manager | CA portal user (manages keys/ceremonies) |
| Custodian | Key manager participating in threshold ceremony |
| RA Admin | RA portal user (manages RA config) |
| RA Officer | RA portal user (processes CSRs) |
| External Client | REST API consumer (submits CSRs) |
| OCSP Client | Certificate status checker |

---

## UC-E2E-01: Full Certificate Issuance Flow

**Modules:** RA Engine → CA Engine → Validation
**Precondition:** CA ceremony completed, key activated, cert profile exists, API key active

| Step | Actor | Module | Action | Expected Result |
|------|-------|--------|--------|-----------------|
| 1 | External Client | RA API | POST `/api/v1/csr` with valid CSR PEM | 201, CSR created |
| 2 | System | RA Engine | Auto-validates CSR | Status → "verified" |
| 3 | RA Officer | RA Portal | Navigate to `/csrs`, view CSR detail | CSR with Approve button |
| 4 | RA Officer | RA Portal | Click "Approve" | Status → "approved" |
| 5 | System | RA Engine | `forward_to_ca(csr_id)` | Calls CA Engine |
| 6 | System | CA Engine | `sign_certificate(issuer_key_id, csr_pem, profile)` | X.509 cert signed |
| 7 | System | RA Engine | `mark_issued(csr_id, serial)` | Status → "issued" |
| 8 | OCSP Client | Validation | POST `/ocsp` with cert serial | Status = "good" |
| 9 | OCSP Client | Validation | GET `/crl` | Cert NOT in revoked list |

---

## UC-E2E-02: Full Certificate Revocation Flow

**Modules:** CA Engine → Validation
**Precondition:** Certificate issued (UC-E2E-01 completed)

| Step | Actor | Module | Action | Expected Result |
|------|-------|--------|--------|-----------------|
| 1 | OCSP Client | Validation | Query OCSP for cert | Status = "good" |
| 2 | CA Admin | CA Engine | Revoke certificate with "keyCompromise" | Cert status = "revoked" |
| 3 | System | Validation | CRL regeneration (periodic or forced) | CRL updated |
| 4 | OCSP Client | Validation | Query OCSP for same cert | Status = "revoked", reason = "keyCompromise" |
| 5 | OCSP Client | Validation | GET `/crl` | Cert in revoked_certificates list |

---

## UC-E2E-03: Key Ceremony to Certificate Signing

**Modules:** CA Portal → CA Engine → RA Engine
**Precondition:** CA instance exists, users created, keystore configured

| Step | Actor | Module | Action | Expected Result |
|------|-------|--------|--------|-----------------|
| 1 | Key Manager | CA Portal | Navigate to `/ceremony` | Ceremony form |
| 2 | Key Manager | CA Portal | Initiate ceremony (RSA-4096, K=2, N=3) | Ceremony created |
| 3 | Key Manager | CA Engine | Generate keypair | `{:ok, %{public_key, private_key}}` |
| 4 | Key Manager | CA Engine | Distribute shares to 3 custodians | 3 shares stored |
| 5 | Key Manager | CA Engine | Complete as root (self-signed cert) | Key status → "active" |
| 6 | Custodian 1 | CA Engine | Submit share with password | Share accepted |
| 7 | Custodian 2 | CA Engine | Submit share with password | Key activated |
| 8 | External Client | RA API | Submit CSR | CSR created |
| 9 | RA Officer | RA Portal | Approve CSR | CSR approved |
| 10 | System | CA Engine | Sign certificate | Real X.509 cert issued |
| 11 | OCSP Client | Validation | Query cert status | "good" |

---

## UC-E2E-04: Multi-Certificate Issuance with Same Key

**Modules:** RA Engine → CA Engine
**Precondition:** Key activated, multiple CSRs submitted

| Step | Actor | Action | Expected Result |
|------|-------|--------|-----------------|
| 1 | External Client | Submit CSR 1 (CN=app1.example.com) | CSR 1 created |
| 2 | External Client | Submit CSR 2 (CN=app2.example.com) | CSR 2 created |
| 3 | External Client | Submit CSR 3 (CN=app3.example.com) | CSR 3 created |
| 4 | RA Officer | Approve all 3 CSRs | All approved |
| 5 | System | Sign all 3 | 3 unique certificates issued |
| 6 | — | Verify all serial numbers unique | No duplicates |
| 7 | — | Verify all subject_dn correct | Matches each CSR |
| 8 | OCSP Client | Query each cert | All return "good" |

---

## UC-E2E-05: Selective Revocation — One of Many

**Modules:** CA Engine → Validation
**Precondition:** Multiple certs issued (UC-E2E-04)

| Step | Actor | Action | Expected Result |
|------|-------|--------|-----------------|
| 1 | CA Admin | Revoke cert 2 only | Cert 2 revoked |
| 2 | OCSP Client | Query cert 1 | "good" |
| 3 | OCSP Client | Query cert 2 | "revoked" |
| 4 | OCSP Client | Query cert 3 | "good" |
| 5 | CRL Consumer | GET `/crl` | Only cert 2 in revoked list, total_revoked=1 |

---

## UC-E2E-06: Key Deactivation Blocks Signing

**Modules:** CA Engine → RA Engine
**Precondition:** Key activated, CSR approved

| Step | Actor | Action | Expected Result |
|------|-------|--------|-----------------|
| 1 | Key Manager | Deactivate key | Key deactivated |
| 2 | System | Attempt to sign CSR | `{:error, :key_not_active}` |
| 3 | Custodian 1 | Re-submit share | Share accepted |
| 4 | Custodian 2 | Re-submit share | Key re-activated |
| 5 | System | Attempt to sign CSR again | Certificate issued |

---

## UC-E2E-07: CSR Rejection Flow

**Modules:** RA Portal → RA Engine
**Precondition:** CSR submitted and auto-validated

| Step | Actor | Module | Action | Expected Result |
|------|-------|--------|--------|-----------------|
| 1 | External Client | RA API | Submit CSR | CSR verified |
| 2 | RA Officer | RA Portal | View CSR detail | Detail with Reject form |
| 3 | RA Officer | RA Portal | Enter reason, click Reject | CSR rejected |
| 4 | External Client | RA API | GET `/api/v1/csr/:id` | status="rejected", reason present |
| 5 | — | — | Verify cert never issued | No issued_cert_serial |

---

## UC-E2E-08: API Key Lifecycle with CSR Operations

**Modules:** RA Portal → RA API
**Precondition:** RA admin logged in

| Step | Actor | Module | Action | Expected Result |
|------|-------|--------|--------|-----------------|
| 1 | RA Admin | RA Portal | Create API key "client-v1" | Raw key displayed |
| 2 | External Client | RA API | Submit CSR with key v1 | 201 Created |
| 3 | RA Admin | RA Portal | Create API key "client-v2" | New raw key |
| 4 | External Client | RA API | Submit CSR with key v2 | 201 Created |
| 5 | RA Admin | RA Portal | Revoke key v1 | Key v1 revoked |
| 6 | External Client | RA API | Submit CSR with key v1 | 401 Unauthorized |
| 7 | External Client | RA API | Submit CSR with key v2 | 201 Created (still works) |

---

## UC-E2E-09: CA Setup from Scratch

**Modules:** CA Portal → CA Engine (full initial setup)
**Precondition:** Clean database, services running

| Step | Actor | Module | Action | Expected Result |
|------|-------|--------|--------|-----------------|
| 1 | First User | CA Portal | Navigate to `/setup` | Bootstrap form displayed |
| 1a | First User | CA Portal | Enter username, display name, password, confirm password | Form populated |
| 1b | First User | CA Portal | Click "Create Admin Account" | Redirected to `/login` with success flash |
| 1c | — | CA Portal | Navigate to `/setup` again | Redirected to `/login` ("System already configured.") |
| 2 | CA Admin | CA Portal | Login with bootstrap credentials | Dashboard shown (empty) |
| 2 | CA Admin | CA Portal | Create key_manager user "km1" | User created |
| 3 | CA Admin | CA Portal | Create key_manager user "km2" | User created |
| 4 | CA Admin | CA Portal | Create key_manager user "km3" | User created |
| 5 | CA Admin | CA Portal | Create auditor user | User created |
| 6 | Key Manager | CA Portal | Configure software keystore | Keystore created |
| 7 | Key Manager | CA Portal | Initiate ceremony (RSA-4096, 2-of-3) | Ceremony initiated |
| 8 | Key Manager | CA Engine | Generate keypair | Keypair in memory |
| 9 | Key Manager | CA Engine | Distribute shares (km1, km2, km3) | 3 shares stored |
| 10 | Key Manager | CA Engine | Complete as root CA | Key active with cert |
| 11 | CA Admin | CA Portal | Verify dashboard | 1 active key, 1 completed ceremony |

---

## UC-E2E-10: RA Setup from Scratch

**Modules:** RA Portal → RA Engine (full initial setup)
**Precondition:** Clean database, services running

| Step | Actor | Module | Action | Expected Result |
|------|-------|--------|--------|-----------------|
| 1 | First User | RA Portal | Navigate to `/setup` | Bootstrap form displayed |
| 1a | First User | RA Portal | Enter username, display name, password, confirm password | Form populated |
| 1b | First User | RA Portal | Click "Create Admin Account" | Redirected to `/login` with success flash |
| 1c | — | RA Portal | Navigate to `/setup` again | Redirected to `/login` ("System already configured.") |
| 2 | RA Admin | RA Portal | Login with bootstrap credentials | Dashboard shown (empty) |
| 2 | RA Admin | RA Portal | Create ra_officer user | User created |
| 3 | RA Admin | RA Portal | Create cert profile "TLS Server" | Profile created |
| 4 | RA Admin | RA Portal | Configure OCSP service | Config stored |
| 5 | RA Admin | RA Portal | Configure CRL service | Config stored |
| 6 | RA Admin | RA Portal | Create API key | Raw key captured |
| 7 | External Client | RA API | Submit CSR with API key | 201, CSR verified |
| 8 | RA Admin | RA Portal | Verify dashboard | 1 pending CSR, 1 profile |

---

## UC-E2E-11: Concurrent CSR Processing

**Modules:** RA API → RA Engine → CA Engine
**Precondition:** Key activated, cert profile exists, API key active

| Step | Actor | Action | Expected Result |
|------|-------|--------|-----------------|
| 1 | Client A | Submit CSR A | 201 |
| 2 | Client B | Submit CSR B (concurrently) | 201 |
| 3 | Client C | Submit CSR C (concurrently) | 201 |
| 4 | RA Officer | Approve all 3 | All approved |
| 5 | System | Sign all 3 concurrently | 3 unique certs |
| 6 | — | Verify unique serial numbers | No collisions |

---

## UC-E2E-12: Cross-Portal Navigation

**Modules:** CA Portal + RA Portal
**Precondition:** Both portals running

| Step | Actor | Action | Expected Result |
|------|-------|--------|-----------------|
| 1 | User | Access CA Portal at `:4002` | CA login page |
| 2 | User | Access RA Portal at `:4004` | RA login page |
| 3 | User | Login to CA Portal | CA Dashboard |
| 4 | User | Login to RA Portal (separate session) | RA Dashboard |
| 5 | — | Verify sessions are independent | Different cookies/sessions |

---

## UC-E2E-13: Real CSR with Real Certificate — Full Crypto Chain

**Modules:** RA API → RA Engine → CA Engine → Validation
**Precondition:** CA key active (RSA-4096), cert profile exists

| Step | Actor | Action | Expected Result |
|------|-------|--------|-----------------|
| 1 | External Client | Generate RSA keypair locally | Private key available |
| 2 | External Client | Create CSR: `X509.CSR.new(key, "/CN=real.example.com/O=RealOrg")` | Valid PEM |
| 3 | External Client | Submit CSR via API | 201, subject_dn = "CN=real.example.com" |
| 4 | RA Officer | Approve CSR | Status → approved |
| 5 | System | Sign certificate | Real X.509 cert issued |
| 6 | — | Decode cert DER with `:public_key.der_decode(:OTPCertificate, der)` | Valid structure |
| 7 | — | Verify cert subject matches CSR subject | Subjects match |
| 8 | — | Verify cert signed by issuer key | `:public_key.pkix_verify` passes |
| 9 | OCSP Client | Query OCSP | Status = "good" |

---

## UC-E2E-14: HSM-Backed Certificate Issuance

**Modules:** SoftHSM2 → CA Engine → RA Engine → Validation
**Precondition:** SoftHSM2 running, HSM keystore configured

| Step | Actor | Action | Expected Result |
|------|-------|--------|-----------------|
| 1 | Key Manager | Configure HSM keystore | Keystore created type=hsm |
| 2 | Key Manager | Initiate ceremony with HSM keystore | Ceremony created |
| 3 | Key Manager | Generate keypair on HSM via PKCS#11 | Key handle returned |
| 4 | Key Manager | Distribute shares, complete as root | Key active |
| 5 | — | Verify key exists on HSM | `pkcs11-tool --list-objects` shows key |
| 6 | External Client | Submit and approve CSR | CSR approved |
| 7 | System | Sign cert using HSM key | Certificate issued |
| 8 | — | Verify cert valid | Real X.509 signature |

---

## UC-E2E-15: Audit Trail — Event Recording

**Modules:** CA Engine → Audit Trail
**Precondition:** Audit trail service running

| Step | Actor | Action | Expected Result |
|------|-------|--------|-----------------|
| 1 | CA Admin | Create user | Audit event logged: action=user_created |
| 2 | Key Manager | Initiate ceremony | Audit event logged: action=ceremony_initiated |
| 3 | Custodian | Activate key | Audit event logged: action=key_activated |
| 4 | System | Sign certificate | Audit event logged: action=cert_signed |
| 5 | CA Admin | Revoke certificate | Audit event logged: action=cert_revoked |
| 6 | CA Admin | View audit log in portal | All 5 events visible with timestamps, actors |
| 7 | — | Filter by action "cert_signed" | Only signing event shown |

---

## UC-E2E-16: Service Config Activation — OCSP/CRL

**Modules:** RA Portal → RA Engine → Validation
**Precondition:** Validation service running

| Step | Actor | Action | Expected Result |
|------|-------|--------|-----------------|
| 1 | RA Admin | Configure OCSP service: url=http://pki-validation:4005, port=4005 | Config stored |
| 2 | RA Admin | Configure CRL service: url=http://pki-validation:4005/crl | Config stored |
| 3 | — | Verify OCSP endpoint responds | GET health returns 200 |
| 4 | — | Verify CRL endpoint responds | GET /crl returns valid CRL |
| 5 | — | Issue a cert, query OCSP using configured URL | Status = "good" |
| 6 | — | Revoke cert, query CRL using configured URL | Cert in revoked list |

---

## Coverage Matrix

| Module | Use Cases | Portal UI | API/Engine | State Machine | Error Cases |
|--------|-----------|-----------|------------|---------------|-------------|
| **CA** | 35 | UC-CA-00A/B, 01 to 09, 22, 26 | UC-CA-10 to 21, 23-25, 27-28 | UC-CA-21, 33 (key), UC-CA-08 (ceremony) | UC-CA-00A (validation), 29, 30, 31, 32 |
| **RA** | 38 | UC-RA-00A/B, 01 to 11, 15-19, 29 | UC-RA-12 to 14, 20-28, 33-35 | UC-RA-21, 30 (CSR) | UC-RA-00A (validation), 31, 32, 36 |
| **Validation** | 20 | — | UC-VAL-01 to 20 | UC-VAL-06, 15, 16 (lifecycle) | UC-VAL-13, 18, 20 |
| **E2E** | 16 | UC-E2E-09, 10, 12 | UC-E2E-01 to 08, 11, 13-16 | UC-E2E-01, 02, 03, 13 (full chain) | UC-E2E-06, 07 |
| **Total** | **109** | | | | |
