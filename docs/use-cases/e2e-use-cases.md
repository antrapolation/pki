# End-to-End Cross-Module — Use Cases

These use cases span multiple modules and test the full system working together.

## Actors

| Actor | Description |
|-------|-------------|
| Platform Admin | Platform portal user (manages tenants) |
| Tenant Admin | First user of a new tenant (bootstraps CA instance) |
| CA Admin | CA portal user (manages CA) |
| Key Manager | CA portal user (manages keys/ceremonies) |
| Custodian | Key manager participating in threshold ceremony |
| Auditor | Views audit logs, participates in ceremony finalization |
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

## UC-E2E-17: Tenant Lifecycle

**Modules:** Platform Portal → CA Portal → CA Engine → RA Portal
**Precondition:** Platform Portal running, PostgreSQL accessible
**Actors:** Platform Admin, Tenant Admin, CA Admin

| Step | Actor | Module | Action | Expected Result |
|------|-------|--------|--------|-----------------|
| 1 | Platform Admin | Platform Portal | Login to Platform Portal | Dashboard displayed |
| 2 | Platform Admin | Platform Portal | Create tenant "Acme Corp" with subdomain "acme" | Tenant created, status = "initialized", setup URL returned |
| 3 | Tenant Admin | CA Portal | Navigate to `https://acme.ca.domain.com/setup` | Bootstrap form displayed |
| 4 | Tenant Admin | CA Portal | Enter name, login, password, org name | Form populated |
| 5 | Tenant Admin | CA Portal | Click "Create Admin Account" | Admin created with dual keypairs, Keypair ACL initialized, 4 system keypairs created |
| 6 | — | System | Tenant status transitions to "active" | Tenant resolvable |
| 7 | CA Admin | CA Portal | Login with credentials | Dashboard displayed, session_key in cookie |
| 8 | CA Admin | CA Portal | Create users, configure keystores | Normal CA operations succeed |
| 9 | Platform Admin | Platform Portal | Suspend tenant "acme" | Tenant status = "suspended" |
| 10 | CA Admin | CA Portal | Attempt login | Fails: "Tenant suspended" |
| 11 | Platform Admin | Platform Portal | Activate tenant "acme" | Tenant status = "active" |
| 12 | CA Admin | CA Portal | Login with credentials | Login succeeds, operations resume |

---

## UC-E2E-18: Cross-Tenant Isolation

**Modules:** Platform Portal → CA Engine (two tenants)
**Precondition:** Platform Portal running
**Actors:** Platform Admin, Tenant Admin A, Tenant Admin B

| Step | Actor | Module | Action | Expected Result |
|------|-------|--------|--------|-----------------|
| 1 | Platform Admin | Platform Portal | Create tenant "Alpha" (subdomain "alpha") | Tenant A created with own database |
| 2 | Platform Admin | Platform Portal | Create tenant "Beta" (subdomain "beta") | Tenant B created with own database |
| 3 | Tenant Admin A | CA Portal (alpha) | Bootstrap and create users | Users created in `pki_tenant_{uuid_a}.ca.users` |
| 4 | Tenant Admin B | CA Portal (beta) | Bootstrap and create users | Users created in `pki_tenant_{uuid_b}.ca.users` |
| 5 | CA Admin A | CA Portal (alpha) | List users | Only sees Alpha's users, no Beta data |
| 6 | CA Admin B | CA Portal (beta) | List users | Only sees Beta's users, no Alpha data |
| 7 | CA Admin A | CA Engine | Create keystore and initiate ceremony | Ceremony scoped to Alpha's database |
| 8 | CA Admin B | CA Engine | List keystores | Empty — no Alpha keystores visible |
| 9 | — | System | Verify at DB level: `pki_tenant_{uuid_a}` and `pki_tenant_{uuid_b}` are separate databases | Complete isolation |

---

## UC-E2E-19: Credential-Aware Certificate Issuance

**Modules:** Platform Portal → CA Portal → CA Engine → RA Engine → Validation
**Precondition:** Platform Portal running, PostgreSQL accessible
**Actors:** Platform Admin, Tenant Admin, Key Managers, Auditor, RA Admin, RA Officer, External Client, OCSP Client

| Step | Actor | Module | Action | Expected Result |
|------|-------|--------|--------|-----------------|
| 1 | Platform Admin | Platform Portal | Create tenant | Tenant initialized |
| 2 | Tenant Admin | CA Portal | Bootstrap with credentials (UC-CA-00C) | Admin with dual keypairs, ACL, system keypairs created |
| 3 | CA Admin | CA Portal | Login with credentials (UC-CA-01A) | Session with session_key |
| 4 | CA Admin | CA Portal | Create Key Manager 1 with credentials (UC-CA-03A) | User with dual keypairs |
| 5 | CA Admin | CA Portal | Create Key Manager 2 with credentials | Second manager with keypairs |
| 6 | CA Admin | CA Portal | Create Auditor with credentials | Auditor with keypairs |
| 7 | Key Managers + Auditor | CA Engine | Multi-manager key ceremony (UC-CA-35) | Root key created, shares to custodians, auditor signs off |
| 8 | Custodians | CA Engine | Activate key via threshold shares | Key activated |
| 9 | RA Admin | RA Portal | Bootstrap RA with credentials (UC-RA-00C) | RA admin with dual keypairs |
| 10 | RA Admin | RA Portal | Create cert profile, API key | Infrastructure ready |
| 11 | External Client | RA API | Submit CSR | CSR created, auto-validated |
| 12 | RA Officer | RA Portal | Approve CSR | CSR approved |
| 13 | System | CA Engine | Sign certificate (with credential-activated key) | X.509 cert issued |
| 14 | OCSP Client | Validation | Query OCSP for cert | Status = "good" |

---

## Coverage Matrix

| Module | Use Cases | Portal UI | API/Engine | State Machine | Error Cases |
|--------|-----------|-----------|------------|---------------|-------------|
| **Platform** | 8 | UC-PLT-01 to 06 | UC-PLT-07, 08 | UC-PLT-04, 05 (tenant status) | UC-PLT-03, 06, 07, 08 |
| **CA** | 40 | UC-CA-00A/B/C, 01, 01A, 03, 03A, 04 to 09, 22, 26, 34 | UC-CA-10 to 21, 23-25, 27-28, 35-38 | UC-CA-21, 33 (key), UC-CA-08 (ceremony) | UC-CA-00A/C (validation), 29, 30, 31, 32, 35, 36, 38 |
| **RA** | 41 | UC-RA-00A/B/C, 01, 01A, 03, 03A, 04 to 11, 15-19, 29 | UC-RA-12 to 14, 20-28, 33-35 | UC-RA-21, 30 (CSR) | UC-RA-00A/C (validation), 31, 32, 36 |
| **Validation** | 20 | — | UC-VAL-01 to 20 | UC-VAL-06, 15, 16 (lifecycle) | UC-VAL-13, 18, 20 |
| **E2E** | 19 | UC-E2E-09, 10, 12, 17 | UC-E2E-01 to 08, 11, 13-19 | UC-E2E-01, 02, 03, 13, 17 (full chain) | UC-E2E-06, 07, 18 |
| **Total** | **128** | | | | |
