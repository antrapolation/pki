# RA Module — Use Cases

## Actors

| Actor | Role | Description |
|-------|------|-------------|
| RA Admin | `ra_admin` | Manages RA users, cert profiles, service configs, API keys |
| RA Officer | `ra_officer` | Processes CSRs (view, approve, reject) |
| Auditor | `auditor` | Views audit logs |
| External Client | — | Submits CSRs via REST API using API key |
| CA Engine | — | Signs approved CSRs |

---

## UC-RA-00A: Bootstrap — First-Run Setup Page

**Actor:** First user (becomes RA Admin)
**Precondition:** Clean database, no users exist, service running
**Trigger:** Navigate to `/setup`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/setup` | Setup form displayed with title "RA Portal Setup" |
| 2 | Verify form fields | Username, Display Name, Password, Confirm Password fields present |
| 3 | Enter username (min 3 chars) | Field populated |
| 4 | Enter display name (optional) | Field populated |
| 5 | Enter password (min 8 chars) | Field populated |
| 6 | Enter matching password confirmation | Field populated |
| 7 | Click "Create Admin Account" | Admin user created with role `ra_admin` |
| 8 | Verify redirect | Redirected to `/login` with flash "Admin account created. Please sign in." |

**Error Cases:**
- Password mismatch → "Passwords do not match" error displayed
- Password too short (< 8 chars) → "Password must be at least 8 characters" error displayed
- Duplicate username → changeset error displayed

---

## UC-RA-00B: Bootstrap — Setup Page Blocked After Initial Setup

**Actor:** Any user
**Precondition:** Admin user already created (UC-RA-00A completed)
**Trigger:** Navigate to `/setup`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/setup` | Redirected to `/login` |
| 2 | Verify flash message | "System already configured." |
| 3 | POST to `/setup` with valid params | Redirected to `/login` with error "System already configured." |

---

## UC-RA-01: Login to RA Portal

**Actor:** RA Admin / RA Officer / Auditor
**Precondition:** Service running, user has valid DID
**Trigger:** Navigate to `/login`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/login` | Login form with DID and role fields |
| 2 | Enter DID, select role | Form populated |
| 3 | Click "Login" | Redirected to Dashboard (`/`) |
| 4 | Verify session | User identity in nav bar |

---

## UC-RA-02: View RA Dashboard

**Actor:** Any authenticated user
**Precondition:** Logged in
**Trigger:** Navigate to `/`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Page loads | Pending CSR count displayed |
| 2 | — | Certificate profile count displayed |
| 3 | — | Recent 5 CSRs table populated |
| 4 | — | Quick action links visible |

---

## UC-RA-03: Create RA User

**Actor:** RA Admin
**Precondition:** Logged in as `ra_admin`
**Trigger:** Navigate to `/users`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/users` | User list and create form |
| 2 | Enter DID | Field populated |
| 3 | Enter display name | Field populated |
| 4 | Select role: `ra_officer` | Role set |
| 5 | Click "Create User" | New user in table |
| 6 | Verify user row | Shows DID, name, role, active status |

**Error Cases:**
- Duplicate DID → error
- Missing fields → validation error

---

## UC-RA-04: Filter RA Users by Role

**Actor:** RA Admin
**Precondition:** Multiple users exist

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Select "ra_officer" filter | Only RA officers shown |
| 2 | Select "ra_admin" filter | Only RA admins shown |
| 3 | Select "all" filter | All users shown |

---

## UC-RA-05: Suspend RA User

**Actor:** RA Admin
**Precondition:** User exists

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Click "Delete" on user row | User removed from list |
| 2 | Verify in DB | Status = "suspended" |

---

## UC-RA-06: Create Certificate Profile

**Actor:** RA Admin
**Precondition:** Logged in as `ra_admin`
**Trigger:** Navigate to `/cert-profiles`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/cert-profiles` | Profile list and create form |
| 2 | Enter name: "TLS Server" | Name field populated |
| 3 | Enter key usage: "digitalSignature,keyEncipherment" | Key usage set |
| 4 | Enter ext key usage: "serverAuth,clientAuth" | Ext key usage set |
| 5 | Select digest algo: "SHA-256" | Digest set |
| 6 | Enter validity days: 365 | Validity set |
| 7 | Click "Create Profile" | New profile in table |

---

## UC-RA-07: Edit Certificate Profile

**Actor:** RA Admin
**Precondition:** Profile exists

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Click "Edit" on profile row | Edit form opens with current values |
| 2 | Change validity_days to 730 | Field updated |
| 3 | Click "Update" | Profile updated in table |
| 4 | Verify new values | validity_days = 730 |

---

## UC-RA-08: Delete Certificate Profile

**Actor:** RA Admin
**Precondition:** Profile exists, no CSRs reference it

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Click "Delete" on profile row | Profile removed from table |
| 2 | Verify deletion | Profile no longer in DB |

---

## UC-RA-09: Configure OCSP Service

**Actor:** RA Admin
**Precondition:** Logged in as `ra_admin`
**Trigger:** Navigate to `/service-configs`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/service-configs` | Config list and form |
| 2 | Select service type: "OCSP Responder" | Type set |
| 3 | Enter port: 4005 | Port set |
| 4 | Enter URL: "http://ocsp.example.com" | URL set |
| 5 | Enter rate limit: 1000 | Rate limit set |
| 6 | Enter IP whitelist: "10.0.0.0/8" | Whitelist set |
| 7 | Click "Configure" | Config appears in table |

**Also test with:** CRL Distribution, TSA

---

## UC-RA-10: Create API Key

**Actor:** RA Admin
**Precondition:** Logged in as `ra_admin`
**Trigger:** Navigate to `/api-keys`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/api-keys` | Key list and create form |
| 2 | Enter name: "external-integrator" | Name field populated |
| 3 | Click "Create Key" | Raw key displayed in modal (one-time) |
| 4 | Copy raw key value | Base64-encoded key string |
| 5 | Click "Dismiss" | Modal closes, raw key no longer visible |
| 6 | Verify key in table | Shows name, status=active, created_at |

---

## UC-RA-11: Revoke API Key

**Actor:** RA Admin
**Precondition:** Active API key exists

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Locate key in table | Key row visible |
| 2 | Click "Revoke" | Key status changes to "revoked" |
| 3 | Verify revoke button gone | No action available on revoked key |

---

## UC-RA-12: Submit CSR via REST API

**Actor:** External Client
**Precondition:** Valid API key, cert profile exists
**Trigger:** POST request to `/api/v1/csr`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/api/v1/csr` with `Authorization: Bearer <key>` | — |
| 2 | Body: `{"csr_pem": "<valid PEM>", "cert_profile_id": 1}` | — |
| 3 | Response: 201 Created | CSR record with status "verified" |
| 4 | Verify subject_dn extracted from CSR | Real subject DN (not placeholder) |
| 5 | Verify submitted_at timestamp | Non-nil UTC timestamp |

**Error Cases:**
- Missing Authorization header → 401 Unauthorized
- Invalid API key → 401 Unauthorized
- Revoked API key → 401 Unauthorized
- Missing csr_pem → 400/422 error
- Invalid cert_profile_id → error

---

## UC-RA-13: Submit CSR with Auto-Validation Pass

**Actor:** External Client
**Precondition:** Valid CSR PEM, valid cert profile
**Trigger:** CSR submission

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Submit valid CSR | CSR created with status "pending" |
| 2 | Call `validate_csr(csr_id)` | CSR transitions to "verified" |
| 3 | Verify status = "verified" | Auto-validation passed |

---

## UC-RA-14: Submit CSR with Auto-Validation Fail

**Actor:** External Client
**Precondition:** Empty or invalid CSR
**Trigger:** CSR submission with bad data

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Submit CSR with empty csr_pem | CSR created as "pending" |
| 2 | Call `validate_csr(csr_id)` | CSR transitions to "rejected" |
| 3 | Verify status = "rejected" | Auto-validation failed |

---

## UC-RA-15: View CSR List in Portal

**Actor:** RA Officer
**Precondition:** CSRs exist in various statuses
**Trigger:** Navigate to `/csrs`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Navigate to `/csrs` | CSR table with all entries |
| 2 | Each row shows: ID, subject_dn, status, submitted_at | Correct data |

---

## UC-RA-16: Filter CSRs by Status

**Actor:** RA Officer
**Precondition:** CSRs in multiple statuses exist

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Select "pending" filter | Only pending CSRs shown |
| 2 | Select "approved" filter | Only approved CSRs shown |
| 3 | Select "rejected" filter | Only rejected CSRs shown |
| 4 | Select "all" filter | All CSRs shown |

---

## UC-RA-17: View CSR Detail

**Actor:** RA Officer
**Precondition:** CSR exists
**Trigger:** Click "View" on CSR row

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Click "View" on a CSR row | Detail modal opens |
| 2 | Verify fields: CSR PEM, subject_dn, status, profile_id | All shown |
| 3 | If status = "verified": Approve/Reject buttons visible | Action buttons present |
| 4 | If status = "approved"/"issued": No action buttons | Read-only detail |
| 5 | Click "Close" | Modal closes |

---

## UC-RA-18: Approve CSR

**Actor:** RA Officer
**Precondition:** CSR in "verified" status
**Trigger:** Click "Approve" in CSR detail

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Open CSR detail (verified status) | Approve button visible |
| 2 | Click "Approve" | CSR status changes to "approved" |
| 3 | Verify reviewed_by = current user DID | Reviewer recorded |
| 4 | Verify reviewed_at | Timestamp set |
| 5 | Detail modal updates to show approved status | No more action buttons |

---

## UC-RA-19: Reject CSR with Reason

**Actor:** RA Officer
**Precondition:** CSR in "verified" status
**Trigger:** Click "Reject" in CSR detail

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Open CSR detail (verified status) | Reject form visible |
| 2 | Enter rejection reason: "Invalid domain ownership" | Reason field populated |
| 3 | Submit rejection | CSR status changes to "rejected" |
| 4 | Verify rejection_reason stored | "Invalid domain ownership" |
| 5 | Verify reviewed_by and reviewed_at | Both set |

---

## UC-RA-20: Forward Approved CSR to CA for Signing

**Actor:** System / RA Officer
**Precondition:** CSR in "approved" status, CA engine running with active key
**Trigger:** Forward to CA

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Call `CsrValidation.forward_to_ca(csr_id)` | CA engine signs the CSR |
| 2 | CA returns certificate data with serial_number | — |
| 3 | CSR status transitions to "issued" | Status updated |
| 4 | issued_cert_serial populated | Serial number from CA |

**Error Cases:**
- CA engine not configured → `{:error, :ca_engine_not_configured}`
- CA key not active → `{:error, :key_not_active}`

---

## UC-RA-21: CSR State Machine — Invalid Transitions

**Actor:** System
**Precondition:** CSRs in various states

| Step | From Status | To Status | Expected |
|------|------------|-----------|----------|
| 1 | pending | approved | Error: invalid_transition |
| 2 | pending | issued | Error: invalid_transition |
| 3 | rejected | approved | Error: invalid_transition |
| 4 | rejected | issued | Error: invalid_transition |
| 5 | issued | approved | Error: invalid_transition |
| 6 | approved | verified | Error: invalid_transition |

---

## UC-RA-22: API Key Authentication — Valid Key

**Actor:** External Client
**Precondition:** Active API key

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | GET `/api/v1/csr` with `Authorization: Bearer <valid-key>` | 200 OK with CSR list |

---

## UC-RA-23: API Key Authentication — Invalid/Revoked Key

**Actor:** External Client
**Precondition:** Revoked or non-existent key

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | GET `/api/v1/csr` with `Authorization: Bearer <revoked-key>` | 401 Unauthorized |
| 2 | GET `/api/v1/csr` with `Authorization: Bearer <garbage>` | 401 Unauthorized |
| 3 | GET `/api/v1/csr` without Authorization header | 401 Unauthorized |

---

## UC-RA-24: API Key Rotation Flow

**Actor:** RA Admin + External Client
**Precondition:** Old API key active, client using it

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Create new API key (UC-RA-10) | New key created, raw key captured |
| 2 | Test new key: POST `/api/v1/csr` | 201 Created — works |
| 3 | Revoke old key (UC-RA-11) | Old key revoked |
| 4 | Test old key: POST `/api/v1/csr` | 401 Unauthorized — rejected |
| 5 | Test new key again | Still works |

---

## UC-RA-25: List CSRs via REST API

**Actor:** External Client
**Precondition:** Valid API key, CSRs exist

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | GET `/api/v1/csr` | 200 with list of all CSRs |
| 2 | GET `/api/v1/csr?status=pending` | Only pending CSRs |

---

## UC-RA-26: Get CSR by ID via REST API

**Actor:** External Client
**Precondition:** Valid API key, CSR exists

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | GET `/api/v1/csr/1` | 200 with CSR detail |
| 2 | GET `/api/v1/csr/99999` | 404 Not Found |

---

## UC-RA-27: Approve CSR via REST API

**Actor:** External Client (with officer privileges)
**Precondition:** CSR in "verified" status

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/api/v1/csr/1/approve` with `{"reviewer_user_id": 5}` | CSR approved |
| 2 | Verify status = "approved" | — |

---

## UC-RA-28: Reject CSR via REST API

**Actor:** External Client
**Precondition:** CSR in "verified" status

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/api/v1/csr/1/reject` with reason | CSR rejected |
| 2 | Verify rejection_reason stored | — |

---

## UC-RA-29: Logout from RA Portal

**Actor:** Any authenticated user

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Click "Logout" | Session cleared, redirect to `/login` |
| 2 | Try accessing `/csrs` | Redirected to `/login` |

---

## UC-RA-30: CSR State Machine — All Invalid Transitions (Exhaustive)

**Actor:** System
**Precondition:** CSRs in various states

| Step | From | To | Expected |
|------|------|-----|----------|
| 1 | pending | approved | `{:error, {:invalid_transition, ...}}` |
| 2 | pending | issued | `{:error, {:invalid_transition, ...}}` |
| 3 | verified | issued | `{:error, {:invalid_transition, ...}}` |
| 4 | verified | pending | `{:error, {:invalid_transition, ...}}` |
| 5 | rejected | approved | `{:error, {:invalid_transition, ...}}` |
| 6 | rejected | verified | `{:error, {:invalid_transition, ...}}` |
| 7 | rejected | issued | `{:error, {:invalid_transition, ...}}` |
| 8 | issued | approved | `{:error, {:invalid_transition, ...}}` |
| 9 | issued | rejected | `{:error, {:invalid_transition, ...}}` |
| 10 | issued | pending | `{:error, {:invalid_transition, ...}}` |
| 11 | approved | verified | `{:error, {:invalid_transition, ...}}` |
| 12 | approved | pending | `{:error, {:invalid_transition, ...}}` |

---

## UC-RA-31: API Key Authentication — Edge Cases

**Actor:** External Client
**Precondition:** Various key states

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Request with `Authorization: Bearer ` (empty token) | 401 Unauthorized |
| 2 | Request with `Authorization: Basic <base64>` (wrong scheme) | 401 Unauthorized |
| 3 | Request with `Authorization: Bearer <invalid-base64>` | 401 Unauthorized |
| 4 | Request with expired API key (if expiry set) | 401 Unauthorized |
| 5 | Request immediately after key creation | 200 OK |
| 6 | Request immediately after key revocation | 401 Unauthorized |

---

## UC-RA-32: CSR Submission — Input Validation

**Actor:** External Client
**Precondition:** Valid API key

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/api/v1/csr` with empty body | 400/422 error |
| 2 | POST `/api/v1/csr` with missing csr_pem | 400/422 error |
| 3 | POST `/api/v1/csr` with missing cert_profile_id | 400/422 error |
| 4 | POST `/api/v1/csr` with non-existent cert_profile_id | Error: profile not found |
| 5 | POST `/api/v1/csr` with invalid JSON | 400 Bad Request |
| 6 | POST `/api/v1/csr` with empty csr_pem ("") | CSR created, auto-validation rejects it |

---

## UC-RA-33: CSR with Real PEM — Subject DN Extraction

**Actor:** External Client
**Precondition:** Valid API key, cert profile exists

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Generate real RSA keypair | Private key available |
| 2 | Create CSR with subject "/CN=test.example.com/O=TestOrg/C=MY" | Valid PEM |
| 3 | Submit CSR via API | 201 Created |
| 4 | Verify extracted subject_dn | Contains "CN=test.example.com" (parsed from PEM) |
| 5 | Verify subject_dn is NOT "CN=pending_extraction" | Real parsing worked |

---

## UC-RA-34: Service Config — Upsert Behavior

**Actor:** RA Admin
**Precondition:** Service config may or may not exist

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Configure "OCSP Responder" with port 4005 | Config created |
| 2 | Configure "OCSP Responder" again with port 4006 | Config updated (upsert), not duplicated |
| 3 | List service configs | Only 1 OCSP config with port 4006 |

---

## UC-RA-35: RA Health Check Endpoint

**Actor:** Monitoring system
**Precondition:** RA engine running

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | GET `/health` | 200 OK |
| 2 | Verify response | `{"status": "ok"}` |
| 3 | No authentication required | No Bearer token needed |

---

## UC-RA-36: RA User Authorization Enforcement

**Actor:** Various roles
**Precondition:** Users with different roles exist

| Step | Role | Permission | Expected |
|------|------|-----------|----------|
| 1 | ra_admin | manage_ra_admins | Authorized |
| 2 | ra_admin | manage_cert_profiles | Authorized |
| 3 | ra_admin | manage_api_keys | Authorized |
| 4 | ra_officer | process_csrs | Authorized |
| 5 | ra_officer | manage_cert_profiles | Unauthorized |
| 6 | ra_officer | manage_api_keys | Unauthorized |
| 7 | auditor | view_audit_log | Authorized |
| 8 | auditor | process_csrs | Unauthorized |
