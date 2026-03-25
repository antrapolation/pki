# Validation Module (OCSP/CRL) — Use Cases

## Actors

| Actor | Role | Description |
|-------|------|-------------|
| OCSP Client | — | Queries certificate status (relying parties, browsers, TLS libraries) |
| CRL Consumer | — | Downloads CRL for offline validation |
| CA Engine | — | Issues and revokes certificates (source of truth) |
| System | — | Periodic CRL regeneration, cache management |

---

## UC-VAL-01: Health Check

**Actor:** Monitoring system / Load balancer
**Precondition:** Service running
**Trigger:** GET `/health`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | GET `/health` | 200 OK |
| 2 | Verify response body | `{"status": "ok"}` |

---

## UC-VAL-02: OCSP Query — Certificate Good

**Actor:** OCSP Client
**Precondition:** Certificate issued and active in DB
**Trigger:** POST `/ocsp`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/ocsp` with `{"serial_number": "<valid-serial>"}` | 200 OK |
| 2 | Verify response.status | `"good"` |
| 3 | Verify response.serial_number | Matches request |
| 4 | Verify response.not_after | Future date |

---

## UC-VAL-03: OCSP Query — Certificate Revoked

**Actor:** OCSP Client
**Precondition:** Certificate revoked via CA engine
**Trigger:** POST `/ocsp`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/ocsp` with `{"serial_number": "<revoked-serial>"}` | 200 OK |
| 2 | Verify response.status | `"revoked"` |
| 3 | Verify response.revoked_at | Timestamp of revocation |
| 4 | Verify response.reason | Revocation reason (e.g., "keyCompromise") |

---

## UC-VAL-04: OCSP Query — Certificate Unknown

**Actor:** OCSP Client
**Precondition:** Serial number does not exist in DB
**Trigger:** POST `/ocsp`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/ocsp` with `{"serial_number": "nonexistent123"}` | 200 OK |
| 2 | Verify response.status | `"unknown"` |
| 3 | Verify response.serial_number | Matches request |

---

## UC-VAL-05: OCSP Cache Hit

**Actor:** OCSP Client
**Precondition:** Same serial queried within cache TTL
**Trigger:** Repeated POST `/ocsp`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | First query: POST `/ocsp` with serial | Response from DB lookup |
| 2 | Second query: same serial within cache TTL | Response from ETS cache (faster) |
| 3 | Verify both responses identical | Same status, same data |

---

## UC-VAL-06: OCSP Query After Revocation

**Actor:** OCSP Client
**Precondition:** Certificate was "good", then revoked
**Trigger:** OCSP query after revocation

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Query OCSP for active cert | Status = "good" |
| 2 | CA Engine revokes the certificate | — |
| 3 | Query OCSP again (after cache refresh) | Status = "revoked" |
| 4 | Verify revoked_at and reason present | Non-nil |

---

## UC-VAL-07: Get Current CRL

**Actor:** CRL Consumer
**Precondition:** CRL has been generated
**Trigger:** GET `/crl`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | GET `/crl` | 200 OK |
| 2 | Verify response.type | `"X509CRL"` |
| 3 | Verify response.version | `2` |
| 4 | Verify response.this_update | Recent timestamp |
| 5 | Verify response.next_update | Future timestamp (this_update + interval) |
| 6 | Verify response.revoked_certificates | Array of revoked entries |
| 7 | Verify response.total_revoked | Integer count |

---

## UC-VAL-08: CRL Contains Revoked Certificate

**Actor:** CRL Consumer
**Precondition:** Certificate has been revoked
**Trigger:** GET `/crl`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Revoke a certificate via CA Engine | Certificate marked revoked |
| 2 | Force CRL regeneration or wait for periodic refresh | — |
| 3 | GET `/crl` | Response includes revoked cert |
| 4 | Find cert in revoked_certificates by serial_number | Entry exists |
| 5 | Verify entry.revoked_at | Matches revocation timestamp |
| 6 | Verify entry.reason | Matches revocation reason |

---

## UC-VAL-09: CRL Empty (No Revocations)

**Actor:** CRL Consumer
**Precondition:** No certificates have been revoked
**Trigger:** GET `/crl`

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | GET `/crl` | 200 OK |
| 2 | Verify revoked_certificates | Empty array `[]` |
| 3 | Verify total_revoked | `0` |

---

## UC-VAL-10: CRL Periodic Regeneration

**Actor:** System
**Precondition:** CRL publisher running with interval
**Trigger:** Timer fires

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | CRL publisher starts with interval (e.g., 1 hour) | Timer set |
| 2 | Timer fires | CRL regenerated from DB |
| 3 | New CRL has updated this_update and next_update | Timestamps refreshed |
| 4 | GET `/crl` returns new CRL | Updated data |

---

## UC-VAL-11: CRL Force Regeneration

**Actor:** Admin (via API/IEx)
**Precondition:** CRL publisher running
**Trigger:** Manual regeneration request

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Call `CrlPublisher.regenerate(server)` | Returns `{:ok, new_crl}` |
| 2 | Verify new CRL this_update | Recent timestamp |
| 3 | GET `/crl` reflects new data | Updated |

---

## UC-VAL-12: OCSP Concurrent Queries

**Actor:** Multiple OCSP clients
**Precondition:** Service running, certificates in various states

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Send 10 concurrent OCSP queries for different serials | All return within timeout |
| 2 | Verify each response matches expected status | Correct per serial |
| 3 | No errors or crashes | Service stable |

---

## UC-VAL-13: OCSP Query with Invalid Request

**Actor:** OCSP Client
**Precondition:** Service running
**Trigger:** Malformed request

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | POST `/ocsp` with empty body | Error response |
| 2 | POST `/ocsp` with `{"serial_number": ""}` | Status "unknown" or error |
| 3 | POST `/ocsp` with invalid JSON | 400 Bad Request |

---

## UC-VAL-14: CRL Multiple Revocations

**Actor:** CRL Consumer
**Precondition:** Multiple certificates revoked with different reasons

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Revoke cert A with "keyCompromise" | — |
| 2 | Revoke cert B with "cessationOfOperation" | — |
| 3 | Revoke cert C with "affiliationChanged" | — |
| 4 | Regenerate CRL | — |
| 5 | GET `/crl` | All 3 certs in revoked_certificates |
| 6 | Verify each entry has correct serial, revoked_at, reason | Distinct entries |
| 7 | Verify total_revoked = 3 | Count correct |

---

## UC-VAL-15: Certificate Status Tracking — Full Lifecycle

**Actor:** System + OCSP Client
**Precondition:** CA Engine and Validation Service running

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | CA Engine issues a certificate | Certificate stored |
| 2 | OCSP query for new cert | Status = "good" |
| 3 | CRL check | Cert NOT in revoked list |
| 4 | CA Engine revokes the cert | Cert marked revoked |
| 5 | OCSP query again | Status = "revoked" |
| 6 | CRL check again | Cert IS in revoked list |

---

## UC-VAL-16: OCSP Cache Invalidation After Revocation

**Actor:** OCSP Client
**Precondition:** Certificate cached as "good" in ETS
**Trigger:** Certificate revoked, then queried again

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Query OCSP for active cert | Status = "good" (cached) |
| 2 | Revoke the certificate in CA engine | — |
| 3 | Query OCSP immediately (cache still warm) | May return stale "good" |
| 4 | Wait for cache TTL to expire or force uncached query | — |
| 5 | Query OCSP again | Status = "revoked" |
| 6 | Verify `check_status_uncached` always returns fresh result | "revoked" immediately |

---

## UC-VAL-17: CRL Validity Window

**Actor:** CRL Consumer
**Precondition:** CRL generated

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | GET `/crl` | CRL returned |
| 2 | Verify this_update | Recent timestamp (within last interval) |
| 3 | Verify next_update | this_update + interval (e.g., 1 hour) |
| 4 | Verify next_update > this_update | Monotonically increasing |
| 5 | Wait for interval, GET `/crl` again | New CRL with updated timestamps |

---

## UC-VAL-18: OCSP Under Concurrent Load

**Actor:** Multiple OCSP Clients
**Precondition:** Mix of good, revoked, and unknown certs in DB

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Send 50 concurrent OCSP queries (mix of serials) | All return within 500ms |
| 2 | Verify each response correct per serial | good/revoked/unknown as expected |
| 3 | No 500 errors or timeouts | Service stable |
| 4 | Verify ETS cache populated | Subsequent queries faster |

---

## UC-VAL-19: Validation Health Check Under Load

**Actor:** Monitoring system
**Precondition:** CRL generation and OCSP queries active

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | GET `/health` while CRL regeneration in progress | 200 OK (non-blocking) |
| 2 | GET `/health` while OCSP queries running | 200 OK |
| 3 | Verify health check response time < 100ms | Fast regardless of load |

---

## UC-VAL-20: CRL Generation Error Handling

**Actor:** System
**Precondition:** Database connection issues or empty DB

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | CRL generation with no revoked certificates | CRL with empty list, total_revoked=0 |
| 2 | CRL generation with DB query error | CRL with generation_error=true |
| 3 | GET `/crl` after error | Returns last valid CRL or error state |
