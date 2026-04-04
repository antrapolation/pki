# Domain Control Validation (DCV) Design

**Date:** 2026-04-04
**Status:** Approved
**Goal:** Implement HTTP-01 and DNS-01 domain control validation for CSR approval, per CA/Browser Forum Baseline Requirements §3.2.2.4.

---

## 1. DCV Lifecycle

```
CSR verified → Officer clicks "Start DCV" → Challenge created (pending)
→ Requestor places token → Auto-poll every 5min + manual "Verify Now"
→ Token found → DCV "passed" → Officer can approve
→ Window expired → DCV "expired" → Officer can retry
```

- DCV is per-CSR, independent of CSR status
- Officer triggers DCV after reviewing the CSR
- Officer chooses method: HTTP-01 or DNS-01
- Officer cannot approve until DCV passes (if cert profile requires DCV)
- Configurable timeout per cert profile (default 24 hours)

---

## 2. Challenge Methods

### HTTP-01

- System generates: `token` (32 random bytes, base64url) and `token_value` (SHA-256 of token + domain)
- Requestor places file at: `http://<domain>/.well-known/pki-validation/<token>`
- File content must contain: `token_value`
- Verification: HTTP GET, 10s timeout, follow up to 3 same-domain redirects
- Response 200 with body containing token_value → pass

### DNS-01

- System generates: same `token` and `token_value`
- Requestor adds TXT record: `_pki-validation.<domain>` with value `token_value`
- Verification: DNS TXT lookup via Erlang `:inet_res.lookup`
- Any TXT record matching token_value → pass

### Token Generation

- `token`: 32 bytes from `:crypto.strong_rand_bytes`, base64url-encoded
- `token_value`: `Base.encode16(:crypto.hash(:sha256, token <> domain), case: :lower)`
- Token is tied to the specific domain — can't be reused across domains

---

## 3. Database Schema

### New table: `dcv_challenges`

| Column | Type | Purpose |
|--------|------|---------|
| `id` | binary_id (UUIDv7) | PK |
| `csr_id` | FK → csr_requests, NOT NULL | Which CSR |
| `domain` | string, NOT NULL | Domain being validated |
| `method` | string, NOT NULL | "http-01" or "dns-01" |
| `token` | string, NOT NULL | Challenge token |
| `token_value` | string, NOT NULL | Expected verification value |
| `status` | string, default "pending" | "pending", "passed", "failed", "expired" |
| `initiated_by` | binary_id | Officer who started DCV |
| `verified_at` | utc_datetime | When passed |
| `expires_at` | utc_datetime, NOT NULL | Window deadline |
| `attempts` | integer, default 0 | Verification attempt count |
| `last_checked_at` | utc_datetime | Last poll time |
| `error_details` | string | Last check error |
| timestamps | | inserted_at, updated_at |

Index: `(csr_id)`, unique index: `(csr_id, domain, method)` — one active challenge per domain per method per CSR.

### No CSR status change

DCV is tracked separately. CSR remains "verified" while DCV is in progress. The approval gate checks DCV status at approval time.

---

## 4. Cert Profile Integration

Add to `subject_dn_policy` map:

```json
{
  "require_dcv": true,
  "dcv_timeout_hours": 24,
  "allowed_domains": ["*.example.com"]
}
```

- `require_dcv: true` — officer must complete DCV before approving
- `require_dcv: false` (default) — DCV is optional, officer can approve without it
- `dcv_timeout_hours` — challenge window (default 24, configurable 1-168)

---

## 5. RA Engine Modules

### DcvChallenge module

```elixir
PkiRaEngine.DcvChallenge
  .create(tenant_id, csr_id, domain, method, initiated_by, timeout_hours)
  .verify(tenant_id, challenge_id)           # immediate check
  .get_for_csr(tenant_id, csr_id)            # list challenges for a CSR
  .check_dcv_passed(tenant_id, csr_id)       # returns :ok or {:error, :dcv_not_passed}
  .expire_overdue(tenant_id)                 # sweep expired challenges
```

### DcvPoller GenServer

- Runs every 5 minutes
- Queries pending challenges where `expires_at > now`
- For each: call `verify`, update status
- Sweep expired: set status "expired"
- Broadcast via PubSub: `"dcv:<csr_id>"` topic

### DcvVerifier (HTTP-01 + DNS-01)

```elixir
PkiRaEngine.DcvVerifier
  .check_http_01(domain, token, token_value)   # → :ok | {:error, reason}
  .check_dns_01(domain, token_value)           # → :ok | {:error, reason}
```

Uses `Req` for HTTP, `:inet_res` for DNS. Both with timeouts and error handling.

---

## 6. API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `POST /api/v1/csr/:id/dcv` | Start DCV challenge | Body: `{"method": "http-01"}` |
| `POST /api/v1/csr/:id/dcv/verify` | Trigger immediate check | No body |
| `GET /api/v1/csr/:id/dcv` | Get DCV status | Returns challenge(s) |

---

## 7. RA Portal UI

### CsrsLive modifications

**For verified CSRs:**
- "Start DCV" button (if cert profile has `require_dcv: true`)
- Method selector: HTTP-01 / DNS-01
- After starting: show challenge details panel:
  - For HTTP-01: "Place this content at `http://<domain>/.well-known/pki-validation/<token>`"
  - For DNS-01: "Add TXT record `_pki-validation.<domain>` with value `<token_value>`"
  - Copy-to-clipboard buttons for token and instructions
- Status indicator: pending (spinner), passed (green check), expired (red)
- "Verify Now" button for immediate check
- Attempts count and last error

**Approval gate:**
- When cert profile requires DCV, "Approve" button is disabled until DCV passes
- Show: "DCV required — complete domain validation before approving"

---

## 8. Approval Gate

Modify `approve_csr` to check DCV:

```elixir
def approve_csr(tenant_id, csr_id, reviewer_user_id) do
  with {:ok, csr} <- get_csr(tenant_id, csr_id),
       :ok <- check_transition(csr.status, "approved"),
       :ok <- check_dcv_requirement(tenant_id, csr) do
    # ... existing approval logic
  end
end

defp check_dcv_requirement(tenant_id, csr) do
  case CertProfileConfig.get_profile(tenant_id, csr.cert_profile_id) do
    {:ok, profile} ->
      policy = profile.subject_dn_policy || %{}
      if policy["require_dcv"] == true do
        DcvChallenge.check_dcv_passed(tenant_id, csr.id)
      else
        :ok
      end
    _ -> :ok
  end
end
```

---

## 9. Security

- Tokens are cryptographically random (32 bytes)
- Token values are domain-bound (SHA-256 of token + domain)
- HTTP-01 follows redirects only to same domain
- DNS lookup uses system resolver (no spoofable custom server)
- Challenges expire — no indefinite validity
- Each CSR gets its own challenge — no reuse across CSRs
- Audit logging: DCV started, verified, passed, expired

---

## 10. What's NOT In Scope

- **Email validation (admin@domain)** — deferred, adds mail infrastructure complexity
- **Wildcard certificate special handling** — DNS-01 works for wildcards by default
- **CAA record checking** — per BR §3.2.2.8, checking DNS CAA records is recommended but deferred
- **Multi-domain SAN validation** — validates CN only. SAN domain validation is future work.
- **ACME protocol** — DCV is internal to the RA, not exposed as ACME endpoints
