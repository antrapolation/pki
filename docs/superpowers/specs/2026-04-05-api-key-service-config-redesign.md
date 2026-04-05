# API Key Management & Service Config Redesign

## Overview

Redesign API Key Management into a production-grade access control system for external and internal API consumers. Simplify Service Configs to focus solely on certificate extension endpoints. Add cert profile approval modes (auto/manual) and webhook notifications.

**Target users:**
- **RA Admin** — creates and manages API keys, configures services
- **External customers** — use Client Keys to submit CSRs programmatically
- **Internal systems** — use Service Keys for automation with broader access

---

## 1. API Key — New Schema

### Key Types

| Type | Permissions | Use Case |
|---|---|---|
| **client** | submit_csr, view_csr_status, view_certificates | External customer systems |
| **service** | All client permissions + revoke_certificate | Internal automation |

### Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | binary_id | Auto | UUIDv7 |
| `hashed_key` | string | Yes | SHA3-256 hash (raw key shown once at creation) |
| `label` | string | Yes | Human-readable name, max 100 chars |
| `key_type` | string | Yes | `"client"` or `"service"` |
| `status` | string | Yes | `"active"` or `"revoked"`, default `"active"` |
| `ra_user_id` | binary_id | Yes | Owner — the RA user this key belongs to |
| `ra_instance_id` | binary_id | No | Optional RA instance association |
| `allowed_profile_ids` | array of string | Yes | Cert profile IDs this key can submit against (at least one) |
| `ip_whitelist` | array of string | No | CIDR list — only accept from these IPs. Empty = allow all |
| `rate_limit` | integer | Yes | Requests per minute, default 60, min 1, max 10000 |
| `expiry` | utc_datetime | Yes | Mandatory expiry date — no perpetual keys |
| `webhook_url` | string | No | HTTPS URL for event callbacks |
| `webhook_secret` | string | No | HMAC secret for webhook signature verification |
| `revoked_at` | utc_datetime | No | Timestamp when revoked |
| `inserted_at` | utc_datetime | Auto | |
| `updated_at` | utc_datetime | Auto | |

### Migration

New migration to add columns to existing `ra_api_keys` table:
- `key_type` (string, default "client", not null)
- `allowed_profile_ids` (jsonb, default [])
- `ip_whitelist` (jsonb, default [])
- `webhook_url` (string, nullable)
- `webhook_secret` (string, nullable)

Existing `rate_limit` and `expiry` fields already exist. `label` already exists.

---

## 2. Per-Key Rate Limiting

### Enforcement

Replace/extend the current global IP-based `RateLimitPlug` with per-key enforcement in `AuthPlug`:

```
Request arrives with Bearer token
    → AuthPlug verifies key
    → Check IP against key.ip_whitelist (if configured)
    → Check rate limit: Hammer.check_rate("api_key:#{key.id}", 60_000, key.rate_limit)
    → Check key_type permissions against requested route
    → Proceed or reject
```

### Rate Limit Response

When exceeded:
```json
HTTP 429
{
  "error": "rate_limited",
  "retry_after": 60,
  "limit": 60,
  "message": "Rate limit exceeded. Try again in 60 seconds."
}
```

### IP Whitelist Enforcement

When `ip_whitelist` is non-empty:
- Extract client IP (respecting X-Forwarded-For with trusted proxies)
- Check if IP matches any CIDR in the whitelist
- Reject with 403 if not matched:

```json
HTTP 403
{
  "error": "ip_not_allowed",
  "message": "Request from this IP address is not permitted."
}
```

---

## 3. Key Type Permission Enforcement

In `RbacPlug` or a new `ApiKeyScopePlug`, check the key type against the route:

| Route | client | service |
|---|---|---|
| `POST /csr` | Yes | Yes |
| `GET /csr` | Own CSRs only | All |
| `GET /csr/:id` | Own CSRs only | All |
| `GET /certificates` | Own certs only | All |
| `POST /certificates/:serial/revoke` | No | Yes |
| `POST /csr/:id/dcv` | No | Yes |
| All other routes | No | No |

"Own CSRs" means CSRs submitted by the same API key (tracked via a new `submitted_by_key_id` field on `csr_requests`).

---

## 4. Cert Profile — Approval Mode

### New Fields

Add to `cert_profiles` schema:

| Field | Type | Default | Description |
|---|---|---|---|
| `approval_mode` | string | `"manual"` | `"auto"` or `"manual"` |

### Auto-Approve Flow

When `approval_mode == "auto"`:

```
CSR submitted
    → auto-validate (structural checks, key strength, DN policy)
    → IF validation fails → rejected (no human touch)
    → IF profile requires DCV → DCV must pass first
    → IF all validation passes AND DCV passes (or not required)
        → auto-forward to CA for signing
        → cert issued
    → IF DCV fails → stays in verified, awaiting DCV
```

When `approval_mode == "manual"` (current behavior):

```
CSR submitted
    → auto-validate
    → IF validation passes → status: verified (queued for officer)
    → Officer reviews → approves/rejects
    → IF approved → forward to CA
```

### Engine Changes

In `CsrValidation.validate_csr/2`, after successful validation:
- Check profile's `approval_mode`
- If `"auto"` and DCV passes (or not required): auto-approve and forward to CA
- If `"auto"` and DCV required but not passed: stay in `verified` (DCV poller will check)
- If `"manual"`: current behavior (officer queue)

---

## 5. Webhook Notifications

### Events

| Event | Trigger | Payload |
|---|---|---|
| `csr_submitted` | CSR created | `{event, csr_id, subject_dn, status, profile_id, submitted_at}` |
| `csr_validated` | Auto-validation complete | `{event, csr_id, result: "verified"/"rejected", reason}` |
| `csr_approved` | Officer approves | `{event, csr_id, approved_by, approved_at}` |
| `csr_rejected` | Officer rejects | `{event, csr_id, rejected_by, reason, rejected_at}` |
| `cert_issued` | Certificate signed by CA | `{event, csr_id, serial_number, cert_pem, subject_dn, not_before, not_after}` |
| `cert_revoked` | Certificate revoked | `{event, serial_number, reason, revoked_at}` |

### Delivery

- `POST` to `webhook_url` with JSON body
- Headers:
  - `Content-Type: application/json`
  - `X-Webhook-Signature: HMAC-SHA256(webhook_secret, body)`
  - `X-Webhook-Event: cert_issued`
  - `X-Webhook-Timestamp: ISO8601`
- Retry: 3 attempts with exponential backoff (1s, 5s, 30s)
- Timeout: 10 seconds per attempt
- All webhook deliveries logged to audit trail (event, URL, status code, attempt count)

### Implementation

New module: `PkiRaEngine.WebhookDelivery`
- Looks up API key's `webhook_url` from the CSR's `submitted_by_key_id`
- If webhook_url is configured, delivers asynchronously via `Task.Supervisor`
- Stores delivery status in audit log

---

## 6. Service Configs — Simplified

### Remove from Service Configs
- `rate_limit` — moved to per-API-key
- `ip_whitelist` — moved to per-API-key
- `ip_blacklist` — moved to per-API-key
- `credentials` — unused
- `ca_engine_ref` — unused

### Remaining Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | binary_id | Auto | |
| `service_type` | string | Yes | `"ocsp_responder"`, `"crl_distribution"`, `"tsa"` |
| `url` | string | Yes | Endpoint URL |
| `port` | integer | No | Port number |
| `connection_security` | string | No | `"tls"`, `"plain"` |
| `status` | string | Yes | `"active"`, `"inactive"` |

### Rename

Rename "Service Configs" to **"Validation Endpoints"** in the sidebar and page title. These configure the URLs embedded in issued certificates as extensions (AIA, CDP, etc.), not API access control.

### Normalize service_types

Replace inconsistent casing:
- `"OCSP Responder"` → `"ocsp_responder"`
- `"CRL Distribution"` → `"crl_distribution"`
- `"TSA"` → `"tsa"`

---

## 7. Portal UI — API Key Management Redesign

### Create API Key Form

Multi-section form:

**Section 1: Basic Info**
- Label (text, required, max 100)
- Key Type (radio: Client Key / Service Key)
- Assign to User (dropdown: list of active RA users)
- Expiry Date (date picker, required, min: tomorrow, max: 2 years from now)

**Section 2: Access Control**
- Allowed Certificate Profiles (multi-select checkboxes: list of active profiles)
- IP Whitelist (textarea: one CIDR per line, optional)
- Rate Limit (number input: requests/minute, default 60)

**Section 3: Webhook (optional, collapsible)**
- Webhook URL (text, must start with https://)
- Auto-generated webhook secret (shown once, like the API key)

**On Create:**
- Show the raw API key in a modal (one-time display, copy button)
- If webhook configured, show the webhook secret too

### API Key Table Columns

| Column | Content |
|---|---|
| Label | Key name |
| Type | Badge: "Client" (blue) / "Service" (purple) |
| Owner | RA user display name |
| Profiles | Count badge: "3 profiles" |
| Rate Limit | e.g., "60/min" |
| Expiry | Date, with warning badge if <30 days |
| Status | Active (green) / Revoked (grey) / Expired (red) |
| Actions | View details, Revoke |

### Key Detail View

Expandable row or side panel showing:
- All fields from creation
- IP whitelist (formatted)
- Allowed profiles (listed)
- Webhook URL (masked)
- Usage stats: total requests, last used, requests today

---

## 8. Portal UI — Validation Endpoints (renamed Service Configs)

### Simplified Form

- Service Type (dropdown: OCSP Responder, CRL Distribution, TSA)
- URL (text, required)
- Port (number, optional)
- Connection Security (dropdown: TLS / Plain)

No rate_limit, no IP whitelist, no credentials — those moved to API keys.

### Sidebar

Rename "Service Configs" → "Validation Endpoints" in the sidebar under CONFIGURATION.

---

## 9. CSR Tracking — `submitted_by_key_id`

Add field to `csr_requests` schema:

| Field | Type | Description |
|---|---|---|
| `submitted_by_key_id` | binary_id, nullable | API key that submitted this CSR (null if submitted via portal) |

This enables:
- "Own CSRs only" filtering for client keys
- Webhook lookup (find webhook URL from CSR's API key)
- Audit trail (which key submitted which CSR)

---

## 10. Audit Logging

All webhook events logged to `PlatformAudit`:

| Action | Details |
|---|---|
| `webhook_delivered` | `{event, url, status_code, attempt}` |
| `webhook_failed` | `{event, url, error, attempts_exhausted}` |
| `api_key_rate_limited` | `{key_id, ip, limit}` |
| `api_key_ip_rejected` | `{key_id, ip, whitelist}` |
| `api_key_scope_denied` | `{key_id, route, key_type}` |

Register these new actions in `PlatformAuditEvent.@actions`.

---

## 11. Summary of Changes

### New Files
- `PkiRaEngine.WebhookDelivery` — webhook dispatch + retry
- `PkiRaEngine.ApiKeyScopePlug` — key type permission enforcement
- Migration: add columns to `ra_api_keys`
- Migration: add `approval_mode` to `cert_profiles`
- Migration: add `submitted_by_key_id` to `csr_requests`
- Migration: add `status` to `service_configs`, normalize types

### Modified Files
- `RaApiKey` schema — new fields
- `CertProfile` schema — add `approval_mode`
- `CsrRequest` schema — add `submitted_by_key_id`
- `ServiceConfig` schema — simplified, add status
- `ApiKeyManagement` — enforce rate limit, IP whitelist
- `AuthPlug` — per-key rate limiting + IP check
- `CsrValidation` — auto-approve flow
- `CsrController` — record `submitted_by_key_id`
- Portal: `api_keys_live.ex` — full form redesign
- Portal: `service_configs_live.ex` — simplified, renamed
- Portal: `cert_profiles_live.ex` — add approval_mode toggle
- Portal: `layouts.ex` — rename sidebar item
- `PlatformAuditEvent` — register new actions
