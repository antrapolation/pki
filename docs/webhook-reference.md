# Webhook Reference

API keys with a configured `webhook_url` and `webhook_secret` receive HTTP POST callbacks for CSR and certificate lifecycle events.

## Delivery

- **Method:** POST
- **Content-Type:** application/json
- **Retry:** 3 attempts with exponential backoff (1s, 5s, 30s)
- **Timeout:** 10 seconds per attempt
- **Success:** HTTP 2xx response

## Headers

| Header | Description |
|--------|-------------|
| `x-webhook-event` | Event name (e.g. `csr_submitted`) |
| `x-webhook-timestamp` | Delivery timestamp (`YYYY-MM-DD HH:MM:SS`) |
| `x-webhook-signature` | HMAC-SHA256 signature (`sha256=<hex>`) |
| `content-type` | `application/json` |

## Signature Verification

The signature covers `"{timestamp}.{body}"` using HMAC-SHA256 with the webhook secret.

```python
import hmac, hashlib

def verify(secret, timestamp, body, signature):
    expected = "sha256=" + hmac.new(
        secret.encode(), f"{timestamp}.{body}".encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

```javascript
const crypto = require('crypto');

function verify(secret, timestamp, body, signature) {
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${body}`)
    .digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}
```

## Base Payload

Every webhook includes these fields:

```json
{
  "event": "csr_submitted",
  "csr_id": "019d5c43-18af-7315-a452-dd7071c114dd",
  "subject_dn": "CN=example.com, O=Acme Corp",
  "status": "pending",
  "timestamp": "2026-04-05 15:30:00"
}
```

## Events

### csr_submitted

Fired when a new CSR is submitted via API.

```json
{
  "event": "csr_submitted",
  "csr_id": "019d5c43-18af-7315-a452-dd7071c114dd",
  "subject_dn": "CN=example.com, O=Acme Corp",
  "status": "pending",
  "timestamp": "2026-04-05 15:30:00"
}
```

### csr_validated

Fired after auto-validation completes (pass or fail).

```json
{
  "event": "csr_validated",
  "csr_id": "019d5c43-18af-7315-a452-dd7071c114dd",
  "subject_dn": "CN=example.com, O=Acme Corp",
  "status": "verified",
  "timestamp": "2026-04-05 15:30:01",
  "result": "verified"
}
```

`result` is either `"verified"` or `"rejected"`.

### csr_approved

Fired when an RA officer approves a CSR, or when auto-approve triggers.

```json
{
  "event": "csr_approved",
  "csr_id": "019d5c43-18af-7315-a452-dd7071c114dd",
  "subject_dn": "CN=example.com, O=Acme Corp",
  "status": "approved",
  "timestamp": "2026-04-05 15:31:00"
}
```

Auto-approved CSRs include an extra field:

```json
{
  "event": "csr_approved",
  "csr_id": "019d5c43-18af-7315-a452-dd7071c114dd",
  "subject_dn": "CN=example.com, O=Acme Corp",
  "status": "approved",
  "timestamp": "2026-04-05 15:30:02",
  "auto_approved": true
}
```

### csr_rejected

Fired when an RA officer rejects a CSR.

```json
{
  "event": "csr_rejected",
  "csr_id": "019d5c43-18af-7315-a452-dd7071c114dd",
  "subject_dn": "CN=example.com, O=Acme Corp",
  "status": "rejected",
  "timestamp": "2026-04-05 15:31:00",
  "reason": "Duplicate CSR for this domain"
}
```

### cert_issued

Fired when the CA signs the certificate and it is recorded as issued.

```json
{
  "event": "cert_issued",
  "csr_id": "019d5c43-18af-7315-a452-dd7071c114dd",
  "subject_dn": "CN=example.com, O=Acme Corp",
  "status": "issued",
  "timestamp": "2026-04-05 15:31:05",
  "serial_number": "ab12cd34ef567890"
}
```

### cert_revoked

Fired when a certificate is revoked. Delivered via the originating CSR's API key.

```json
{
  "event": "cert_revoked",
  "csr_id": "019d5c43-18af-7315-a452-dd7071c114dd",
  "subject_dn": "CN=example.com, O=Acme Corp",
  "status": "issued",
  "timestamp": "2026-04-05 16:00:00",
  "reason": "keyCompromise"
}
```

## Event Flow

```
CSR submitted ─── csr_submitted
       │
       ▼
Auto-validation ── csr_validated (result: verified | rejected)
       │
       ▼
Officer review ─── csr_approved  (or csr_rejected with reason)
  (or auto-approve)  (auto_approved: true if auto)
       │
       ▼
CA signing ──────── cert_issued (serial_number)
       │
       ▼
Revocation ──────── cert_revoked (reason)
(if needed)
```

## Configuration

Set `webhook_url` (HTTPS required) when creating or editing an API key. A `webhook_secret` is auto-generated on first configuration. The secret is shown once at key creation and used for all HMAC signatures.

Only CSRs submitted using that API key will trigger webhooks. CSRs submitted via the portal (internal auth) do not trigger webhooks.
