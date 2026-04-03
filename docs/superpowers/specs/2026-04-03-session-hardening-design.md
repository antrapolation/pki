# Session Hardening Design

**Date:** 2026-04-03
**Status:** Approved
**Goal:** Production-grade session management for CA compliance — idle timeout, session pinning, revocation, admin oversight, and anomaly detection.

---

## 1. Server-Side Session Registry

### Storage

ETS table per portal, owned by a GenServer started with the application:

- `:pki_ca_session_store`
- `:pki_ra_session_store`
- `:pki_platform_session_store`

Sessions are ephemeral — lost on restart, which forces re-authentication (acceptable and arguably desirable for a CA system).

### Session Record

```
{session_id, user_id, username, role, tenant_id, ip, user_agent, created_at, last_active_at}
```

### Lifecycle

- **Login:** Generate 32-byte random session ID (Base64-encoded). Insert into ETS. Store only `session_id` in the cookie (not the full user map).
- **Every request / LiveView event:** Look up session ID in ETS. If missing or expired, force logout. If valid, update `last_active_at`.
- **Logout:** Delete from ETS, clear cookie.
- **Forced logout:** Admin deletes entry from ETS. Next request from that session is rejected.
- **Cleanup:** GenServer sweeps every 5 minutes, removing sessions idle beyond the timeout threshold.

### Cookie Slimming

The session cookie stores only `session_id`. All user data (role, tenant, etc.) is looked up from ETS per request. ETS reads are microsecond-scale, so no performance concern.

---

## 2. Idle Timeout

### Configuration

Per-app, configurable:

```elixir
config :pki_ca_portal, :session_idle_timeout_ms, 30 * 60 * 1000
config :pki_ra_portal, :session_idle_timeout_ms, 30 * 60 * 1000
config :pki_platform_portal, :session_idle_timeout_ms, 30 * 60 * 1000
```

Default: 30 minutes. Can be tuned per portal.

### Server-Side Enforcement

The `RequireAuth` plug and LiveView `AuthHook` check `last_active_at` on every request/mount:

- If `now - last_active_at > idle_timeout`: delete session from ETS, redirect to `/login` with flash "Session expired due to inactivity", log `session_expired` to PlatformAudit.
- If valid: update `last_active_at` in ETS.

`last_active_at` is updated on real interactions — page loads, LiveView handle_event, handle_params. Not on artificial heartbeats.

### Client-Side Countdown Modal

A JavaScript hook (`SessionTimeout`) tracks user activity (mouse, keyboard, scroll, touch):

- **At 25 min idle:** Show a modal — "Your session will expire in 5 minutes due to inactivity. Click Continue to stay logged in." with a live countdown.
- **Continue button:** Sends a `keep_alive` LiveView event, which updates `last_active_at` in ETS. Resets the JS timer.
- **At 30 min idle (no action):** JS redirects to `/logout`.
- **Any user activity before 25 min:** Resets the JS timer silently. Does NOT ping the server — avoids unnecessary traffic.

The server-side GenServer sweep is the backstop for sessions where the browser was closed without logout.

---

## 3. IP / User-Agent Pinning

### On Login

Record `ip` and `user_agent` in the ETS session record.

### On Every Request

Checked in `RequireAuth` plug and `AuthHook` on mount:

**User-agent mismatch (strict):**
- Kill session immediately (delete from ETS)
- Redirect to login
- Log `session_hijack_suspected` to PlatformAudit (old + new user-agent, IP, user)
- Send async email notification to platform admins

**IP mismatch (advisory):**
- Continue session
- Update IP in ETS (prevents repeated notifications on subsequent requests)
- Log `session_ip_changed` to PlatformAudit (old + new IP, user)
- Send async email notification to platform admins

### IP Extraction

Reuse `client_ip` logic from the rate limiter plugs (trusted proxy + X-Forwarded-For right-to-left walk).

### LiveView Consideration

User-agent is captured during the initial WebSocket handshake (`connect_info`). It stays constant for the socket lifetime. Pinning checks happen at plug level (page loads) and LiveView mount — not on every socket event.

---

## 4. Suspicious Event Detection & Notifications

### Events

| Event | Severity | Session Action | Notification |
|-------|----------|----------------|--------------|
| User-agent change mid-session | Critical | Kill session | Email to platform admins |
| IP change mid-session | Warning | Continue, update IP | Email to platform admins |
| Login from new IP for user | Info | Continue | Email to platform admins |
| Multiple concurrent sessions for same user | Warning | Continue | Email to platform admins |

### Notification Mechanism

A `SessionSecurity` module per portal:

1. Log to PlatformAudit (synchronous — always happens)
2. Spawn `Task.Supervisor.async_nolink` to send email (fire-and-forget)
3. Fetch all platform admin emails via `AdminManagement.list_admins()`
4. Use existing `Mailer` + `EmailTemplates` infrastructure

### Email Format

- **Subject:** `[PKI Security] Suspicious session activity - {event_type}`
- **Body:** Who (username, role), what (event description), when (timestamp), where (IP, user-agent). Factual, no clickable links (avoids phishing patterns in security emails).

### "New IP" Detection

On login, query ETS for all sessions belonging to that user. If the current IP hasn't been seen in any active session, log as new-IP event. This is best-effort (ETS is ephemeral) — sufficient for real-time alerting without a permanent IP history table.

---

## 5. Admin Session Management UI

### Location

New LiveView page at `/sessions` on the Platform Portal. Only accessible to `platform_admin` role.

### Display

Table of all active sessions across all three portal ETS stores:

| User | Portal | Role | Tenant | IP | Login Time | Last Active | Actions |
|------|--------|------|--------|----|------------|-------------|---------|
| km1 | CA | key_manager | tenant-1 | 10.0.0.5 | 14:30 | 14:52 | [Force Logout] |
| admin | Platform | platform_admin | — | 127.0.0.1 | 13:00 | 14:55 | [Force Logout] |

### Force Logout

- Deletes session from ETS
- Logs `forced_logout` to PlatformAudit (who forced it, who was logged out)
- Next request from the affected user is rejected, redirected to login

### Cross-Portal Access

All portals run in one BEAM node. The Platform Portal LiveView reads all three ETS tables directly — no API calls needed.

### Real-Time Updates

The LiveView subscribes to PubSub topic `:session_events`. The session GenServer broadcasts on create, expire, and force-kill. Page updates automatically without polling.

---

## 6. Implementation Scope Per Component

### New Modules (per portal)

- `SessionStore` — GenServer owning ETS table, insert/lookup/delete/sweep/list
- `SessionSecurity` — suspicious event detection, async admin notification
- `SessionTimeout` JS hook — idle detection, countdown modal, keep-alive

### Modified Modules (per portal)

- `SessionController` — create session record on login, store only session_id in cookie
- `RequireAuth` plug — validate session from ETS, check timeout, check IP/UA pinning
- `AuthHook` (LiveView) — same validation as RequireAuth for LiveView mounts
- `Endpoint` — no changes needed (cookie config stays the same)
- `Router` (Platform Portal only) — add `/sessions` route

### New LiveView (Platform Portal only)

- `SessionsLive` — admin session management page

### Configuration

```elixir
# config.exs (per portal)
config :pki_ca_portal,
  session_idle_timeout_ms: 30 * 60 * 1000   # 30 minutes

# dev.exs (longer timeout + relaxed pinning for debugging)
config :pki_ca_portal,
  session_idle_timeout_ms: 120 * 60 * 1000,  # 2 hours in dev
  session_ip_pinning: false                   # disable IP change notifications in dev
```

---

## 7. What's NOT In Scope

- **Persistent session history** — ETS is ephemeral. No DB table for historical sessions. Audit log covers the compliance need.
- **Concurrent session limits** — Detect and notify, but don't block. Users may legitimately have multiple tabs.
- **Absolute session lifetime** — Only idle timeout, not a hard max duration. Can be added later if needed.
- **Per-user timeout configuration** — Same timeout for all users in a portal. Per-role or per-user overrides are future work.
- **Multi-node session replication** — Single BEAM node for now. Swap to Mnesia or DB backend when multi-node is needed.
