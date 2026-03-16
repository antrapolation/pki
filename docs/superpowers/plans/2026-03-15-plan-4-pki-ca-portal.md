# Plan 4: pki_ca_portal — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the CA Admin Portal — Phoenix LiveView web interface for managing the CA engine (user management, keystore config, key ceremony, audit log viewer).

**Architecture:** Phoenix LiveView application with no own database. All data operations go through `pki_ca_engine` via a client module (simulating RPC). LiveView provides real-time UI for key ceremonies and audit log streaming. Authentication will use SSDID (stubbed for now with session-based auth).

**Tech Stack:** Elixir, Phoenix, Phoenix LiveView, Tailwind CSS

**Spec Reference:** `docs/superpowers/specs/2026-03-15-pqc-ca-system-design.md` — Section 3.1

---

## Chunk 1: Project Scaffold

### Task 1: Create Phoenix LiveView project

- [ ] **Step 1: Generate project**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src
mix phx.new pki_ca_portal --no-ecto --no-mailer
cd pki_ca_portal
```

If `phx.new` is unavailable, create manually with Phoenix + LiveView deps.

- [ ] **Step 2: Configure**

No database — this portal reads/writes through the CA engine. Add a CA engine client module that will later use RPC but for now provides a local API facade.

- [ ] **Step 3: Verify and commit**

```bash
mix deps.get && mix compile
git init && git add -A && git commit -m "feat: scaffold pki_ca_portal with Phoenix LiveView"
```

---

## Chunk 2: CA Engine Client + Auth

### Task 2: CA Engine Client Module

**Files:**
- Create: `lib/pki_ca_portal/ca_engine_client.ex`
- Create: `test/pki_ca_portal/ca_engine_client_test.exs`

A client module that abstracts communication with `pki_ca_engine`. For now it's a behaviour with a configurable implementation — test impl returns mock data, production impl will use Erlang RPC.

```elixir
defmodule PkiCaPortal.CaEngineClient do
  @moduledoc """
  Client interface to pki_ca_engine.
  Delegates to configured implementation (mock for dev/test, RPC for prod).
  """

  @callback list_users(ca_instance_id :: integer()) :: {:ok, [map()]} | {:error, term()}
  @callback create_user(ca_instance_id :: integer(), attrs :: map()) :: {:ok, map()} | {:error, term()}
  @callback list_keystores(ca_instance_id :: integer()) :: {:ok, [map()]} | {:error, term()}
  @callback list_issuer_keys(ca_instance_id :: integer()) :: {:ok, [map()]} | {:error, term()}
  @callback get_engine_status(ca_instance_id :: integer()) :: {:ok, map()} | {:error, term()}
  @callback initiate_ceremony(ca_instance_id :: integer(), params :: map()) :: {:ok, map()} | {:error, term()}
  @callback list_ceremonies(ca_instance_id :: integer()) :: {:ok, [map()]} | {:error, term()}
  @callback query_audit_log(filters :: keyword()) :: {:ok, [map()]} | {:error, term()}

  def impl, do: Application.get_env(:pki_ca_portal, :ca_engine_client, PkiCaPortal.CaEngineClient.Mock)

  def list_users(ca_instance_id), do: impl().list_users(ca_instance_id)
  def create_user(ca_instance_id, attrs), do: impl().create_user(ca_instance_id, attrs)
  def list_keystores(ca_instance_id), do: impl().list_keystores(ca_instance_id)
  def list_issuer_keys(ca_instance_id), do: impl().list_issuer_keys(ca_instance_id)
  def get_engine_status(ca_instance_id), do: impl().get_engine_status(ca_instance_id)
  def initiate_ceremony(ca_instance_id, params), do: impl().initiate_ceremony(ca_instance_id, params)
  def list_ceremonies(ca_instance_id), do: impl().list_ceremonies(ca_instance_id)
  def query_audit_log(filters), do: impl().query_audit_log(filters)
end
```

Create a Mock implementation that returns realistic test data.

TDD → commit: `git add -A && git commit -m "feat: add CA engine client with mock implementation"`

---

### Task 3: Session-based Auth (SSDID stub)

**Files:**
- Create: `lib/pki_ca_portal_web/plugs/auth_plug.ex`
- Create: `lib/pki_ca_portal_web/controllers/session_controller.ex`

Simple session-based login for development. In production, this will be replaced by SSDID credential verification.

- Login page with DID + role selection (dev mode)
- Session stores: current_user (did, role, ca_instance_id)
- Auth plug checks session, redirects to login if not authenticated
- Logout clears session

TDD → commit: `git add -A && git commit -m "feat: add session-based auth stub for development"`

---

## Chunk 3: LiveView Pages

### Task 4: Dashboard LiveView

**Files:**
- Create: `lib/pki_ca_portal_web/live/dashboard_live.ex`

Main dashboard showing:
- CA engine status (running/stopped)
- Active issuer keys count
- Recent ceremonies
- Quick actions (start ceremony, manage users)

Uses `CaEngineClient` for data.

TDD → commit: `git add -A && git commit -m "feat: add dashboard LiveView"`

---

### Task 5: User Management LiveView

**Files:**
- Create: `lib/pki_ca_portal_web/live/users_live.ex`
- Create: `lib/pki_ca_portal_web/live/user_form_component.ex`

LiveView for:
- List users with role filter
- Create new user (form with DID, display_name, role dropdown)
- Edit user (display_name, status)
- Suspend user

TDD → commit: `git add -A && git commit -m "feat: add user management LiveView"`

---

### Task 6: Keystore Management LiveView

**Files:**
- Create: `lib/pki_ca_portal_web/live/keystores_live.ex`

LiveView for:
- List configured keystores
- Configure new keystore (type: software/HSM, config)
- Status indicator (active/inactive)

TDD → commit: `git add -A && git commit -m "feat: add keystore management LiveView"`

---

### Task 7: Key Ceremony LiveView

**Files:**
- Create: `lib/pki_ca_portal_web/live/ceremony_live.ex`
- Create: `lib/pki_ca_portal_web/live/ceremony_initiate_component.ex`

The most interactive page:
- Initiate ceremony form (algorithm, keystore, threshold K/N, domain info)
- Real-time participant list (LiveView updates)
- Share distribution progress
- Ceremony completion status

TDD → commit: `git add -A && git commit -m "feat: add key ceremony LiveView"`

---

### Task 8: Audit Log Viewer LiveView

**Files:**
- Create: `lib/pki_ca_portal_web/live/audit_log_live.ex`

LiveView for:
- List audit events with filters (action, actor, resource, date range)
- Real-time streaming of new events
- Event detail modal

TDD → commit: `git add -A && git commit -m "feat: add audit log viewer LiveView"`

---

## Summary

| Module | Responsibility |
|--------|----------------|
| `PkiCaPortal.CaEngineClient` | Abstracted client to CA engine (mock/RPC) |
| `DashboardLive` | CA status overview + quick actions |
| `UsersLive` | User CRUD with role management |
| `KeystoresLive` | Keystore configuration |
| `CeremonyLive` | Key ceremony initiation + real-time progress |
| `AuditLogLive` | Audit event viewer with filters |
| `AuthPlug` | Session-based auth (SSDID stub) |

**No database** — all operations via CaEngineClient.

**Next plan:** Plan 5 — `pki_ra_portal`
