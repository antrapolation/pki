# Session Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add server-side session management with idle timeout, IP/user-agent pinning, suspicious event notifications, and admin session management UI across all three portals.

**Architecture:** ETS-backed session registry per portal, owned by a GenServer. Cookie stores only session_id; user data looked up from ETS per request. RequireAuth plug and LiveView AuthHook validate sessions, enforce timeout, and check IP/UA pinning. Client-side JS hook provides idle countdown modal. Platform Portal gets an admin sessions page.

**Tech Stack:** Elixir/Phoenix, ETS, GenServer, Phoenix.PubSub, LiveView hooks, JavaScript

---

## File Structure

### New Files (per portal pattern — shown for CA portal, replicate for RA + Platform)

| File | Responsibility |
|------|----------------|
| `src/pki_ca_portal/lib/pki_ca_portal/session_store.ex` | GenServer + ETS: insert, lookup, delete, sweep, list, touch |
| `src/pki_ca_portal/lib/pki_ca_portal/session_security.ex` | Suspicious event detection, async admin email notification |
| `src/pki_ca_portal/assets/js/session_timeout.js` | Client-side idle detection, countdown modal, keep-alive |
| `src/pki_ca_portal/test/pki_ca_portal/session_store_test.exs` | Unit tests for SessionStore |
| `src/pki_ca_portal/test/pki_ca_portal/session_security_test.exs` | Unit tests for SessionSecurity |

### New Files (Platform Portal only)

| File | Responsibility |
|------|----------------|
| `src/pki_platform_portal/lib/pki_platform_portal_web/live/sessions_live.ex` | Admin session management page |

### Modified Files (per portal)

| File | Changes |
|------|---------|
| `lib/<app>/application.ex` | Add SessionStore + Task.Supervisor to children |
| `lib/<app>_web/plugs/require_auth.ex` | Validate session from ETS, check timeout + IP/UA pinning |
| `lib/<app>_web/live/auth_hook.ex` | Same validation as RequireAuth for LiveView mounts |
| `lib/<app>_web/controllers/session_controller.ex` | Create ETS session on login, store only session_id in cookie |
| `lib/<app>_web/endpoint.ex` | Add `peer` to connect_info for IP in LiveView |
| `assets/js/app.js` | Register SessionTimeout hook |
| `config/config.exs` | Add session_idle_timeout_ms default |
| `config/dev.exs` | Add relaxed timeout + disable IP pinning |

### Modified Files (Platform Portal only)

| File | Changes |
|------|---------|
| `lib/pki_platform_portal_web/router.ex` | Add `/sessions` route |
| `lib/pki_platform_portal_web/live/auth_hook.ex` | Add SessionsLive to allowed pages |

---

### Task 1: SessionStore GenServer for CA Portal

**Files:**
- Create: `src/pki_ca_portal/lib/pki_ca_portal/session_store.ex`
- Create: `src/pki_ca_portal/test/pki_ca_portal/session_store_test.exs`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/application.ex`
- Modify: `src/pki_ca_portal/config/config.exs`
- Modify: `src/pki_ca_portal/config/dev.exs`

- [ ] **Step 1: Write SessionStore tests**

```elixir
# src/pki_ca_portal/test/pki_ca_portal/session_store_test.exs
defmodule PkiCaPortal.SessionStoreTest do
  use ExUnit.Case, async: false

  alias PkiCaPortal.SessionStore

  setup do
    # Clear all sessions before each test
    SessionStore.clear_all()
    :ok
  end

  describe "create/1" do
    test "creates a session and returns session_id" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1",
        username: "admin",
        role: "ca_admin",
        tenant_id: "tenant-1",
        ip: "127.0.0.1",
        user_agent: "Mozilla/5.0"
      })

      assert is_binary(session_id)
      assert byte_size(session_id) > 20
    end

    test "created session can be looked up" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1",
        username: "admin",
        role: "ca_admin",
        tenant_id: "tenant-1",
        ip: "127.0.0.1",
        user_agent: "Mozilla/5.0"
      })

      {:ok, session} = SessionStore.lookup(session_id)
      assert session.user_id == "user-1"
      assert session.username == "admin"
      assert session.role == "ca_admin"
      assert session.tenant_id == "tenant-1"
      assert session.ip == "127.0.0.1"
      assert session.user_agent == "Mozilla/5.0"
      assert %DateTime{} = session.created_at
      assert %DateTime{} = session.last_active_at
    end
  end

  describe "lookup/1" do
    test "returns error for nonexistent session" do
      assert {:error, :not_found} = SessionStore.lookup("nonexistent")
    end
  end

  describe "touch/1" do
    test "updates last_active_at" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })

      {:ok, before} = SessionStore.lookup(session_id)
      Process.sleep(10)
      :ok = SessionStore.touch(session_id)
      {:ok, after_touch} = SessionStore.lookup(session_id)

      assert DateTime.compare(after_touch.last_active_at, before.last_active_at) == :gt
    end
  end

  describe "update_ip/2" do
    test "updates the IP address" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })

      :ok = SessionStore.update_ip(session_id, "10.0.0.5")
      {:ok, session} = SessionStore.lookup(session_id)
      assert session.ip == "10.0.0.5"
    end
  end

  describe "delete/1" do
    test "removes the session" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })

      :ok = SessionStore.delete(session_id)
      assert {:error, :not_found} = SessionStore.lookup(session_id)
    end
  end

  describe "list_all/0" do
    test "returns all active sessions" do
      {:ok, _} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })
      {:ok, _} = SessionStore.create(%{
        user_id: "user-2", username: "km1", role: "key_manager",
        tenant_id: "t1", ip: "10.0.0.2", user_agent: "Chrome"
      })

      sessions = SessionStore.list_all()
      assert length(sessions) == 2
    end
  end

  describe "list_by_user/1" do
    test "returns sessions for a specific user" do
      {:ok, _} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })
      {:ok, _} = SessionStore.create(%{
        user_id: "user-2", username: "km1", role: "key_manager",
        tenant_id: "t1", ip: "10.0.0.2", user_agent: "Chrome"
      })

      sessions = SessionStore.list_by_user("user-1")
      assert length(sessions) == 1
      assert hd(sessions).username == "admin"
    end
  end

  describe "sweep/1" do
    test "removes sessions idle beyond timeout" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })

      # Sweep with 0ms timeout — should remove everything
      swept = SessionStore.sweep(0)
      assert swept >= 1
      assert {:error, :not_found} = SessionStore.lookup(session_id)
    end

    test "preserves sessions within timeout" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })

      # Sweep with very long timeout — should keep everything
      swept = SessionStore.sweep(999_999_999)
      assert swept == 0
      assert {:ok, _} = SessionStore.lookup(session_id)
    end
  end

  describe "expired?/2" do
    test "returns true for sessions idle beyond timeout" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })

      # 0ms timeout means immediately expired
      assert SessionStore.expired?(session_id, 0)
    end

    test "returns false for fresh sessions" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })

      refute SessionStore.expired?(session_id, 999_999_999)
    end
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd src/pki_ca_portal && mix test test/pki_ca_portal/session_store_test.exs --trace`
Expected: Compilation error — SessionStore module does not exist

- [ ] **Step 3: Implement SessionStore**

```elixir
# src/pki_ca_portal/lib/pki_ca_portal/session_store.ex
defmodule PkiCaPortal.SessionStore do
  @moduledoc """
  ETS-backed server-side session registry.

  Owns an ETS table that maps session_id to session data.
  Runs periodic cleanup of expired sessions.
  Broadcasts session events via PubSub for admin UI.
  """

  use GenServer
  require Logger

  @table :pki_ca_session_store
  @sweep_interval_ms 5 * 60 * 1000
  @pubsub PkiCaPortal.PubSub
  @pubsub_topic "session_events"

  # --- Client API ---

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def create(attrs) do
    session_id = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    now = DateTime.utc_now()

    record = %{
      session_id: session_id,
      user_id: attrs.user_id,
      username: attrs.username,
      role: attrs.role,
      tenant_id: attrs.tenant_id,
      ip: attrs.ip,
      user_agent: attrs.user_agent,
      created_at: now,
      last_active_at: now
    }

    :ets.insert(@table, {session_id, record})
    broadcast(:session_created, record)
    {:ok, session_id}
  end

  def lookup(session_id) do
    case :ets.lookup(@table, session_id) do
      [{^session_id, record}] -> {:ok, record}
      [] -> {:error, :not_found}
    end
  end

  def touch(session_id) do
    case :ets.lookup(@table, session_id) do
      [{^session_id, record}] ->
        updated = %{record | last_active_at: DateTime.utc_now()}
        :ets.insert(@table, {session_id, updated})
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  def update_ip(session_id, new_ip) do
    case :ets.lookup(@table, session_id) do
      [{^session_id, record}] ->
        updated = %{record | ip: new_ip, last_active_at: DateTime.utc_now()}
        :ets.insert(@table, {session_id, updated})
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  def delete(session_id) do
    case :ets.lookup(@table, session_id) do
      [{^session_id, record}] ->
        :ets.delete(@table, session_id)
        broadcast(:session_deleted, record)

      [] ->
        :ok
    end

    :ok
  end

  def list_all do
    :ets.tab2list(@table) |> Enum.map(fn {_id, record} -> record end)
  end

  def list_by_user(user_id) do
    list_all() |> Enum.filter(&(&1.user_id == user_id))
  end

  def expired?(session_id, timeout_ms) do
    case lookup(session_id) do
      {:ok, session} ->
        elapsed = DateTime.diff(DateTime.utc_now(), session.last_active_at, :millisecond)
        elapsed > timeout_ms

      {:error, :not_found} ->
        true
    end
  end

  def sweep(timeout_ms) do
    now = DateTime.utc_now()

    expired =
      :ets.tab2list(@table)
      |> Enum.filter(fn {_id, record} ->
        DateTime.diff(now, record.last_active_at, :millisecond) > timeout_ms
      end)

    Enum.each(expired, fn {session_id, record} ->
      :ets.delete(@table, session_id)
      broadcast(:session_expired, record)
    end)

    length(expired)
  end

  def clear_all do
    :ets.delete_all_objects(@table)
    :ok
  end

  # --- GenServer Callbacks ---

  @impl true
  def init(_opts) do
    table = :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    schedule_sweep()
    {:ok, %{table: table}}
  end

  @impl true
  def handle_info(:sweep, state) do
    timeout_ms = Application.get_env(:pki_ca_portal, :session_idle_timeout_ms, 30 * 60 * 1000)
    count = sweep(timeout_ms)
    if count > 0, do: Logger.info("[session_store] Swept #{count} expired sessions")
    schedule_sweep()
    {:noreply, state}
  end

  defp schedule_sweep do
    Process.send_after(self(), :sweep, @sweep_interval_ms)
  end

  defp broadcast(event, session) do
    Phoenix.PubSub.broadcast(@pubsub, @pubsub_topic, {event, session})
  rescue
    _ -> :ok
  end
end
```

- [ ] **Step 4: Add SessionStore to application supervision tree**

In `src/pki_ca_portal/lib/pki_ca_portal/application.ex`, add to the children list before the Endpoint:

```elixir
    children = [
      PkiCaPortalWeb.Telemetry,
      {DNSCluster, query: Application.get_env(:pki_ca_portal, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: PkiCaPortal.PubSub},
      {Task.Supervisor, name: PkiCaPortal.TaskSupervisor},
      PkiCaPortal.SessionStore,
      PkiCaPortalWeb.Endpoint
    ]
```

- [ ] **Step 5: Add config defaults**

In `src/pki_ca_portal/config/config.exs`, add:

```elixir
config :pki_ca_portal,
  session_idle_timeout_ms: 30 * 60 * 1000
```

In `src/pki_ca_portal/config/dev.exs`, add:

```elixir
# Longer session timeout in dev to avoid being logged out during debugging
config :pki_ca_portal,
  session_idle_timeout_ms: 120 * 60 * 1000,
  session_ip_pinning: false
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd src/pki_ca_portal && mix test test/pki_ca_portal/session_store_test.exs --trace`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal/session_store.ex \
        src/pki_ca_portal/test/pki_ca_portal/session_store_test.exs \
        src/pki_ca_portal/lib/pki_ca_portal/application.ex \
        src/pki_ca_portal/config/config.exs \
        src/pki_ca_portal/config/dev.exs
git commit -m "feat(ca-portal): add ETS-backed SessionStore with sweep and PubSub"
```

---

### Task 2: Replicate SessionStore for RA Portal and Platform Portal

**Files:**
- Create: `src/pki_ra_portal/lib/pki_ra_portal/session_store.ex`
- Create: `src/pki_ra_portal/test/pki_ra_portal/session_store_test.exs`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/application.ex`
- Modify: `src/pki_ra_portal/config/config.exs`
- Modify: `src/pki_ra_portal/config/dev.exs`
- Create: `src/pki_platform_portal/lib/pki_platform_portal/session_store.ex`
- Create: `src/pki_platform_portal/test/pki_platform_portal/session_store_test.exs`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal/application.ex`
- Modify: `src/pki_platform_portal/config/config.exs`
- Modify: `src/pki_platform_portal/config/dev.exs`

- [ ] **Step 1: Create RA Portal SessionStore**

Copy the CA Portal `SessionStore` module, replacing:
- Module name: `PkiRaPortal.SessionStore`
- ETS table: `:pki_ra_session_store`
- PubSub: `PkiRaPortal.PubSub`
- App config key: `:pki_ra_portal`

- [ ] **Step 2: Create RA Portal SessionStore tests**

Copy the CA Portal test file, replacing:
- Module name: `PkiRaPortal.SessionStoreTest`
- Alias: `PkiRaPortal.SessionStore`

- [ ] **Step 3: Add RA Portal SessionStore to application.ex**

Add `{Task.Supervisor, name: PkiRaPortal.TaskSupervisor}` and `PkiRaPortal.SessionStore` to children in `src/pki_ra_portal/lib/pki_ra_portal/application.ex` before the Endpoint.

- [ ] **Step 4: Add RA Portal config**

In `src/pki_ra_portal/config/config.exs`:
```elixir
config :pki_ra_portal,
  session_idle_timeout_ms: 30 * 60 * 1000
```

In `src/pki_ra_portal/config/dev.exs`:
```elixir
config :pki_ra_portal,
  session_idle_timeout_ms: 120 * 60 * 1000,
  session_ip_pinning: false
```

- [ ] **Step 5: Create Platform Portal SessionStore**

Copy the CA Portal `SessionStore` module, replacing:
- Module name: `PkiPlatformPortal.SessionStore`
- ETS table: `:pki_platform_session_store`
- PubSub: `PkiPlatformPortal.PubSub`
- App config key: `:pki_platform_portal`

- [ ] **Step 6: Create Platform Portal SessionStore tests**

Copy the CA Portal test file, replacing:
- Module name: `PkiPlatformPortal.SessionStoreTest`
- Alias: `PkiPlatformPortal.SessionStore`

- [ ] **Step 7: Add Platform Portal SessionStore to application.ex**

Add `{Task.Supervisor, name: PkiPlatformPortal.TaskSupervisor}` and `PkiPlatformPortal.SessionStore` to children in `src/pki_platform_portal/lib/pki_platform_portal/application.ex` before the Endpoint.

- [ ] **Step 8: Add Platform Portal config**

In `src/pki_platform_portal/config/config.exs`:
```elixir
config :pki_platform_portal,
  session_idle_timeout_ms: 30 * 60 * 1000
```

In `src/pki_platform_portal/config/dev.exs`:
```elixir
config :pki_platform_portal,
  session_idle_timeout_ms: 120 * 60 * 1000,
  session_ip_pinning: false
```

- [ ] **Step 9: Run all SessionStore tests**

Run: `cd src/pki_ra_portal && mix test test/pki_ra_portal/session_store_test.exs --trace`
Run: `cd src/pki_platform_portal && mix test test/pki_platform_portal/session_store_test.exs --trace`
Expected: All pass

- [ ] **Step 10: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal/session_store.ex \
        src/pki_ra_portal/test/pki_ra_portal/session_store_test.exs \
        src/pki_ra_portal/lib/pki_ra_portal/application.ex \
        src/pki_ra_portal/config/config.exs \
        src/pki_ra_portal/config/dev.exs \
        src/pki_platform_portal/lib/pki_platform_portal/session_store.ex \
        src/pki_platform_portal/test/pki_platform_portal/session_store_test.exs \
        src/pki_platform_portal/lib/pki_platform_portal/application.ex \
        src/pki_platform_portal/config/config.exs \
        src/pki_platform_portal/config/dev.exs
git commit -m "feat(ra+platform): add SessionStore for RA and Platform portals"
```

---

### Task 3: Wire SessionStore into Login/Logout (CA Portal)

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_controller.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/endpoint.ex`

- [ ] **Step 1: Modify SessionController.create to create ETS session**

In `do_authenticate/5`, after the `{:ok, user, session_info}` match and rate limit bucket clear, replace the session setup. For the `true ->` branch (normal login):

```elixir
        true ->
            PkiPlatformEngine.PlatformAudit.log("login", %{
              actor_id: user[:id],
              actor_username: user[:username],
              tenant_id: tenant_id,
              portal: "ca",
              details: %{ca_instance_id: ca_instance_id}
            })

            ip = conn.remote_ip |> :inet.ntoa() |> to_string()
            ua = Plug.Conn.get_req_header(conn, "user-agent") |> List.first("")

            {:ok, session_id} = PkiCaPortal.SessionStore.create(%{
              user_id: user[:id],
              username: user[:username],
              role: user[:role],
              tenant_id: tenant_id,
              ip: ip,
              user_agent: ua
            })

            conn
            |> configure_session(renew: true)
            |> put_session(:session_id, session_id)
            |> put_session(:current_user, serialize_user(user, ca_instance_id))
            |> put_session(:tenant_id, tenant_id)
            |> put_session(:session_key, session_info[:session_key])
            |> put_session(:session_salt, session_info[:session_salt])
            |> redirect(to: "/")
```

Apply the same pattern to the `must_change_password ->` branch.

- [ ] **Step 2: Modify SessionController.delete to delete ETS session**

```elixir
  def delete(conn, _params) do
    if session_id = get_session(conn, :session_id) do
      PkiCaPortal.SessionStore.delete(session_id)
    end

    conn
    |> clear_session()
    |> redirect(to: "/login")
  end
```

- [ ] **Step 3: Add `peer` to endpoint connect_info for LiveView IP access**

In `src/pki_ca_portal/lib/pki_ca_portal_web/endpoint.ex`, update the socket line:

```elixir
  socket "/live", Phoenix.LiveView.Socket,
    websocket: [connect_info: [:peer, session: @session_options]],
    longpoll: [connect_info: [:peer, session: @session_options]]
```

- [ ] **Step 4: Compile and verify**

Run: `cd src/pki_ca_portal && mix compile`
Expected: Compiles with no errors from our changes

- [ ] **Step 5: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_controller.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/endpoint.ex
git commit -m "feat(ca-portal): wire SessionStore into login/logout flow"
```

---

### Task 4: Wire SessionStore into Login/Logout (RA + Platform Portals)

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/session_controller.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/endpoint.ex`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_controller.ex`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/endpoint.ex`

- [ ] **Step 1: RA Portal SessionController — create session on login**

Same pattern as Task 3 Step 1, using `PkiRaPortal.SessionStore`, `portal: "ra"`. RA portal's `create/2` directly calls `RaEngineClient.authenticate_with_session` — add the SessionStore.create call in the `true ->` branch and the `must_change_password ->` branch.

- [ ] **Step 2: RA Portal SessionController — delete session on logout**

Same pattern as Task 3 Step 2, using `PkiRaPortal.SessionStore`.

- [ ] **Step 3: RA Portal endpoint — add :peer to connect_info**

In `src/pki_ra_portal/lib/pki_ra_portal_web/endpoint.ex`:
```elixir
  socket "/live", Phoenix.LiveView.Socket,
    websocket: [connect_info: [:peer, session: @session_options]],
    longpoll: [connect_info: [:peer, session: @session_options]]
```

- [ ] **Step 4: Platform Portal SessionController — create session on login**

Same pattern. Platform Portal uses `PkiPlatformPortal.SessionStore`. Note: Platform Portal doesn't have `session_key`/`session_salt` — just store `session_id` and `current_user`.

- [ ] **Step 5: Platform Portal SessionController — delete session on logout**

Same pattern as Task 3 Step 2, using `PkiPlatformPortal.SessionStore`.

- [ ] **Step 6: Platform Portal endpoint — add :peer to connect_info**

In `src/pki_platform_portal/lib/pki_platform_portal_web/endpoint.ex`:
```elixir
  socket "/live", Phoenix.LiveView.Socket,
    websocket: [connect_info: [:peer, session: @session_options]],
    longpoll: [connect_info: [:peer, session: @session_options]]
```

- [ ] **Step 7: Compile all three**

Run: `cd src/pki_ra_portal && mix compile && cd ../pki_platform_portal && mix compile`
Expected: No errors from our changes

- [ ] **Step 8: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/controllers/session_controller.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/endpoint.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_controller.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/endpoint.ex
git commit -m "feat(ra+platform): wire SessionStore into login/logout flow"
```

---

### Task 5: RequireAuth Plug — Session Validation + Timeout + IP/UA Pinning (CA Portal)

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/plugs/require_auth.ex`

- [ ] **Step 1: Rewrite RequireAuth to validate from ETS**

```elixir
defmodule PkiCaPortalWeb.Plugs.RequireAuth do
  @moduledoc """
  Plug that validates the session from the server-side SessionStore.

  Checks:
  1. Session exists in ETS (not revoked/expired)
  2. Session is within idle timeout
  3. User-agent matches (strict — kills session on mismatch)
  4. IP matches (advisory — logs and updates on mismatch)
  """

  import Plug.Conn
  import Phoenix.Controller
  require Logger

  @app :pki_ca_portal

  def init(opts), do: opts

  def call(conn, _opts) do
    session_id = get_session(conn, :session_id)

    with {:ok, session_id} <- ensure_present(session_id),
         {:ok, session} <- PkiCaPortal.SessionStore.lookup(session_id),
         :ok <- check_timeout(session_id, session),
         :ok <- check_user_agent(conn, session_id, session),
         :ok <- check_ip(conn, session_id, session) do
      PkiCaPortal.SessionStore.touch(session_id)

      conn
      |> assign(:current_user, session_to_user(session))
      |> assign(:session_id, session_id)
    else
      {:error, :no_session} ->
        conn |> redirect(to: "/login") |> halt()

      {:error, :not_found} ->
        conn |> clear_session() |> redirect(to: "/login") |> halt()

      {:error, :expired} ->
        PkiCaPortal.SessionStore.delete(session_id)
        PkiPlatformEngine.PlatformAudit.log("session_expired", %{
          portal: "ca", details: %{session_id: session_id}
        })

        conn
        |> clear_session()
        |> put_flash(:error, "Session expired due to inactivity.")
        |> redirect(to: "/login")
        |> halt()

      {:error, :ua_mismatch} ->
        conn |> clear_session() |> redirect(to: "/login") |> halt()
    end
  end

  defp ensure_present(nil), do: {:error, :no_session}
  defp ensure_present(session_id), do: {:ok, session_id}

  defp check_timeout(session_id, session) do
    timeout_ms = Application.get_env(@app, :session_idle_timeout_ms, 30 * 60 * 1000)
    elapsed = DateTime.diff(DateTime.utc_now(), session.last_active_at, :millisecond)

    if elapsed > timeout_ms, do: {:error, :expired}, else: :ok
  end

  defp check_user_agent(conn, session_id, session) do
    current_ua = get_req_header(conn, "user-agent") |> List.first("")

    if current_ua == session.user_agent do
      :ok
    else
      Logger.warning("[session] UA mismatch for #{session.username}, killing session")
      PkiCaPortal.SessionStore.delete(session_id)

      PkiCaPortal.SessionSecurity.notify(:session_hijack_suspected, %{
        username: session.username,
        role: session.role,
        old_user_agent: session.user_agent,
        new_user_agent: current_ua,
        ip: session.ip,
        portal: "ca"
      })

      {:error, :ua_mismatch}
    end
  end

  defp check_ip(conn, session_id, session) do
    if not Application.get_env(@app, :session_ip_pinning, true) do
      :ok
    else
      current_ip = conn.remote_ip |> :inet.ntoa() |> to_string()

      if current_ip == session.ip do
        :ok
      else
        Logger.info("[session] IP changed for #{session.username}: #{session.ip} -> #{current_ip}")
        PkiCaPortal.SessionStore.update_ip(session_id, current_ip)

        PkiCaPortal.SessionSecurity.notify(:session_ip_changed, %{
          username: session.username,
          role: session.role,
          old_ip: session.ip,
          new_ip: current_ip,
          portal: "ca"
        })

        :ok
      end
    end
  end

  defp session_to_user(session) do
    %{
      id: session.user_id,
      username: session.username,
      role: session.role,
      tenant_id: session.tenant_id
    }
  end
end
```

- [ ] **Step 2: Compile and verify**

Run: `cd src/pki_ca_portal && mix compile`
Expected: Compiles (SessionSecurity doesn't exist yet but is only called, not referenced at compile time)

- [ ] **Step 3: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal_web/plugs/require_auth.ex
git commit -m "feat(ca-portal): RequireAuth validates ETS session with timeout + IP/UA pinning"
```

---

### Task 6: AuthHook — Session Validation for LiveView (CA Portal)

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/live/auth_hook.ex`

- [ ] **Step 1: Rewrite AuthHook to validate from ETS**

```elixir
defmodule PkiCaPortalWeb.Live.AuthHook do
  @moduledoc """
  LiveView on_mount hook that validates the session from the server-side SessionStore
  and enforces role-based access control.
  """

  import Phoenix.LiveView
  import Phoenix.Component

  @app :pki_ca_portal

  @role_pages %{
    "ca_admin" => :all,
    "key_manager" => [
      PkiCaPortalWeb.DashboardLive,
      PkiCaPortalWeb.CaInstancesLive,
      PkiCaPortalWeb.HsmDevicesLive,
      PkiCaPortalWeb.KeystoresLive,
      PkiCaPortalWeb.CeremonyLive,
      PkiCaPortalWeb.IssuerKeysLive,
      PkiCaPortalWeb.ProfileLive
    ],
    "auditor" => [
      PkiCaPortalWeb.DashboardLive,
      PkiCaPortalWeb.CaInstancesLive,
      PkiCaPortalWeb.AuditLogLive,
      PkiCaPortalWeb.ProfileLive
    ]
  }

  def on_mount(:default, _params, session, socket) do
    session_id = session["session_id"]

    with {:ok, session_id} when is_binary(session_id) <- {:ok, session_id},
         {:ok, sess} <- PkiCaPortal.SessionStore.lookup(session_id),
         :ok <- check_timeout(session_id, sess) do
      PkiCaPortal.SessionStore.touch(session_id)
      user = session_to_user(sess)
      role = user.role || "auditor"
      view = socket.view

      if allowed?(role, view) do
        timeout_ms = Application.get_env(@app, :session_idle_timeout_ms, 30 * 60 * 1000)
        warning_ms = timeout_ms - 5 * 60 * 1000

        {:cont,
         socket
         |> assign(:current_user, user)
         |> assign(:tenant_id, sess.tenant_id)
         |> assign(:session_id, session_id)
         |> assign(:session_timeout_ms, timeout_ms)
         |> assign(:session_warning_ms, warning_ms)}
      else
        {:halt,
         socket
         |> put_flash(:error, "You don't have access to that page.")
         |> redirect(to: "/")}
      end
    else
      _ ->
        {:halt, redirect(socket, to: "/login")}
    end
  end

  defp check_timeout(session_id, session) do
    timeout_ms = Application.get_env(@app, :session_idle_timeout_ms, 30 * 60 * 1000)
    elapsed = DateTime.diff(DateTime.utc_now(), session.last_active_at, :millisecond)

    if elapsed > timeout_ms do
      PkiCaPortal.SessionStore.delete(session_id)
      {:error, :expired}
    else
      :ok
    end
  end

  defp session_to_user(sess) do
    %{
      id: sess.user_id,
      username: sess.username,
      role: sess.role,
      tenant_id: sess.tenant_id
    }
  end

  defp allowed?(role, view) do
    case Map.get(@role_pages, role) do
      :all -> true
      nil -> false
      pages -> view in pages
    end
  end
end
```

- [ ] **Step 2: Add `handle_event` for keep_alive in a shared hook or app-level LiveView**

Each LiveView that uses the AuthHook needs to handle the `"keep_alive"` event from the JS timeout hook. The simplest approach: add a catch-all `handle_event("keep_alive", ...)` in a shared module that all LiveViews can `use`, or add it to each LiveView.

The cleanest approach: add it directly to the AuthHook as an `on_mount` attach_hook:

After the `{:cont, socket ...}` return, the socket already has `session_id`. For the keep_alive, we attach a hook in `on_mount`:

Update the `{:cont, ...}` return to:

```elixir
        {:cont,
         socket
         |> assign(:current_user, user)
         |> assign(:tenant_id, sess.tenant_id)
         |> assign(:session_id, session_id)
         |> assign(:session_timeout_ms, timeout_ms)
         |> assign(:session_warning_ms, warning_ms)
         |> attach_hook(:session_keep_alive, :handle_event, fn
           "keep_alive", _params, socket ->
             if sid = socket.assigns[:session_id] do
               PkiCaPortal.SessionStore.touch(sid)
             end
             {:halt, socket}

           _event, _params, socket ->
             # Touch session on any LiveView interaction
             if sid = socket.assigns[:session_id] do
               PkiCaPortal.SessionStore.touch(sid)
             end
             {:cont, socket}
         end)}
```

- [ ] **Step 3: Compile**

Run: `cd src/pki_ca_portal && mix compile`
Expected: Compiles clean

- [ ] **Step 4: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal_web/live/auth_hook.ex
git commit -m "feat(ca-portal): AuthHook validates ETS session + keep_alive + touch on events"
```

---

### Task 7: Replicate RequireAuth + AuthHook for RA and Platform Portals

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/plugs/require_auth.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/live/auth_hook.ex`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/plugs/require_auth.ex`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/live/auth_hook.ex`

- [ ] **Step 1: RA Portal RequireAuth**

Copy CA Portal RequireAuth, replacing:
- Module: `PkiRaPortalWeb.Plugs.RequireAuth`
- SessionStore: `PkiRaPortal.SessionStore`
- SessionSecurity: `PkiRaPortal.SessionSecurity`
- App: `:pki_ra_portal`
- Portal: `"ra"`

- [ ] **Step 2: RA Portal AuthHook**

Copy CA Portal AuthHook, replacing:
- Module: `PkiRaPortalWeb.Live.AuthHook`
- SessionStore: `PkiRaPortal.SessionStore`
- App: `:pki_ra_portal`
- Remove RBAC (`@role_pages`) — RA portal doesn't have per-role page restrictions, just check user exists

- [ ] **Step 3: Platform Portal RequireAuth**

Copy CA Portal RequireAuth, replacing:
- Module: `PkiPlatformPortalWeb.Plugs.RequireAuth`
- SessionStore: `PkiPlatformPortal.SessionStore`
- SessionSecurity: `PkiPlatformPortal.SessionSecurity`
- App: `:pki_platform_portal`
- Portal: `"platform"`

- [ ] **Step 4: Platform Portal AuthHook**

Copy CA Portal AuthHook, replacing:
- Module: `PkiPlatformPortalWeb.Live.AuthHook`
- SessionStore: `PkiPlatformPortal.SessionStore`
- App: `:pki_platform_portal`
- Remove RBAC — Platform portal doesn't have per-role page restrictions

- [ ] **Step 5: Compile all**

Run: `cd src/pki_ra_portal && mix compile && cd ../pki_platform_portal && mix compile`
Expected: Compiles clean

- [ ] **Step 6: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/plugs/require_auth.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/live/auth_hook.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/plugs/require_auth.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/live/auth_hook.ex
git commit -m "feat(ra+platform): RequireAuth + AuthHook with ETS session validation"
```

---

### Task 8: SessionSecurity — Suspicious Event Detection + Email Notifications

**Files:**
- Create: `src/pki_ca_portal/lib/pki_ca_portal/session_security.ex`
- Create: `src/pki_ca_portal/test/pki_ca_portal/session_security_test.exs`
- Create: `src/pki_ra_portal/lib/pki_ra_portal/session_security.ex`
- Create: `src/pki_platform_portal/lib/pki_platform_portal/session_security.ex`

- [ ] **Step 1: Write SessionSecurity tests (CA Portal)**

```elixir
# src/pki_ca_portal/test/pki_ca_portal/session_security_test.exs
defmodule PkiCaPortal.SessionSecurityTest do
  use ExUnit.Case, async: false

  alias PkiCaPortal.SessionSecurity

  describe "notify/2" do
    test "logs audit event for session_hijack_suspected" do
      # This should not crash — it logs to PlatformAudit and spawns email task
      assert :ok = SessionSecurity.notify(:session_hijack_suspected, %{
        username: "admin",
        role: "ca_admin",
        old_user_agent: "Mozilla/5.0",
        new_user_agent: "curl/7.0",
        ip: "127.0.0.1",
        portal: "ca"
      })
    end

    test "logs audit event for session_ip_changed" do
      assert :ok = SessionSecurity.notify(:session_ip_changed, %{
        username: "admin",
        role: "ca_admin",
        old_ip: "127.0.0.1",
        new_ip: "10.0.0.5",
        portal: "ca"
      })
    end

    test "logs audit event for new_ip_login" do
      assert :ok = SessionSecurity.notify(:new_ip_login, %{
        username: "admin",
        role: "ca_admin",
        ip: "10.0.0.5",
        portal: "ca"
      })
    end

    test "logs audit event for concurrent_sessions" do
      assert :ok = SessionSecurity.notify(:concurrent_sessions, %{
        username: "admin",
        role: "ca_admin",
        session_count: 3,
        portal: "ca"
      })
    end
  end
end
```

- [ ] **Step 2: Implement SessionSecurity (CA Portal)**

```elixir
# src/pki_ca_portal/lib/pki_ca_portal/session_security.ex
defmodule PkiCaPortal.SessionSecurity do
  @moduledoc """
  Detects suspicious session events and sends async notifications to platform admins.
  """

  require Logger

  @task_supervisor PkiCaPortal.TaskSupervisor

  def notify(event, details) do
    # Always log to audit trail (synchronous)
    PkiPlatformEngine.PlatformAudit.log(to_string(event), %{
      portal: details[:portal] || "ca",
      details: details
    })

    # Send email notification (async, fire-and-forget)
    Task.Supervisor.start_child(@task_supervisor, fn ->
      send_admin_notification(event, details)
    end)

    :ok
  rescue
    e ->
      Logger.error("[session_security] Failed to process #{event}: #{inspect(e)}")
      :ok
  end

  defp send_admin_notification(event, details) do
    admins = PkiPlatformEngine.AdminManagement.list_admins()
    emails = admins |> Enum.map(& &1.email) |> Enum.reject(&is_nil/1)

    if emails == [] do
      Logger.warning("[session_security] No admin emails to notify for #{event}")
    else
      subject = "[PKI Security] Suspicious session activity - #{format_event(event)}"
      body = format_email_body(event, details)

      Enum.each(emails, fn email ->
        PkiPlatformEngine.Mailer.send_email(email, subject, body)
      end)
    end
  rescue
    e ->
      Logger.error("[session_security] Failed to send notification email: #{inspect(e)}")
  end

  defp format_event(:session_hijack_suspected), do: "User-Agent Mismatch (Possible Hijack)"
  defp format_event(:session_ip_changed), do: "IP Address Changed"
  defp format_event(:new_ip_login), do: "Login From New IP"
  defp format_event(:concurrent_sessions), do: "Multiple Concurrent Sessions"
  defp format_event(event), do: to_string(event)

  defp format_email_body(event, details) do
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601()

    """
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2 style="color: #b91c1c;">PKI Security Alert</h2>
    <table style="border-collapse: collapse; width: 100%;">
    <tr><td style="padding: 8px; font-weight: bold;">Event</td><td style="padding: 8px;">#{format_event(event)}</td></tr>
    <tr><td style="padding: 8px; font-weight: bold;">User</td><td style="padding: 8px;">#{details[:username]} (#{details[:role]})</td></tr>
    <tr><td style="padding: 8px; font-weight: bold;">Portal</td><td style="padding: 8px;">#{details[:portal]}</td></tr>
    <tr><td style="padding: 8px; font-weight: bold;">Timestamp</td><td style="padding: 8px;">#{timestamp}</td></tr>
    #{event_specific_rows(event, details)}
    </table>
    <p style="color: #6b7280; font-size: 12px; margin-top: 20px;">
    This is an automated security notification from the PKI CA System. Do not reply to this email.
    </p>
    </body></html>
    """
  end

  defp event_specific_rows(:session_hijack_suspected, details) do
    """
    <tr><td style="padding: 8px; font-weight: bold;">Old User-Agent</td><td style="padding: 8px;">#{details[:old_user_agent]}</td></tr>
    <tr><td style="padding: 8px; font-weight: bold;">New User-Agent</td><td style="padding: 8px;">#{details[:new_user_agent]}</td></tr>
    <tr><td style="padding: 8px; font-weight: bold;">IP</td><td style="padding: 8px;">#{details[:ip]}</td></tr>
    """
  end

  defp event_specific_rows(:session_ip_changed, details) do
    """
    <tr><td style="padding: 8px; font-weight: bold;">Old IP</td><td style="padding: 8px;">#{details[:old_ip]}</td></tr>
    <tr><td style="padding: 8px; font-weight: bold;">New IP</td><td style="padding: 8px;">#{details[:new_ip]}</td></tr>
    """
  end

  defp event_specific_rows(:new_ip_login, details) do
    """
    <tr><td style="padding: 8px; font-weight: bold;">IP</td><td style="padding: 8px;">#{details[:ip]}</td></tr>
    """
  end

  defp event_specific_rows(:concurrent_sessions, details) do
    """
    <tr><td style="padding: 8px; font-weight: bold;">Active Sessions</td><td style="padding: 8px;">#{details[:session_count]}</td></tr>
    """
  end

  defp event_specific_rows(_, _), do: ""
end
```

- [ ] **Step 3: Run CA Portal SessionSecurity tests**

Run: `cd src/pki_ca_portal && mix test test/pki_ca_portal/session_security_test.exs --trace`
Expected: All pass

- [ ] **Step 4: Create RA Portal SessionSecurity**

Copy CA Portal module, replacing:
- Module: `PkiRaPortal.SessionSecurity`
- TaskSupervisor: `PkiRaPortal.TaskSupervisor`
- Default portal: `"ra"`

- [ ] **Step 5: Create Platform Portal SessionSecurity**

Copy CA Portal module, replacing:
- Module: `PkiPlatformPortal.SessionSecurity`
- TaskSupervisor: `PkiPlatformPortal.TaskSupervisor`
- Default portal: `"platform"`

- [ ] **Step 6: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal/session_security.ex \
        src/pki_ca_portal/test/pki_ca_portal/session_security_test.exs \
        src/pki_ra_portal/lib/pki_ra_portal/session_security.ex \
        src/pki_platform_portal/lib/pki_platform_portal/session_security.ex
git commit -m "feat: SessionSecurity with async admin email notifications"
```

---

### Task 9: New IP + Concurrent Session Detection on Login

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_controller.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/session_controller.ex`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_controller.ex`

- [ ] **Step 1: Add detection after SessionStore.create in CA Portal**

After `{:ok, session_id} = PkiCaPortal.SessionStore.create(...)`, add:

```elixir
            # Check for suspicious patterns
            existing = PkiCaPortal.SessionStore.list_by_user(user[:id])
            known_ips = existing |> Enum.map(& &1.ip) |> Enum.uniq()

            if ip not in known_ips and known_ips != [] do
              PkiCaPortal.SessionSecurity.notify(:new_ip_login, %{
                username: user[:username], role: user[:role], ip: ip, portal: "ca"
              })
            end

            if length(existing) > 1 do
              PkiCaPortal.SessionSecurity.notify(:concurrent_sessions, %{
                username: user[:username], role: user[:role],
                session_count: length(existing), portal: "ca"
              })
            end
```

- [ ] **Step 2: Apply same pattern to RA Portal**

Same code with `PkiRaPortal.SessionStore`, `PkiRaPortal.SessionSecurity`, `portal: "ra"`.

- [ ] **Step 3: Apply same pattern to Platform Portal**

Same code with `PkiPlatformPortal.SessionStore`, `PkiPlatformPortal.SessionSecurity`, `portal: "platform"`.

- [ ] **Step 4: Compile all**

Run: compile all three portals
Expected: Clean

- [ ] **Step 5: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_controller.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/controllers/session_controller.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_controller.ex
git commit -m "feat: detect new IP and concurrent sessions on login with admin notification"
```

---

### Task 10: Client-Side Session Timeout JS Hook + Modal

**Files:**
- Create: `src/pki_ca_portal/assets/js/session_timeout.js`
- Modify: `src/pki_ca_portal/assets/js/app.js`
- Create: `src/pki_ra_portal/assets/js/session_timeout.js`
- Modify: `src/pki_ra_portal/assets/js/app.js`
- Create: `src/pki_platform_portal/assets/js/session_timeout.js`
- Modify: `src/pki_platform_portal/assets/js/app.js`

- [ ] **Step 1: Create session_timeout.js (shared across portals)**

```javascript
// src/pki_ca_portal/assets/js/session_timeout.js
const SessionTimeout = {
  mounted() {
    this.warningMs = parseInt(this.el.dataset.warningMs) || 25 * 60 * 1000
    this.timeoutMs = parseInt(this.el.dataset.timeoutMs) || 30 * 60 * 1000
    this.lastActivity = Date.now()
    this.warningShown = false
    this.countdownInterval = null

    // Track user activity
    const events = ["mousedown", "keydown", "scroll", "touchstart"]
    this.activityHandler = () => {
      this.lastActivity = Date.now()
      if (this.warningShown) {
        this.hideWarning()
      }
    }
    events.forEach(e => document.addEventListener(e, this.activityHandler, { passive: true }))

    // Check every 30 seconds
    this.checkInterval = setInterval(() => this.checkTimeout(), 30000)
  },

  destroyed() {
    const events = ["mousedown", "keydown", "scroll", "touchstart"]
    events.forEach(e => document.removeEventListener(e, this.activityHandler))
    clearInterval(this.checkInterval)
    clearInterval(this.countdownInterval)
  },

  checkTimeout() {
    const idle = Date.now() - this.lastActivity

    if (idle >= this.timeoutMs) {
      // Session expired — redirect to logout
      window.location.href = "/logout"
    } else if (idle >= this.warningMs && !this.warningShown) {
      this.showWarning()
    }
  },

  showWarning() {
    this.warningShown = true
    const remaining = this.timeoutMs - (Date.now() - this.lastActivity)
    const modal = document.getElementById("session-timeout-modal")
    const countdown = document.getElementById("session-timeout-countdown")

    if (modal) {
      modal.classList.remove("hidden")

      this.countdownInterval = setInterval(() => {
        const left = this.timeoutMs - (Date.now() - this.lastActivity)
        if (left <= 0) {
          window.location.href = "/logout"
        } else {
          const mins = Math.floor(left / 60000)
          const secs = Math.floor((left % 60000) / 1000)
          if (countdown) {
            countdown.textContent = `${mins}:${secs.toString().padStart(2, "0")}`
          }
        }
      }, 1000)
    }
  },

  hideWarning() {
    this.warningShown = false
    clearInterval(this.countdownInterval)
    const modal = document.getElementById("session-timeout-modal")
    if (modal) modal.classList.add("hidden")
  },

  continueSession() {
    this.lastActivity = Date.now()
    this.hideWarning()
    this.pushEvent("keep_alive", {})
  }
}

export default SessionTimeout
```

- [ ] **Step 2: Register hook in CA Portal app.js**

In `src/pki_ca_portal/assets/js/app.js`, add import and hook registration:

```javascript
import SessionTimeout from "./session_timeout"
import {hooks as colocatedHooks} from "phoenix-colocated/pki_ca_portal"

const Hooks = { ...colocatedHooks, SessionTimeout }

const liveSocket = new LiveSocket("/live", Socket, {
  longPollFallbackMs: 2500,
  params: {_csrf_token: csrfToken},
  hooks: Hooks,
})
```

- [ ] **Step 3: Add timeout modal HTML to root layout**

In `src/pki_ca_portal/lib/pki_ca_portal_web/components/layouts/root.html.heex`, add before `{@inner_content}`:

```heex
    <div id="session-timeout-hook"
         phx-hook="SessionTimeout"
         data-warning-ms={assigns[:session_warning_ms] || 25 * 60 * 1000}
         data-timeout-ms={assigns[:session_timeout_ms] || 30 * 60 * 1000}>
    </div>
    <div id="session-timeout-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div class="bg-base-100 rounded-lg shadow-xl p-6 max-w-md mx-4">
        <h3 class="text-lg font-bold text-warning mb-2">Session Expiring</h3>
        <p class="mb-4">Your session will expire in <span id="session-timeout-countdown" class="font-mono font-bold">5:00</span> due to inactivity.</p>
        <button onclick="document.getElementById('session-timeout-hook')._liveHookInstance?.continueSession()"
                class="btn btn-primary w-full">Continue Working</button>
      </div>
    </div>
```

Note: The `continueSession` call will be wired via the hook instance. A simpler approach: use a phx-click on a LiveView element. Since the modal is in root layout (not LiveView), we'll use the hook's `pushEvent` via a button event listener. Update the button:

```heex
        <button id="session-continue-btn" class="btn btn-primary w-full">Continue Working</button>
```

And in `session_timeout.js`, add in `mounted()`:

```javascript
    const continueBtn = document.getElementById("session-continue-btn")
    if (continueBtn) {
      continueBtn.addEventListener("click", () => this.continueSession())
    }
```

- [ ] **Step 4: Copy session_timeout.js to RA and Platform portals**

Copy `src/pki_ca_portal/assets/js/session_timeout.js` to:
- `src/pki_ra_portal/assets/js/session_timeout.js`
- `src/pki_platform_portal/assets/js/session_timeout.js`

- [ ] **Step 5: Register hook in RA Portal app.js**

```javascript
import SessionTimeout from "./session_timeout"
import {hooks as colocatedHooks} from "phoenix-colocated/pki_ra_portal"

const Hooks = { ...colocatedHooks, SessionTimeout }
```

Update `hooks:` in LiveSocket to use `Hooks`.

- [ ] **Step 6: Register hook in Platform Portal app.js**

```javascript
import SessionTimeout from "./session_timeout"

let Hooks = { SessionTimeout }
Hooks.EngineTimer = { /* existing EngineTimer code */ }
```

Update `hooks:` in LiveSocket to use `Hooks`.

- [ ] **Step 7: Add timeout modal to RA and Platform Portal root layouts**

Copy the modal HTML from Step 3 to:
- `src/pki_ra_portal/lib/pki_ra_portal_web/components/layouts/root.html.heex`
- `src/pki_platform_portal/lib/pki_platform_portal_web/components/layouts/root.html.heex`

- [ ] **Step 8: Compile and verify all three portals**

Run: compile all three portals
Expected: Clean compilation

- [ ] **Step 9: Commit**

```bash
git add src/pki_ca_portal/assets/js/session_timeout.js \
        src/pki_ca_portal/assets/js/app.js \
        src/pki_ca_portal/lib/pki_ca_portal_web/components/layouts/root.html.heex \
        src/pki_ra_portal/assets/js/session_timeout.js \
        src/pki_ra_portal/assets/js/app.js \
        src/pki_ra_portal/lib/pki_ra_portal_web/components/layouts/root.html.heex \
        src/pki_platform_portal/assets/js/session_timeout.js \
        src/pki_platform_portal/assets/js/app.js \
        src/pki_platform_portal/lib/pki_platform_portal_web/components/layouts/root.html.heex
git commit -m "feat: client-side session timeout with countdown modal"
```

---

### Task 11: Admin Session Management Page (Platform Portal)

**Files:**
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/live/sessions_live.ex`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/router.ex`

- [ ] **Step 1: Create SessionsLive**

```elixir
# src/pki_platform_portal/lib/pki_platform_portal_web/live/sessions_live.ex
defmodule PkiPlatformPortalWeb.SessionsLive do
  use PkiPlatformPortalWeb, :live_view

  @pubsub_topics ["session_events"]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      # Subscribe to session events from all three portals
      Enum.each(@pubsub_topics, fn topic ->
        Phoenix.PubSub.subscribe(PkiCaPortal.PubSub, topic)
        Phoenix.PubSub.subscribe(PkiRaPortal.PubSub, topic)
        Phoenix.PubSub.subscribe(PkiPlatformPortal.PubSub, topic)
      end)
    end

    {:ok, assign(socket, :sessions, load_all_sessions())}
  end

  @impl true
  def handle_event("force_logout", %{"portal" => portal, "session-id" => session_id}, socket) do
    admin = socket.assigns.current_user
    store = store_for_portal(portal)

    case store.lookup(session_id) do
      {:ok, session} ->
        store.delete(session_id)

        PkiPlatformEngine.PlatformAudit.log("forced_logout", %{
          portal: portal,
          actor_id: admin["id"] || admin[:id],
          actor_username: admin["username"] || admin[:username],
          details: %{
            target_username: session.username,
            target_session_id: session_id,
            reason: "admin_forced"
          }
        })

      _ ->
        :ok
    end

    {:noreply, assign(socket, :sessions, load_all_sessions())}
  end

  @impl true
  def handle_info({event, _session}, socket)
      when event in [:session_created, :session_deleted, :session_expired] do
    {:noreply, assign(socket, :sessions, load_all_sessions())}
  end

  def handle_info(_, socket), do: {:noreply, socket}

  defp load_all_sessions do
    ca = PkiCaPortal.SessionStore.list_all() |> Enum.map(&Map.put(&1, :portal, "ca"))
    ra = PkiRaPortal.SessionStore.list_all() |> Enum.map(&Map.put(&1, :portal, "ra"))
    platform = PkiPlatformPortal.SessionStore.list_all() |> Enum.map(&Map.put(&1, :portal, "platform"))

    (ca ++ ra ++ platform)
    |> Enum.sort_by(& &1.last_active_at, {:desc, DateTime})
  end

  defp store_for_portal("ca"), do: PkiCaPortal.SessionStore
  defp store_for_portal("ra"), do: PkiRaPortal.SessionStore
  defp store_for_portal("platform"), do: PkiPlatformPortal.SessionStore

  defp format_time(nil), do: "—"
  defp format_time(%DateTime{} = dt) do
    Calendar.strftime(dt, "%H:%M:%S")
  end

  defp portal_badge("ca"), do: "badge-primary"
  defp portal_badge("ra"), do: "badge-secondary"
  defp portal_badge("platform"), do: "badge-accent"
  defp portal_badge(_), do: "badge-ghost"

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <h1 class="text-2xl font-bold mb-6">Active Sessions</h1>

      <div class="overflow-x-auto">
        <table class="table table-zebra w-full">
          <thead>
            <tr>
              <th>User</th>
              <th>Portal</th>
              <th>Role</th>
              <th>Tenant</th>
              <th>IP</th>
              <th>Login Time</th>
              <th>Last Active</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={session <- @sessions}>
              <td class="font-medium">{session.username}</td>
              <td><span class={"badge #{portal_badge(session.portal)}"}>{session.portal |> String.upcase()}</span></td>
              <td>{session.role}</td>
              <td class="text-xs font-mono">{session.tenant_id || "—"}</td>
              <td class="font-mono text-sm">{session.ip}</td>
              <td>{format_time(session.created_at)}</td>
              <td>{format_time(session.last_active_at)}</td>
              <td>
                <button
                  phx-click="force_logout"
                  phx-value-portal={session.portal}
                  phx-value-session-id={session.session_id}
                  data-confirm={"Force logout #{session.username} from #{session.portal}?"}
                  class="btn btn-error btn-xs"
                >
                  Force Logout
                </button>
              </td>
            </tr>
            <tr :if={@sessions == []}>
              <td colspan="8" class="text-center text-base-content/50 py-8">No active sessions</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="mt-4 text-sm text-base-content/50">
        {length(@sessions)} active session(s) across all portals. Updates in real-time.
      </div>
    </div>
    """
  end
end
```

- [ ] **Step 2: Add route to Platform Portal router**

In `src/pki_platform_portal/lib/pki_platform_portal_web/router.ex`, add to the authenticated live_session:

```elixir
      live "/sessions", SessionsLive
```

- [ ] **Step 3: Compile and verify**

Run: `cd src/pki_platform_portal && mix compile`
Expected: Clean

- [ ] **Step 4: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/live/sessions_live.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/router.ex
git commit -m "feat(platform): admin session management page with real-time updates and force logout"
```

---

### Task 12: Final Integration Verification

- [ ] **Step 1: Compile all five projects**

```bash
cd src/pki_ca_engine && mix compile
cd ../pki_ra_engine && mix compile
cd ../pki_ca_portal && mix compile
cd ../pki_ra_portal && mix compile
cd ../pki_platform_portal && mix compile
```

Expected: All compile clean (warnings from pre-existing issues are acceptable)

- [ ] **Step 2: Run all SessionStore tests**

```bash
cd src/pki_ca_portal && mix test test/pki_ca_portal/session_store_test.exs --trace
cd ../pki_ra_portal && mix test test/pki_ra_portal/session_store_test.exs --trace
cd ../pki_platform_portal && mix test test/pki_platform_portal/session_store_test.exs --trace
```

Expected: All pass

- [ ] **Step 3: Run SessionSecurity tests**

```bash
cd src/pki_ca_portal && mix test test/pki_ca_portal/session_security_test.exs --trace
```

Expected: All pass

- [ ] **Step 4: Commit any final fixes**

If any tests fail, fix and commit.
