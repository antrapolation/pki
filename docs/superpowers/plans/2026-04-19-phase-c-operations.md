# Phase C: Operations (Monitoring, Backup, Caddy) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add observability (LiveDashboard + health JSON), disaster recovery (S3 backup), and production Caddy config (3 wildcard certs, GoDaddy DNS-01).

**Architecture:** Three independent workstreams: monitoring extends platform portal + tenant health, backup extends MnesiaBackup with S3 upload, Caddy updates CaddyConfigurator for 3-hostname routing + OCSP dispatch.

**Tech Stack:** Elixir/OTP, Phoenix LiveDashboard, Req (HTTP client for S3), Caddy with caddy-dns/godaddy, age encryption.

---

## File Structure

### New files

```
src/pki_mnesia/lib/pki_mnesia/structs/backup_record.ex          # BackupRecord struct
src/pki_mnesia/test/pki_mnesia/structs/backup_record_test.exs   # BackupRecord struct tests
src/pki_tenant/lib/pki_tenant/s3_upload.ex                      # S3v4 signed upload via Req
src/pki_tenant/test/s3_upload_test.exs                          # S3 upload tests with mock
src/pki_tenant_web/lib/pki_tenant_web/controllers/health_controller.ex    # Tenant health JSON
src/pki_tenant_web/lib/pki_tenant_web/controllers/health_json.ex          # JSON view for health
src/pki_tenant_web/test/controllers/health_controller_test.exs            # Tenant health endpoint tests
src/pki_platform_portal/lib/pki_platform_portal_web/controllers/health_controller.ex  # Platform health JSON
src/pki_platform_portal/lib/pki_platform_portal_web/controllers/health_json.ex        # JSON view
src/pki_platform_portal/test/pki_platform_portal_web/controllers/health_controller_test.exs  # Platform health tests
deploy/Caddyfile.template                                       # Base Caddy config template
deploy/RESTORE.md                                               # Backup restore runbook
```

### Modified files

```
src/pki_mnesia/lib/pki_mnesia/schema.ex                        # Add backup_records table + @sync_tables
src/pki_mnesia/test/pki_mnesia/schema_test.exs                 # Add backup_records to table assertions
src/pki_tenant/lib/pki_tenant/health.ex                         # Richer health data
src/pki_tenant/test/health_test.exs                             # Updated health tests
src/pki_tenant/lib/pki_tenant/mnesia_backup.ex                  # Daily S3 upload, encryption, BackupRecord
src/pki_ca_engine/lib/pki_ca_engine/key_activation.ex           # Add active_key_count/1
src/pki_ca_engine/test/pki_ca_engine/key_activation_test.exs    # Test active_key_count
src/pki_tenant_web/lib/pki_tenant_web/host_router.ex            # Add :ocsp dispatch
src/pki_tenant_web/lib/pki_tenant_web/ca_router.ex              # Add /health route
src/pki_tenant_web/lib/pki_tenant_web/ra_router.ex              # Add /health route
src/pki_tenant_web/test/host_router_test.exs                    # Add :ocsp tests
src/pki_platform_engine/lib/pki_platform_engine/caddy_configurator.ex  # 3 hostnames per tenant
src/pki_platform_portal/mix.exs                                 # Add phoenix_live_dashboard dep
src/pki_platform_portal/lib/pki_platform_portal_web/router.ex   # Add /health + /dashboard routes
```

---

## Prerequisites

Before starting any task, confirm Phase A + B branch compiles:

```bash
cd /Users/amirrudinyahaya/Workspace/pki && mix compile --no-deps-check
```

**Important conventions:**
- `PkiMnesia.Repo` returns tagged tuples: `{:ok, struct}` | `{:ok, nil}` | `{:error, reason}`
- Project uses `path:` deps, not `in_umbrella: true`
- All struct modules implement `fields/0` returning a list with `:id` first
- All struct modules implement `new/1` accepting an attrs map

---

## Task 1: BackupRecord Struct + Schema Update

**Files:**
- Create: `src/pki_mnesia/lib/pki_mnesia/structs/backup_record.ex`
- Create: `src/pki_mnesia/test/pki_mnesia/structs/backup_record_test.exs`
- Modify: `src/pki_mnesia/lib/pki_mnesia/schema.ex`
- Modify: `src/pki_mnesia/test/pki_mnesia/schema_test.exs`

### Step 1: Write the BackupRecord struct test

- [ ] **Step 1.1: Create the test file**

```elixir
# src/pki_mnesia/test/pki_mnesia/structs/backup_record_test.exs
defmodule PkiMnesia.Structs.BackupRecordTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.Structs.BackupRecord

  test "new/0 creates a struct with defaults" do
    record = BackupRecord.new()
    assert record.id != nil
    assert record.type == "local"
    assert record.status == "completed"
    assert record.error == nil
    assert %DateTime{} = record.inserted_at
  end

  test "new/1 accepts custom attributes" do
    record = BackupRecord.new(%{
      type: "remote",
      size_bytes: 1024,
      location: "s3://bucket/key",
      status: "failed",
      error: "connection refused"
    })
    assert record.type == "remote"
    assert record.size_bytes == 1024
    assert record.location == "s3://bucket/key"
    assert record.status == "failed"
    assert record.error == "connection refused"
  end

  test "new/1 generates unique ids" do
    r1 = BackupRecord.new()
    r2 = BackupRecord.new()
    assert r1.id != r2.id
  end

  test "fields/0 returns ordered field list starting with :id" do
    fields = BackupRecord.fields()
    assert hd(fields) == :id
    assert :timestamp in fields
    assert :type in fields
    assert :size_bytes in fields
    assert :location in fields
    assert :status in fields
    assert :error in fields
    assert :inserted_at in fields
  end
end
```

- [ ] **Step 1.2: Run test to verify it fails**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_mnesia && mix test test/pki_mnesia/structs/backup_record_test.exs
```
Expected: Compilation error — `PkiMnesia.Structs.BackupRecord` not found.

### Step 2: Implement BackupRecord struct

- [ ] **Step 2.1: Create the struct module**

```elixir
# src/pki_mnesia/lib/pki_mnesia/structs/backup_record.ex
defmodule PkiMnesia.Structs.BackupRecord do
  @moduledoc "Tracks backup operations (local and remote/S3)."

  @fields [:id, :timestamp, :type, :size_bytes, :location, :status, :error, :inserted_at]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
    id: binary(),
    timestamp: DateTime.t(),
    type: String.t(),
    size_bytes: integer() | nil,
    location: String.t() | nil,
    status: String.t(),
    error: String.t() | nil,
    inserted_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      timestamp: attrs[:timestamp] || now,
      type: Map.get(attrs, :type, "local"),
      size_bytes: attrs[:size_bytes],
      location: attrs[:location],
      status: Map.get(attrs, :status, "completed"),
      error: attrs[:error],
      inserted_at: attrs[:inserted_at] || now
    }
  end
end
```

- [ ] **Step 2.2: Run test to verify it passes**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_mnesia && mix test test/pki_mnesia/structs/backup_record_test.exs
```
Expected: 4 tests, 0 failures.

### Step 3: Add BackupRecord to Schema

- [ ] **Step 3.1: Update the alias block in `src/pki_mnesia/lib/pki_mnesia/schema.ex`**

Find the alias block (line 9-14) and add `BackupRecord`:

```elixir
# In src/pki_mnesia/lib/pki_mnesia/schema.ex — replace the alias block
  alias PkiMnesia.Structs.{
    CaInstance, IssuerKey, KeyCeremony, CeremonyParticipant,
    CeremonyTranscript, ThresholdShare, IssuedCertificate,
    RaInstance, RaCaConnection, CertProfile, CsrRequest,
    ApiKey, DcvChallenge, CertificateStatus, PortalUser,
    BackupRecord
  }
```

- [ ] **Step 3.2: Add `:backup_records` to `@sync_tables`**

Find the `@sync_tables` module attribute (line 18-22) and add `:backup_records`:

```elixir
  @sync_tables [
    :ca_instances, :issuer_keys, :threshold_shares, :key_ceremonies,
    :ceremony_participants, :ceremony_transcripts, :portal_users,
    :cert_profiles, :ra_instances, :ra_ca_connections, :api_keys,
    :dcv_challenges, :schema_versions, :backup_records
  ]
```

- [ ] **Step 3.3: Add BackupRecord table creation in `create_tables/0`**

Find the `tables` list inside `create_tables/0` (around line 145-172). Add this entry before the closing `]`:

```elixir
      # Backup tracking (disc_copies)
      {BackupRecord, :disc_copies, [:type, :status]},
```

Insert it after the `{PortalUser, :disc_copies, [:username, :email, :role]}` line, so the full tail looks like:

```elixir
      # Portal users (disc_copies)
      {PortalUser, :disc_copies, [:username, :email, :role]},

      # Backup tracking (disc_copies)
      {BackupRecord, :disc_copies, [:type, :status]}
    ]
```

- [ ] **Step 3.4: Run schema test to verify backup_records table is created**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_mnesia && mix test test/pki_mnesia/schema_test.exs
```
Expected: All existing tests pass. The `backup_records` table will be created as part of `create_tables/0`.

- [ ] **Step 3.5: Verify full test suite for pki_mnesia**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_mnesia && mix test
```
Expected: All tests pass.

- [ ] **Step 3.6: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_mnesia/lib/pki_mnesia/structs/backup_record.ex \
        src/pki_mnesia/test/pki_mnesia/structs/backup_record_test.exs \
        src/pki_mnesia/lib/pki_mnesia/schema.ex
git commit -m "feat: add BackupRecord struct and Mnesia table for backup tracking"
```

---

## Task 2: Enhanced Health Module + Health Endpoints

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/key_activation.ex`
- Modify: `src/pki_tenant/lib/pki_tenant/health.ex`
- Modify: `src/pki_tenant/test/health_test.exs`
- Modify: `src/pki_tenant/lib/pki_tenant/mnesia_backup.ex`
- Create: `src/pki_tenant_web/lib/pki_tenant_web/controllers/health_controller.ex`
- Create: `src/pki_tenant_web/lib/pki_tenant_web/controllers/health_json.ex`
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/ca_router.ex`
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/ra_router.ex`
- Create: `src/pki_tenant_web/test/controllers/health_controller_test.exs`
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/health_controller.ex`
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/health_json.ex`
- Create: `src/pki_platform_portal/test/pki_platform_portal_web/controllers/health_controller_test.exs`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/router.ex`

### Step 1: Add `active_key_count/1` to KeyActivation

- [ ] **Step 1.1: Add the client function to `src/pki_ca_engine/lib/pki_ca_engine/key_activation.ex`**

Add this function after the existing `get_active_key/2` function (after line 55):

```elixir
  def active_key_count(server \\ __MODULE__) do
    GenServer.call(server, :active_key_count)
  end
```

- [ ] **Step 1.2: Add the handler**

Add this clause inside the module, after the existing `handle_call` clauses (find a good spot among the handle_call blocks):

```elixir
  @impl true
  def handle_call(:active_key_count, _from, state) do
    {:reply, map_size(state.active_keys), state}
  end
```

- [ ] **Step 1.3: Run KeyActivation tests**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test test/pki_ca_engine/key_activation_test.exs
```
Expected: All existing tests pass (new function not yet tested — covered by health integration).

### Step 2: Add `last_backup_time/1` to MnesiaBackup

- [ ] **Step 2.1: Add state tracking in `src/pki_tenant/lib/pki_tenant/mnesia_backup.ex`**

In `init/1`, add `last_backup_at: nil` to the state map. Replace the existing `init/1` return:

```elixir
  def init(opts) do
    interval = opts[:interval_ms] || 3_600_000  # 1 hour default
    backup_dir = opts[:backup_dir] || Path.join(System.get_env("MNESIA_DIR", "/tmp/mnesia"), "backups")
    File.mkdir_p!(backup_dir)
    max_backups = opts[:max_backups] || 24

    if opts[:start_timer] != false do
      Process.send_after(self(), :scheduled_backup, interval)
    end

    {:ok, %{
      interval: interval,
      backup_dir: backup_dir,
      max_backups: max_backups,
      last_backup_at: nil
    }}
  end
```

- [ ] **Step 2.2: Add client function for querying last backup time**

Add after `backup_now/1`:

```elixir
  def last_backup_time(server \\ __MODULE__) do
    GenServer.call(server, :last_backup_time)
  end
```

- [ ] **Step 2.3: Add the handler**

Add a new `handle_call` clause:

```elixir
  def handle_call(:last_backup_time, _from, state) do
    {:reply, state.last_backup_at, state}
  end
```

- [ ] **Step 2.4: Update `handle_call(:backup_now, ...)` to track timestamp**

Replace the existing `handle_call(:backup_now, ...)`:

```elixir
  def handle_call(:backup_now, _from, state) do
    case do_backup(state.backup_dir, state.max_backups) do
      {:ok, path} ->
        {:reply, {:ok, path}, %{state | last_backup_at: DateTime.utc_now()}}
      error ->
        {:reply, error, state}
    end
  end
```

- [ ] **Step 2.5: Update `handle_info(:scheduled_backup, ...)` to track timestamp**

Replace the existing `handle_info(:scheduled_backup, ...)`:

```elixir
  def handle_info(:scheduled_backup, state) do
    state =
      case do_backup(state.backup_dir, state.max_backups) do
        {:ok, _path} -> %{state | last_backup_at: DateTime.utc_now()}
        _error -> state
      end

    Process.send_after(self(), :scheduled_backup, state.interval)
    {:noreply, state}
  end
```

### Step 3: Enhance PkiTenant.Health

- [ ] **Step 3.1: Update the health test in `src/pki_tenant/test/health_test.exs`**

Replace the entire file:

```elixir
# src/pki_tenant/test/health_test.exs
defmodule PkiTenant.HealthTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiTenant.Health

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  test "check returns status :ok with mnesia running" do
    result = Health.check()
    assert result.status == :ok
    assert result.mnesia == :running
    assert result.node == node()
    assert is_integer(result.uptime_seconds)
    assert is_integer(result.memory_mb)
  end

  test "check returns table_count as integer" do
    result = Health.check()
    assert is_integer(result.table_count)
    assert result.table_count > 0
  end

  test "check returns active_keys as integer" do
    result = Health.check()
    assert is_integer(result.active_keys)
  end

  test "check returns last_backup (nil when no backup has run)" do
    result = Health.check()
    # last_backup is nil until MnesiaBackup runs a backup
    assert result.last_backup == nil or %DateTime{} = result.last_backup
  end
end
```

- [ ] **Step 3.2: Run the test to verify it fails**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_tenant && mix test test/health_test.exs
```
Expected: FAIL — `table_count`, `active_keys`, `last_backup` keys not present.

- [ ] **Step 3.3: Update `src/pki_tenant/lib/pki_tenant/health.ex`**

Replace the entire file:

```elixir
defmodule PkiTenant.Health do
  @moduledoc """
  Health check module called by platform via :erpc.call.
  Returns detailed health map including Mnesia, keys, and backup status.
  """

  def check do
    %{
      status: :ok,
      mnesia: mnesia_status(),
      table_count: table_count(),
      node: node(),
      uptime_seconds: :erlang.statistics(:wall_clock) |> elem(0) |> div(1000),
      memory_mb: :erlang.memory(:total) |> div(1_048_576),
      active_keys: active_key_count(),
      last_backup: last_backup_time()
    }
  end

  defp mnesia_status do
    case :mnesia.system_info(:is_running) do
      :yes -> :running
      _ -> :stopped
    end
  rescue
    _ -> :error
  end

  defp table_count do
    tables = :mnesia.system_info(:local_tables) -- [:schema]
    length(tables)
  rescue
    _ -> 0
  end

  defp active_key_count do
    PkiCaEngine.KeyActivation.active_key_count()
  rescue
    _ -> 0
  catch
    :exit, _ -> 0
  end

  defp last_backup_time do
    PkiTenant.MnesiaBackup.last_backup_time()
  rescue
    _ -> nil
  catch
    :exit, _ -> nil
  end
end
```

- [ ] **Step 3.4: Run the test to verify it passes**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_tenant && mix test test/health_test.exs
```
Expected: 4 tests, 0 failures. Note: `active_keys` returns 0 (KeyActivation GenServer not started in test) and `last_backup` returns nil (MnesiaBackup GenServer not started in test) — the rescue/catch clauses handle this.

### Step 4: Tenant health endpoint

- [ ] **Step 4.1: Create the tenant health JSON view**

```elixir
# src/pki_tenant_web/lib/pki_tenant_web/controllers/health_json.ex
defmodule PkiTenantWeb.HealthJSON do
  @moduledoc "JSON rendering for tenant health endpoint."

  def show(%{health: health}) do
    %{
      status: to_string(health.status),
      mnesia: to_string(health.mnesia),
      tables: health.table_count,
      active_keys: health.active_keys,
      last_backup: format_datetime(health.last_backup),
      uptime_seconds: health.uptime_seconds
    }
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
end
```

- [ ] **Step 4.2: Create the tenant health controller**

```elixir
# src/pki_tenant_web/lib/pki_tenant_web/controllers/health_controller.ex
defmodule PkiTenantWeb.HealthController do
  use PkiTenantWeb, :controller

  def show(conn, _params) do
    health = PkiTenant.Health.check()

    conn
    |> put_status(200)
    |> put_view(PkiTenantWeb.HealthJSON)
    |> render(:show, health: health)
  end
end
```

- [ ] **Step 4.3: Add `/health` route to CaRouter**

In `src/pki_tenant_web/lib/pki_tenant_web/ca_router.ex`, add an API scope before the existing browser scopes. Insert after the `pipeline :browser do ... end` block (after line 11), before the first `scope`:

```elixir
  pipeline :health_api do
    plug :accepts, ["json"]
  end

  # Health check (unauthenticated, JSON)
  scope "/", PkiTenantWeb do
    pipe_through :health_api

    get "/health", HealthController, :show
  end
```

- [ ] **Step 4.4: Add `/health` route to RaRouter**

In `src/pki_tenant_web/lib/pki_tenant_web/ra_router.ex`, add the same API scope. Insert after the `pipeline :browser do ... end` block (after line 11), before the first `scope`:

```elixir
  pipeline :health_api do
    plug :accepts, ["json"]
  end

  # Health check (unauthenticated, JSON)
  scope "/", PkiTenantWeb do
    pipe_through :health_api

    get "/health", HealthController, :show
  end
```

- [ ] **Step 4.5: Create tenant health controller test**

```elixir
# src/pki_tenant_web/test/controllers/health_controller_test.exs
defmodule PkiTenantWeb.HealthControllerTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  test "HealthJSON.show/1 returns expected structure" do
    health = PkiTenant.Health.check()
    result = PkiTenantWeb.HealthJSON.show(%{health: health})

    assert result.status == "ok"
    assert result.mnesia == "running"
    assert is_integer(result.tables)
    assert is_integer(result.active_keys)
    assert is_integer(result.uptime_seconds)
    # last_backup is nil until a backup has been performed
    assert result.last_backup == nil or is_binary(result.last_backup)
  end
end
```

- [ ] **Step 4.6: Run tenant web tests**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_tenant_web && mix test test/controllers/health_controller_test.exs
```
Expected: 1 test, 0 failures.

### Step 5: Platform health endpoint

- [ ] **Step 5.1: Create the platform health JSON view**

```elixir
# src/pki_platform_portal/lib/pki_platform_portal_web/controllers/health_json.ex
defmodule PkiPlatformPortalWeb.HealthJSON do
  @moduledoc "JSON rendering for platform health endpoint."

  def show(%{health: health}) do
    health
  end
end
```

- [ ] **Step 5.2: Create the platform health controller**

```elixir
# src/pki_platform_portal/lib/pki_platform_portal_web/controllers/health_controller.ex
defmodule PkiPlatformPortalWeb.HealthController do
  use PkiPlatformPortalWeb, :controller

  @doc """
  Platform health endpoint. Collects health from all known tenant nodes
  via :erpc.call, plus replica status. Unauthenticated — for uptime monitors.
  """
  def show(conn, _params) do
    tenants = collect_tenant_health()
    replica = check_replica()

    health = %{
      status: if(Enum.all?(tenants, fn {_slug, t} -> t.status == "running" end), do: "healthy", else: "degraded"),
      tenants: Map.new(tenants),
      replica: replica
    }

    conn
    |> put_status(200)
    |> put_view(PkiPlatformPortalWeb.HealthJSON)
    |> render(:show, health: health)
  end

  defp collect_tenant_health do
    case PkiPlatformEngine.TenantLifecycle.list_tenants() do
      tenants when is_list(tenants) ->
        Enum.map(tenants, fn tenant ->
          slug = tenant.slug
          node_name = tenant.node

          health =
            try do
              case :erpc.call(node_name, PkiTenant.Health, :check, [], 5_000) do
                %{status: :ok} = h ->
                  %{
                    status: "running",
                    mnesia: to_string(h.mnesia),
                    active_keys: h.active_keys,
                    last_backup: format_datetime(h.last_backup)
                  }

                _ ->
                  %{status: "unknown"}
              end
            catch
              _, _ -> %{status: "unreachable"}
            end

          {slug, health}
        end)

      _ ->
        []
    end
  end

  defp check_replica do
    replica_node = Application.get_env(:pki_platform_engine, :replica_node)

    cond do
      is_nil(replica_node) ->
        %{status: "not_configured"}

      Node.ping(replica_node) == :pong ->
        %{status: "connected", node: to_string(replica_node)}

      true ->
        %{status: "disconnected", node: to_string(replica_node)}
    end
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
end
```

- [ ] **Step 5.3: Add `/health` route to platform router**

In `src/pki_platform_portal/lib/pki_platform_portal_web/router.ex`, add an API scope for health. Insert before the `# Setup route` comment (before line 28):

```elixir
  # Health check (unauthenticated, JSON — for uptime monitors)
  scope "/", PkiPlatformPortalWeb do
    pipe_through :api

    get "/health", HealthController, :show
  end
```

- [ ] **Step 5.4: Create platform health controller test**

```elixir
# src/pki_platform_portal/test/pki_platform_portal_web/controllers/health_controller_test.exs
defmodule PkiPlatformPortalWeb.HealthControllerTest do
  use ExUnit.Case, async: false

  test "HealthJSON.show/1 returns the health map as-is" do
    health = %{
      status: "healthy",
      tenants: %{
        "demo" => %{status: "running", mnesia: "running", active_keys: 2, last_backup: nil}
      },
      replica: %{status: "not_configured"}
    }

    result = PkiPlatformPortalWeb.HealthJSON.show(%{health: health})
    assert result.status == "healthy"
    assert result.tenants["demo"].status == "running"
    assert result.replica.status == "not_configured"
  end
end
```

- [ ] **Step 5.5: Run platform health test**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_platform_portal && mix test test/pki_platform_portal_web/controllers/health_controller_test.exs
```
Expected: 1 test, 0 failures.

- [ ] **Step 5.6: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_ca_engine/lib/pki_ca_engine/key_activation.ex \
        src/pki_tenant/lib/pki_tenant/health.ex \
        src/pki_tenant/lib/pki_tenant/mnesia_backup.ex \
        src/pki_tenant/test/health_test.exs \
        src/pki_tenant_web/lib/pki_tenant_web/controllers/health_controller.ex \
        src/pki_tenant_web/lib/pki_tenant_web/controllers/health_json.ex \
        src/pki_tenant_web/lib/pki_tenant_web/ca_router.ex \
        src/pki_tenant_web/lib/pki_tenant_web/ra_router.ex \
        src/pki_tenant_web/test/controllers/health_controller_test.exs \
        src/pki_platform_portal/lib/pki_platform_portal_web/controllers/health_controller.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/controllers/health_json.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/router.ex \
        src/pki_platform_portal/test/pki_platform_portal_web/controllers/health_controller_test.exs
git commit -m "feat: add health JSON endpoints for tenant and platform monitoring"
```

---

## Task 3: S3 Upload + MnesiaBackup Enhancement

**Files:**
- Create: `src/pki_tenant/lib/pki_tenant/s3_upload.ex`
- Create: `src/pki_tenant/test/s3_upload_test.exs`
- Modify: `src/pki_tenant/lib/pki_tenant/mnesia_backup.ex`

### Step 1: Write S3Upload test

- [ ] **Step 1.1: Create the test file**

```elixir
# src/pki_tenant/test/s3_upload_test.exs
defmodule PkiTenant.S3UploadTest do
  use ExUnit.Case, async: true

  alias PkiTenant.S3Upload

  describe "sign_request/5" do
    test "generates Authorization header with AWS4-HMAC-SHA256" do
      headers = S3Upload.sign_request(
        "PUT",
        "https://s3.amazonaws.com/my-bucket/my-key",
        "",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      )

      auth = Enum.find_value(headers, fn
        {"authorization", v} -> v
        _ -> nil
      end)

      assert auth != nil
      assert String.starts_with?(auth, "AWS4-HMAC-SHA256")
      assert String.contains?(auth, "AKIAIOSFODNN7EXAMPLE")
    end

    test "includes x-amz-content-sha256 header" do
      headers = S3Upload.sign_request(
        "PUT",
        "https://s3.amazonaws.com/my-bucket/my-key",
        "",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      )

      sha_header = Enum.find_value(headers, fn
        {"x-amz-content-sha256", v} -> v
        _ -> nil
      end)

      assert sha_header != nil
    end
  end

  describe "put_object/4" do
    test "returns error when endpoint is unreachable" do
      result = S3Upload.put_object("test-bucket", "test-key", "data", %{
        endpoint: "http://localhost:19999",
        access_key: "test",
        secret_key: "test",
        region: "us-east-1"
      })

      assert {:error, _reason} = result
    end
  end
end
```

- [ ] **Step 1.2: Run test to verify it fails**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_tenant && mix test test/s3_upload_test.exs
```
Expected: Compilation error — `PkiTenant.S3Upload` not found.

### Step 2: Implement S3Upload

- [ ] **Step 2.1: Create the S3 upload module**

```elixir
# src/pki_tenant/lib/pki_tenant/s3_upload.ex
defmodule PkiTenant.S3Upload do
  @moduledoc """
  S3-compatible object upload using AWS Signature V4 via Req.
  No ex_aws dependency — minimal implementation for backup uploads.
  """

  require Logger

  @doc """
  Upload binary data to an S3-compatible bucket.

  opts is a map with keys:
    :endpoint    - S3 endpoint URL (default "https://s3.amazonaws.com")
    :access_key  - AWS access key ID
    :secret_key  - AWS secret access key
    :region      - AWS region (default "us-east-1")

  Returns :ok | {:error, reason}.
  """
  def put_object(bucket, key, body, opts) do
    endpoint = Map.get(opts, :endpoint, "https://s3.amazonaws.com")
    access_key = Map.fetch!(opts, :access_key)
    secret_key = Map.fetch!(opts, :secret_key)
    region = Map.get(opts, :region, "us-east-1")

    url = "#{endpoint}/#{bucket}/#{key}"

    headers = sign_request("PUT", url, body, access_key, secret_key, region)

    case Req.put(url, body: body, headers: headers, receive_timeout: 120_000) do
      {:ok, %{status: status}} when status in 200..299 ->
        Logger.info("[s3_upload] Uploaded #{bucket}/#{key} (#{byte_size(body)} bytes)")
        :ok

      {:ok, %{status: status, body: resp_body}} ->
        Logger.error("[s3_upload] Upload failed: HTTP #{status} — #{inspect(resp_body)}")
        {:error, {:http_error, status, resp_body}}

      {:error, reason} ->
        Logger.error("[s3_upload] Upload failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Generate AWS Signature V4 headers for an S3 request.
  Returns a list of {header_name, header_value} tuples.
  """
  def sign_request(method, url, body, access_key, secret_key, region \\ "us-east-1") do
    service = "s3"
    uri = URI.parse(url)
    now = DateTime.utc_now()
    date_stamp = Calendar.strftime(now, "%Y%m%d")
    amz_date = Calendar.strftime(now, "%Y%m%dT%H%M%SZ")

    host = uri.host
    path = uri.path || "/"

    payload_hash = :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)

    headers_to_sign = [
      {"host", host},
      {"x-amz-content-sha256", payload_hash},
      {"x-amz-date", amz_date}
    ]

    signed_header_names = headers_to_sign |> Enum.map(&elem(&1, 0)) |> Enum.join(";")

    canonical_headers = headers_to_sign
    |> Enum.map(fn {k, v} -> "#{k}:#{v}\n" end)
    |> Enum.join()

    canonical_request = Enum.join([
      String.upcase(method),
      path,
      "",  # query string (empty)
      canonical_headers,
      signed_header_names,
      payload_hash
    ], "\n")

    credential_scope = "#{date_stamp}/#{region}/#{service}/aws4_request"

    string_to_sign = Enum.join([
      "AWS4-HMAC-SHA256",
      amz_date,
      credential_scope,
      :crypto.hash(:sha256, canonical_request) |> Base.encode16(case: :lower)
    ], "\n")

    signing_key =
      "AWS4#{secret_key}"
      |> hmac_sha256(date_stamp)
      |> hmac_sha256(region)
      |> hmac_sha256(service)
      |> hmac_sha256("aws4_request")

    signature = hmac_sha256(signing_key, string_to_sign) |> Base.encode16(case: :lower)

    authorization = "AWS4-HMAC-SHA256 Credential=#{access_key}/#{credential_scope}, SignedHeaders=#{signed_header_names}, Signature=#{signature}"

    [
      {"authorization", authorization},
      {"x-amz-content-sha256", payload_hash},
      {"x-amz-date", amz_date}
    ]
  end

  defp hmac_sha256(key, data) do
    :crypto.mac(:hmac, :sha256, key, data)
  end
end
```

- [ ] **Step 2.2: Run test to verify it passes**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_tenant && mix test test/s3_upload_test.exs
```
Expected: 3 tests, 0 failures.

### Step 3: Enhance MnesiaBackup with daily S3 upload

- [ ] **Step 3.1: Update `init/1` in `src/pki_tenant/lib/pki_tenant/mnesia_backup.ex`**

Replace the full `init/1` function. The new version adds S3 config, age encryption config, and a daily upload timer:

```elixir
  def init(opts) do
    interval = opts[:interval_ms] || 3_600_000  # 1 hour default
    backup_dir = opts[:backup_dir] || Path.join(System.get_env("MNESIA_DIR", "/tmp/mnesia"), "backups")
    File.mkdir_p!(backup_dir)
    max_backups = opts[:max_backups] || 24

    s3_config = %{
      bucket: opts[:s3_bucket] || System.get_env("BACKUP_S3_BUCKET"),
      endpoint: opts[:s3_endpoint] || System.get_env("BACKUP_S3_ENDPOINT", "https://s3.amazonaws.com"),
      access_key: opts[:s3_access_key] || System.get_env("BACKUP_S3_ACCESS_KEY"),
      secret_key: opts[:s3_secret_key] || System.get_env("BACKUP_S3_SECRET_KEY"),
      region: opts[:s3_region] || System.get_env("BACKUP_S3_REGION", "us-east-1")
    }

    age_recipient = opts[:age_recipient] || System.get_env("BACKUP_AGE_RECIPIENT")
    upload_interval = opts[:upload_interval_ms] || 86_400_000  # 24 hours

    if opts[:start_timer] != false do
      Process.send_after(self(), :scheduled_backup, interval)

      if s3_config.bucket do
        Process.send_after(self(), :scheduled_upload, upload_interval)
      end
    end

    {:ok, %{
      interval: interval,
      backup_dir: backup_dir,
      max_backups: max_backups,
      last_backup_at: nil,
      s3_config: s3_config,
      age_recipient: age_recipient,
      upload_interval: upload_interval
    }}
  end
```

- [ ] **Step 3.2: Add the `handle_info(:scheduled_upload, ...)` clause**

Add after the existing `handle_info(:scheduled_backup, ...)`:

```elixir
  def handle_info(:scheduled_upload, state) do
    do_daily_upload(state)
    Process.send_after(self(), :scheduled_upload, state.upload_interval)
    {:noreply, state}
  end
```

- [ ] **Step 3.3: Add `upload_now/1` client function**

Add after `last_backup_time/1`:

```elixir
  def upload_now(server \\ __MODULE__) do
    GenServer.call(server, :upload_now, 60_000)
  end
```

- [ ] **Step 3.4: Add `handle_call(:upload_now, ...)` clause**

```elixir
  def handle_call(:upload_now, _from, state) do
    result = do_daily_upload(state)
    {:reply, result, state}
  end
```

- [ ] **Step 3.5: Add the `do_daily_upload/1` private function**

Add at the bottom of the module, before the final `end`:

```elixir
  defp do_daily_upload(state) do
    with {:ok, latest_path} <- find_latest_backup(state.backup_dir),
         {:ok, data} <- encrypt_backup(latest_path, state.age_recipient),
         :ok <- upload_to_s3(latest_path, data, state.s3_config) do
      record_backup(:remote, byte_size(data), s3_location(latest_path, state.s3_config))
      {:ok, latest_path}
    else
      {:error, :no_backups} ->
        Logger.warning("[backup] No local backups found for upload")
        {:error, :no_backups}

      {:error, :s3_not_configured} ->
        Logger.warning("[backup] S3 not configured, skipping upload")
        {:error, :s3_not_configured}

      {:error, reason} ->
        Logger.error("[backup] Daily upload failed: #{inspect(reason)}")
        record_backup_failure(:remote, reason)
        {:error, reason}
    end
  end

  defp find_latest_backup(dir) do
    case dir
         |> File.ls!()
         |> Enum.filter(&String.starts_with?(&1, "mnesia-"))
         |> Enum.sort()
         |> List.last() do
      nil -> {:error, :no_backups}
      file -> {:ok, Path.join(dir, file)}
    end
  end

  defp encrypt_backup(path, nil) do
    # No age recipient configured — upload unencrypted
    File.read(path)
  end

  defp encrypt_backup(path, recipient) do
    case System.cmd("age", ["-r", recipient, "-o", "-", path], stderr_to_stdout: true) do
      {output, 0} -> {:ok, output}
      {error, _} -> {:error, {:age_encrypt_failed, error}}
    end
  rescue
    e -> {:error, {:age_not_available, Exception.message(e)}}
  end

  defp upload_to_s3(_path, _data, %{bucket: nil}), do: {:error, :s3_not_configured}
  defp upload_to_s3(_path, _data, %{access_key: nil}), do: {:error, :s3_not_configured}

  defp upload_to_s3(path, data, s3_config) do
    filename = Path.basename(path)
    # Node name gives us tenant slug, e.g., pki_tenant_comp5@host -> comp5
    node_slug = node() |> to_string() |> String.split("@") |> hd() |> String.replace("pki_tenant_", "")
    s3_key = "tenant-#{node_slug}/#{filename}.age"

    PkiTenant.S3Upload.put_object(s3_config.bucket, s3_key, data, %{
      endpoint: s3_config.endpoint,
      access_key: s3_config.access_key,
      secret_key: s3_config.secret_key,
      region: s3_config.region
    })
  end

  defp s3_location(path, s3_config) do
    filename = Path.basename(path)
    node_slug = node() |> to_string() |> String.split("@") |> hd() |> String.replace("pki_tenant_", "")
    "s3://#{s3_config.bucket}/tenant-#{node_slug}/#{filename}.age"
  end

  defp record_backup(type, size_bytes, location) do
    alias PkiMnesia.Structs.BackupRecord

    record = BackupRecord.new(%{
      type: to_string(type),
      size_bytes: size_bytes,
      location: location,
      status: "completed"
    })

    PkiMnesia.Repo.insert(record)
  rescue
    _ -> :ok
  end

  defp record_backup_failure(type, reason) do
    alias PkiMnesia.Structs.BackupRecord

    record = BackupRecord.new(%{
      type: to_string(type),
      status: "failed",
      error: inspect(reason)
    })

    PkiMnesia.Repo.insert(record)
  rescue
    _ -> :ok
  end
```

- [ ] **Step 3.6: Run the full pki_tenant test suite**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_tenant && mix test
```
Expected: All tests pass.

- [ ] **Step 3.7: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_tenant/lib/pki_tenant/s3_upload.ex \
        src/pki_tenant/test/s3_upload_test.exs \
        src/pki_tenant/lib/pki_tenant/mnesia_backup.ex
git commit -m "feat: add S3 backup upload with age encryption and backup records"
```

---

## Task 4: CaddyConfigurator 3-Hostname + OCSP Dispatch

**Files:**
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/caddy_configurator.ex`
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/host_router.ex`
- Modify: `src/pki_tenant_web/test/host_router_test.exs`
- Create: `deploy/Caddyfile.template`

### Step 1: Update HostRouter for OCSP

- [ ] **Step 1.1: Add OCSP test cases to `src/pki_tenant_web/test/host_router_test.exs`**

Add these test cases inside the existing `describe "extract_service/1"` block:

```elixir
    test "returns :ocsp for slug.ocsp.domain" do
      assert HostRouter.extract_service("acme.ocsp.example.com") == :ocsp
    end

    test "returns :ocsp for slug.ocsp.domain.tld" do
      assert HostRouter.extract_service("tenant1.ocsp.pki.local") == :ocsp
    end
```

- [ ] **Step 1.2: Run test to verify it fails**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_tenant_web && mix test test/host_router_test.exs
```
Expected: 2 failures — `:ocsp` not recognized, returns `:unknown`.

- [ ] **Step 1.3: Update `extract_service/1` in `src/pki_tenant_web/lib/pki_tenant_web/host_router.ex`**

Replace the `extract_service/1` function:

```elixir
  @doc false
  def extract_service(host) do
    case host |> String.split(".") do
      [_slug, "ca" | _] -> :ca
      [_slug, "ra" | _] -> :ra
      [_slug, "ocsp" | _] -> :ocsp
      # For local dev: localhost defaults to CA
      ["localhost" | _] -> :ca
      _ -> :unknown
    end
  end
```

- [ ] **Step 1.4: Update the `call/2` function to handle `:ocsp`**

Replace the `call/2` function:

```elixir
  def call(conn, _opts) do
    case extract_service(conn.host) do
      :ca -> PkiTenantWeb.CaRouter.call(conn, PkiTenantWeb.CaRouter.init([]))
      :ra -> PkiTenantWeb.RaRouter.call(conn, PkiTenantWeb.RaRouter.init([]))
      :ocsp -> handle_ocsp(conn)
      _ -> conn |> send_resp(404, "Unknown service") |> halt()
    end
  end

  defp handle_ocsp(conn) do
    # OCSP requests are HTTP POST with DER-encoded request body
    # Delegate to PkiValidation.OcspResponder HTTP handler
    PkiTenantWeb.OcspPlug.call(conn, PkiTenantWeb.OcspPlug.init([]))
  rescue
    _ -> conn |> send_resp(500, "OCSP responder unavailable") |> halt()
  end
```

Note: `PkiTenantWeb.OcspPlug` is a thin Plug wrapper around `PkiValidation.OcspResponder`. If it doesn't exist yet, create a minimal one:

- [ ] **Step 1.5: Create OcspPlug if it doesn't exist**

Check if it exists first:
```bash
find /Users/amirrudinyahaya/Workspace/pki/src/pki_tenant_web -name "ocsp*" -type f
```

If not found, create it:

```elixir
# src/pki_tenant_web/lib/pki_tenant_web/ocsp_plug.ex
defmodule PkiTenantWeb.OcspPlug do
  @moduledoc """
  Plug that handles OCSP HTTP requests.
  Reads DER-encoded OCSP request from POST body,
  delegates to PkiValidation.OcspResponder.
  """
  import Plug.Conn

  def init(opts), do: opts

  def call(%{method: "POST"} = conn, _opts) do
    {:ok, body, conn} = Plug.Conn.read_body(conn)

    case PkiValidation.OcspResponder.handle_http_request(body) do
      {:ok, response_der} ->
        conn
        |> put_resp_content_type("application/ocsp-response")
        |> send_resp(200, response_der)
        |> halt()

      {:error, _reason} ->
        conn
        |> put_resp_content_type("application/ocsp-response")
        |> send_resp(500, "")
        |> halt()
    end
  end

  def call(conn, _opts) do
    conn
    |> send_resp(405, "Method Not Allowed")
    |> halt()
  end
end
```

- [ ] **Step 1.6: Run host router tests**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_tenant_web && mix test test/host_router_test.exs
```
Expected: All tests pass (including the 2 new OCSP tests).

### Step 2: Update CaddyConfigurator for 3 hostnames

- [ ] **Step 2.1: Replace `add_route/2` in `src/pki_platform_engine/lib/pki_platform_engine/caddy_configurator.ex`**

Replace the entire `add_route/2` function:

```elixir
  def add_route(slug, port) do
    ca_host = "#{slug}.ca.*"
    ra_host = "#{slug}.ra.*"
    ocsp_host = "#{slug}.ocsp.*"

    route = %{
      "@id": "route-#{slug}",
      match: [%{host: [ca_host, ra_host, ocsp_host]}],
      handle: [
        %{
          handler: "reverse_proxy",
          upstreams: [%{dial: "localhost:#{port}"}]
        }
      ]
    }

    case post_config("/config/apps/http/servers/srv0/routes", route) do
      :ok ->
        Logger.info("[caddy] Added route for #{slug} (ca+ra+ocsp) -> port #{port}")
        :ok

      {:error, reason} ->
        Logger.error("[caddy] Failed to add route for #{slug}: #{inspect(reason)}")
        {:error, reason}
    end
  end
```

- [ ] **Step 2.2: Verify CaddyConfigurator compiles**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_platform_engine && mix compile
```
Expected: Compilation succeeds.

### Step 3: Create Caddyfile template

- [ ] **Step 3.1: Create `deploy/Caddyfile.template`**

```
# Caddyfile.template — Base Caddy configuration for PKI system
#
# Build Caddy with GoDaddy DNS plugin:
#   xcaddy build --with github.com/caddy-dns/godaddy
#
# Environment variables required:
#   GODADDY_API_KEY     — GoDaddy API key
#   GODADDY_API_SECRET  — GoDaddy API secret
#
# Routes are added dynamically via Caddy admin API by CaddyConfigurator.
# This file only configures TLS automation and the admin API.

{
	admin localhost:2019
}

# TLS automation for wildcard certs (DNS-01 challenge via GoDaddy)
# Applied via admin API JSON config on boot:
#
# POST http://localhost:2019/config/apps/tls/automation/policies
# {
#   "subjects": ["*.ca.straptrust.com", "*.ra.straptrust.com", "*.ocsp.straptrust.com"],
#   "issuers": [{
#     "module": "acme",
#     "challenges": {
#       "dns": {
#         "provider": {
#           "name": "godaddy",
#           "api_token": "{env.GODADDY_API_KEY}:{env.GODADDY_API_SECRET}"
#         }
#       }
#     }
#   }]
# }
#
# Platform portal cert (regular HTTPS, not wildcard):
# POST http://localhost:2019/config/apps/http/servers/srv0/routes
# {
#   "@id": "route-platform",
#   "match": [{"host": ["platform.straptrust.com"]}],
#   "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "localhost:4000"}]}]
# }
```

### Step 4: Run all affected tests

- [ ] **Step 4.1: Run tenant web tests**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_tenant_web && mix test
```
Expected: All tests pass.

- [ ] **Step 4.2: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_platform_engine/lib/pki_platform_engine/caddy_configurator.ex \
        src/pki_tenant_web/lib/pki_tenant_web/host_router.ex \
        src/pki_tenant_web/lib/pki_tenant_web/ocsp_plug.ex \
        src/pki_tenant_web/test/host_router_test.exs \
        deploy/Caddyfile.template
git commit -m "feat: add OCSP hostname dispatch and 3-hostname Caddy routing"
```

---

## Task 5: LiveDashboard + Restore Runbook

**Files:**
- Modify: `src/pki_platform_portal/mix.exs`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/router.ex`
- Create: `deploy/RESTORE.md`

### Step 1: Add LiveDashboard dependency

- [ ] **Step 1.1: Add `phoenix_live_dashboard` to `src/pki_platform_portal/mix.exs`**

In the `deps/0` function, add this line inside the deps list (after the `{:phoenix_live_view, ...}` line):

```elixir
      {:phoenix_live_dashboard, "~> 0.8"},
```

- [ ] **Step 1.2: Fetch the dependency**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_platform_portal && mix deps.get
```
Expected: `phoenix_live_dashboard` fetched successfully.

### Step 2: Mount LiveDashboard in router

- [ ] **Step 2.1: Add import to `src/pki_platform_portal/lib/pki_platform_portal_web/router.ex`**

Add this import at the top of the module, after the `use PkiPlatformPortalWeb, :router` line:

```elixir
  import Phoenix.LiveDashboard.Router
```

- [ ] **Step 2.2: Add `/dashboard` route inside the authenticated scope**

In the protected routes scope (the `scope "/", PkiPlatformPortalWeb do ... pipe_through [:browser, :require_auth]` block), add the LiveDashboard route. Insert it after the `live_session :authenticated` block closing `end` but still inside the scope. Since LiveDashboard uses its own live_session, it goes outside the existing `live_session` block.

Add a new scope right after the existing protected scope block (after line 66, before the final `end`):

```elixir
  # LiveDashboard (auth-gated)
  scope "/" do
    pipe_through [:browser, :require_auth]

    live_dashboard "/dashboard",
      metrics: PkiPlatformPortalWeb.Telemetry,
      ecto_repos: []
  end
```

- [ ] **Step 2.3: Verify compilation**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_platform_portal && mix compile
```
Expected: Compilation succeeds. (If `PkiPlatformPortalWeb.Telemetry` doesn't exist, use `metrics: false` instead.)

### Step 3: Create restore runbook

- [ ] **Step 3.1: Create `deploy/RESTORE.md`**

```markdown
# Mnesia Backup Restore Procedure

## Prerequisites

- `age` CLI installed (`brew install age` or `apt install age`)
- AWS CLI or compatible S3 client (for downloading from object storage)
- Access to the tenant's age private key at `/etc/pki/age.key`
- Tenant node stopped

## Step 1: List available backups

```bash
aws s3 ls s3://$BACKUP_S3_BUCKET/tenant-$SLUG/
```

## Step 2: Download the backup

```bash
aws s3 cp s3://$BACKUP_S3_BUCKET/tenant-$SLUG/mnesia-2026-04-19T10-00-00Z.bak.age .
```

## Step 3: Decrypt the backup

```bash
age -d -i /etc/pki/age.key mnesia-2026-04-19T10-00-00Z.bak.age > mnesia.bak
```

If the backup was uploaded without age encryption (no `BACKUP_AGE_RECIPIENT` was set), skip this step — the `.age` file is actually unencrypted.

## Step 4: Stop the tenant node

Ensure the tenant BEAM process is stopped before restoring.

```bash
systemctl stop pki-tenant-$SLUG
```

## Step 5: Restore Mnesia

Start an IEx session pointing at the tenant's Mnesia directory:

```bash
MNESIA_DIR=/var/lib/pki/tenants/$SLUG/mnesia iex -S mix
```

In IEx:

```elixir
# Start Mnesia
:mnesia.start()

# Restore — recreate_tables overwrites existing data
:mnesia.restore(~c"mnesia.bak", [{:default_op, :recreate_tables}])

# Verify
:mnesia.system_info(:local_tables)

# Stop
:mnesia.stop()
```

## Step 6: Restart the tenant

```bash
systemctl start pki-tenant-$SLUG
```

## Step 7: Verify

Check the tenant health endpoint:

```bash
curl https://$SLUG.ca.straptrust.com/health
```

Expected: `{"status":"ok","mnesia":"running",...}`

## Notes

- The replica node will automatically re-sync from the restored primary via Mnesia replication.
- BackupRecord entries are part of the backup, so backup history is also restored.
- If restoring to a different server, ensure the Erlang node name matches the original or use `mnesia:change_table_copy_type/3` after restore.
```

- [ ] **Step 3.2: Run platform portal tests**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_platform_portal && mix test
```
Expected: All tests pass.

- [ ] **Step 3.3: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_platform_portal/mix.exs \
        src/pki_platform_portal/lib/pki_platform_portal_web/router.ex \
        deploy/RESTORE.md
git commit -m "feat: add LiveDashboard and backup restore runbook"
```

---

## Self-Review Checklist

### Spec coverage

| Spec requirement | Task |
|---|---|
| LiveDashboard at /dashboard, auth-gated | Task 5 Step 2 |
| Custom tenant health page (LiveDashboard) | Task 5 — noted as optional/future, basic LiveDashboard first |
| Platform /health JSON | Task 2 Step 5 |
| Tenant /health JSON | Task 2 Step 4 |
| PkiTenant.Health enhanced (active_keys, last_backup, uptime) | Task 2 Step 3 |
| BackupRecord Mnesia table | Task 1 |
| S3 upload via Req | Task 3 Step 2 |
| age encryption | Task 3 Step 3.5 (encrypt_backup) |
| Daily upload schedule | Task 3 Step 3.1 (upload_interval) |
| Restore runbook | Task 5 Step 3 |
| CaddyConfigurator 3 hostnames | Task 4 Step 2 |
| HostRouter :ocsp dispatch | Task 4 Step 1 |
| Caddyfile template | Task 4 Step 3 |
| GoDaddy DNS-01 config | Task 4 Step 3 (documented in Caddyfile.template) |

### Spec gaps

1. **Custom tenant health LiveDashboard page** — The spec describes a custom "Tenant Health" LiveDashboard page showing per-tenant status. Task 5 installs basic LiveDashboard. The custom page (`TenantDashboardLive`) is deferred as a follow-up since it requires Phoenix.LiveDashboard.PageBuilder which is complex and the basic dashboard provides immediate value. This is noted in the spec as optional.

2. **OcspPlug** — The spec assumes `PkiValidation.OcspResponder` has an `handle_http_request/1` function. If this doesn't exist yet, the OcspPlug will need adjustment. The task includes a check step.

### Type consistency check

- `BackupRecord.new/1` — used consistently in Task 1 (struct) and Task 3 (MnesiaBackup writes records)
- `PkiTenant.Health.check/0` — returns map with `:active_keys`, `:last_backup`, `:table_count` — consumed in Task 2 Step 4 (HealthJSON) and Step 5 (platform controller)
- `PkiTenant.S3Upload.put_object/4` — signature `(bucket, key, body, opts_map)` — consistent between Task 3 definition and Task 3 usage in MnesiaBackup
- `PkiTenant.MnesiaBackup.last_backup_time/1` — added in Task 2, called in Task 2 Health module
- `PkiCaEngine.KeyActivation.active_key_count/1` — added in Task 2, called in Task 2 Health module
- `PkiTenantWeb.OcspPlug` — created in Task 4, referenced in Task 4 HostRouter
