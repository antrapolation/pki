# BEAM Multi-Tenant Engine Provisioning — Implementation Plan (Foundation)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One BEAM node dynamically provisions CA/RA engine processes per tenant. Tenant activation starts engines automatically. Boot restores all active tenants.

**Architecture:** A `TenantSupervisor` (DynamicSupervisor) manages per-tenant `TenantProcess` supervisors. Each TenantProcess starts dynamic Ecto Repos connected to the tenant's database with the correct schema prefix. A `TenantRegistry` (ETS) provides fast lookup of tenant Repos by tenant_id. Engine modules accept a `tenant_id` parameter and resolve the dynamic Repo from the registry.

**Tech Stack:** Elixir, OTP (DynamicSupervisor, Supervisor, GenServer, ETS), Ecto dynamic repos, Phoenix LiveView

**Scope:** Phases 1-2, 4-5 from the design spec. Portal direct calls (Phase 3) and HTTP API tenant-awareness (Phase 6) are deferred to Plan B.

---

## Phase 1: Infrastructure

### Task 1: Create TenantRegistry (ETS-based lookup)

**Files:**
- Create: `src/pki_platform_engine/lib/pki_platform_engine/tenant_registry.ex`
- Test: `src/pki_platform_engine/test/pki_platform_engine/tenant_registry_test.exs`

The registry is a GenServer that owns an ETS table. It maps `tenant_id` to a map of PIDs/names for that tenant's Repos and Engine.

- [ ] **Step 1: Write test for TenantRegistry**

```elixir
defmodule PkiPlatformEngine.TenantRegistryTest do
  use ExUnit.Case, async: true

  alias PkiPlatformEngine.TenantRegistry

  setup do
    registry = start_supervised!({TenantRegistry, name: :"test_registry_#{System.unique_integer()}"})
    %{registry: registry}
  end

  test "register and lookup tenant", %{registry: registry} do
    tenant_id = "tenant-1"
    refs = %{ca_repo: self(), ra_repo: self(), audit_repo: self(), slug: "test-corp"}

    :ok = TenantRegistry.register(registry, tenant_id, refs)
    assert {:ok, ^refs} = TenantRegistry.lookup(registry, tenant_id)
  end

  test "lookup_by_slug returns tenant refs", %{registry: registry} do
    tenant_id = "tenant-2"
    refs = %{ca_repo: self(), ra_repo: self(), audit_repo: self(), slug: "slug-corp"}

    :ok = TenantRegistry.register(registry, tenant_id, refs)
    assert {:ok, ^refs} = TenantRegistry.lookup_by_slug(registry, "slug-corp")
  end

  test "lookup returns error for unregistered tenant", %{registry: registry} do
    assert {:error, :not_found} = TenantRegistry.lookup(registry, "unknown")
  end

  test "unregister removes tenant", %{registry: registry} do
    :ok = TenantRegistry.register(registry, "t1", %{ca_repo: self(), ra_repo: self(), audit_repo: self(), slug: "s1"})
    :ok = TenantRegistry.unregister(registry, "t1")
    assert {:error, :not_found} = TenantRegistry.lookup(registry, "t1")
  end

  test "list_tenants returns all registered", %{registry: registry} do
    :ok = TenantRegistry.register(registry, "t1", %{slug: "a"})
    :ok = TenantRegistry.register(registry, "t2", %{slug: "b"})
    tenants = TenantRegistry.list_tenants(registry)
    assert length(tenants) == 2
  end
end
```

- [ ] **Step 2: Implement TenantRegistry**

```elixir
defmodule PkiPlatformEngine.TenantRegistry do
  use GenServer

  # Client API

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  def register(registry \\ __MODULE__, tenant_id, refs) do
    GenServer.call(registry, {:register, tenant_id, refs})
  end

  def unregister(registry \\ __MODULE__, tenant_id) do
    GenServer.call(registry, {:unregister, tenant_id})
  end

  def lookup(registry \\ __MODULE__, tenant_id) do
    case :ets.lookup(ets_name(registry), {:id, tenant_id}) do
      [{_, refs}] -> {:ok, refs}
      [] -> {:error, :not_found}
    end
  end

  def lookup_by_slug(registry \\ __MODULE__, slug) do
    case :ets.lookup(ets_name(registry), {:slug, slug}) do
      [{_, tenant_id}] -> lookup(registry, tenant_id)
      [] -> {:error, :not_found}
    end
  end

  def ca_repo(registry \\ __MODULE__, tenant_id) do
    case lookup(registry, tenant_id) do
      {:ok, %{ca_repo: repo}} -> repo
      _ -> raise "No CA repo for tenant #{tenant_id}"
    end
  end

  def ra_repo(registry \\ __MODULE__, tenant_id) do
    case lookup(registry, tenant_id) do
      {:ok, %{ra_repo: repo}} -> repo
      _ -> raise "No RA repo for tenant #{tenant_id}"
    end
  end

  def audit_repo(registry \\ __MODULE__, tenant_id) do
    case lookup(registry, tenant_id) do
      {:ok, %{audit_repo: repo}} -> repo
      _ -> raise "No audit repo for tenant #{tenant_id}"
    end
  end

  def list_tenants(registry \\ __MODULE__) do
    :ets.match(ets_name(registry), {{:id, :"$1"}, :"$2"})
    |> Enum.map(fn [id, refs] -> Map.put(refs, :tenant_id, id) end)
  end

  # Server

  @impl true
  def init(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    table = :ets.new(ets_name(name), [:set, :public, :named_table, read_concurrency: true])
    {:ok, %{table: table, name: name}}
  end

  @impl true
  def handle_call({:register, tenant_id, refs}, _from, state) do
    :ets.insert(state.table, {{:id, tenant_id}, refs})
    if slug = refs[:slug], do: :ets.insert(state.table, {{:slug, slug}, tenant_id})
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:unregister, tenant_id}, _from, state) do
    case :ets.lookup(state.table, {:id, tenant_id}) do
      [{_, refs}] ->
        :ets.delete(state.table, {:id, tenant_id})
        if slug = refs[:slug], do: :ets.delete(state.table, {:slug, slug})
      [] -> :ok
    end
    {:reply, :ok, state}
  end

  defp ets_name(name) when is_atom(name), do: :"#{name}_ets"
  defp ets_name(pid) when is_pid(pid), do: :"tenant_registry_#{inspect(pid)}_ets"
end
```

- [ ] **Step 3: Run tests, commit**

```bash
cd src/pki_platform_engine && mix test test/pki_platform_engine/tenant_registry_test.exs
git add lib/pki_platform_engine/tenant_registry.ex test/pki_platform_engine/tenant_registry_test.exs
git commit -m "feat: add TenantRegistry — ETS-based tenant Repo lookup"
```

---

### Task 2: Create TenantProcess (per-tenant Supervisor)

**Files:**
- Create: `src/pki_platform_engine/lib/pki_platform_engine/tenant_process.ex`
- Test: `src/pki_platform_engine/test/pki_platform_engine/tenant_process_test.exs`

TenantProcess is a Supervisor that starts three dynamic Ecto Repo instances for a tenant (CA, RA, audit), each connected to the tenant's database with the correct `search_path`.

- [ ] **Step 1: Write test for TenantProcess**

```elixir
defmodule PkiPlatformEngine.TenantProcessTest do
  use ExUnit.Case

  alias PkiPlatformEngine.TenantProcess

  @tag :integration
  test "starts and registers repos for a tenant" do
    # Requires a running PostgreSQL with a tenant database
    # Use the existing dev database for testing
    tenant = %{
      id: "test-tenant-#{System.unique_integer([:positive])}",
      slug: "test-slug-#{System.unique_integer([:positive])}",
      database_name: "pki_ca_engine_dev"  # use dev DB for testing
    }

    registry = start_supervised!({PkiPlatformEngine.TenantRegistry, name: :"test_reg_#{System.unique_integer()}"})

    {:ok, pid} = TenantProcess.start_link(tenant: tenant, registry: registry)
    assert Process.alive?(pid)

    # Verify repos are registered
    {:ok, refs} = PkiPlatformEngine.TenantRegistry.lookup(registry, tenant.id)
    assert refs.ca_repo != nil
    assert refs.ra_repo != nil
    assert refs.audit_repo != nil

    # Clean up
    Supervisor.stop(pid)
  end
end
```

- [ ] **Step 2: Implement TenantProcess**

```elixir
defmodule PkiPlatformEngine.TenantProcess do
  @moduledoc """
  Per-tenant supervisor. Starts dynamic Ecto Repos connected to the tenant's
  database with schema-specific search_paths.
  """
  use Supervisor

  alias PkiPlatformEngine.TenantRegistry

  def start_link(opts) do
    tenant = Keyword.fetch!(opts, :tenant)
    registry = Keyword.get(opts, :registry, TenantRegistry)
    Supervisor.start_link(__MODULE__, {tenant, registry}, name: via(tenant.id))
  end

  def via(tenant_id), do: {:global, {__MODULE__, tenant_id}}

  @impl true
  def init({tenant, registry}) do
    base_config = base_repo_config(tenant.database_name)

    ca_repo_name = :"ca_repo_#{tenant.id}"
    ra_repo_name = :"ra_repo_#{tenant.id}"
    audit_repo_name = :"audit_repo_#{tenant.id}"

    children = [
      repo_child_spec(PkiPlatformEngine.DynamicRepo, ca_repo_name, base_config, "ca"),
      repo_child_spec(PkiPlatformEngine.DynamicRepo, ra_repo_name, base_config, "ra"),
      repo_child_spec(PkiPlatformEngine.DynamicRepo, audit_repo_name, base_config, "ca")
    ]

    # Register after children start
    Task.start(fn ->
      Process.sleep(500)  # Wait for repos to connect
      TenantRegistry.register(registry, tenant.id, %{
        ca_repo: ca_repo_name,
        ra_repo: ra_repo_name,
        audit_repo: audit_repo_name,
        slug: tenant.slug,
        tenant: tenant
      })
    end)

    Supervisor.init(children, strategy: :one_for_all)
  end

  defp base_repo_config(database_name) do
    platform_config = Application.get_env(:pki_platform_engine, PkiPlatformEngine.PlatformRepo, [])

    [
      hostname: Keyword.get(platform_config, :hostname, "localhost"),
      port: Keyword.get(platform_config, :port, 5434),
      username: Keyword.get(platform_config, :username, "postgres"),
      password: Keyword.get(platform_config, :password, "postgres"),
      database: database_name,
      pool_size: 5
    ]
  end

  defp repo_child_spec(repo_module, name, base_config, schema_prefix) do
    config =
      base_config
      |> Keyword.put(:name, name)
      |> Keyword.put(:after_connect, {Postgrex, :query!, ["SET search_path TO #{schema_prefix}", []]})

    %{
      id: name,
      start: {repo_module, :start_link, [config]},
      type: :supervisor
    }
  end
end
```

- [ ] **Step 3: Create DynamicRepo module**

```elixir
# src/pki_platform_engine/lib/pki_platform_engine/dynamic_repo.ex
defmodule PkiPlatformEngine.DynamicRepo do
  @moduledoc """
  A generic Ecto Repo that can be started multiple times with different configs.
  Used for per-tenant database connections.
  """
  use Ecto.Repo,
    otp_app: :pki_platform_engine,
    adapter: Ecto.Adapters.Postgres

  def init(_type, config) do
    {:ok, config}
  end
end
```

- [ ] **Step 4: Run tests, commit**

```bash
cd src/pki_platform_engine && mix test test/pki_platform_engine/tenant_process_test.exs
git add lib/pki_platform_engine/tenant_process.ex lib/pki_platform_engine/dynamic_repo.ex test/pki_platform_engine/tenant_process_test.exs
git commit -m "feat: add TenantProcess — per-tenant Supervisor with dynamic Repos"
```

---

### Task 3: Create TenantSupervisor (DynamicSupervisor)

**Files:**
- Create: `src/pki_platform_engine/lib/pki_platform_engine/tenant_supervisor.ex`
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/application.ex`

- [ ] **Step 1: Implement TenantSupervisor**

```elixir
defmodule PkiPlatformEngine.TenantSupervisor do
  @moduledoc """
  DynamicSupervisor that manages TenantProcess children.
  """
  use DynamicSupervisor

  alias PkiPlatformEngine.{TenantProcess, TenantRegistry}

  def start_link(opts \\ []) do
    DynamicSupervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    DynamicSupervisor.init(strategy: :one_for_one)
  end

  @doc "Start engine processes for a tenant."
  def start_tenant(tenant, registry \\ TenantRegistry) do
    case DynamicSupervisor.start_child(__MODULE__, {TenantProcess, tenant: tenant, registry: registry}) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Stop engine processes for a tenant."
  def stop_tenant(tenant_id, registry \\ TenantRegistry) do
    TenantRegistry.unregister(registry, tenant_id)

    case GenServer.whereis(TenantProcess.via(tenant_id)) do
      nil -> :ok
      pid -> DynamicSupervisor.terminate_child(__MODULE__, pid)
    end
  end

  @doc "Start engine processes for all active tenants."
  def boot_active_tenants(registry \\ TenantRegistry) do
    PkiPlatformEngine.Provisioner.list_tenants()
    |> Enum.filter(&(&1.status == "active"))
    |> Enum.each(fn tenant ->
      case start_tenant(tenant, registry) do
        {:ok, _} ->
          require Logger
          Logger.info("[TenantSupervisor] Started engines for tenant #{tenant.name} (#{tenant.slug})")
        {:error, reason} ->
          require Logger
          Logger.error("[TenantSupervisor] Failed to start tenant #{tenant.name}: #{inspect(reason)}")
      end
    end)
  end
end
```

- [ ] **Step 2: Add to Application supervision tree**

In `src/pki_platform_engine/lib/pki_platform_engine/application.ex`:

```elixir
defmodule PkiPlatformEngine.Application do
  use Application

  def start(_type, _args) do
    children = [
      PkiPlatformEngine.PlatformRepo,
      PkiPlatformEngine.EmailVerification,
      PkiPlatformEngine.TenantRegistry,
      PkiPlatformEngine.TenantSupervisor
    ]

    opts = [strategy: :one_for_one, name: PkiPlatformEngine.Supervisor]
    result = Supervisor.start_link(children, opts)

    # Boot active tenants async (after supervisor is ready)
    Task.start(fn ->
      Process.sleep(1_000)
      PkiPlatformEngine.TenantSupervisor.boot_active_tenants()
    end)

    result
  end
end
```

- [ ] **Step 3: Commit**

```bash
git add lib/pki_platform_engine/tenant_supervisor.ex lib/pki_platform_engine/application.ex
git commit -m "feat: add TenantSupervisor — boots active tenants on startup"
```

---

### Task 4: Wire Activation to Start Tenant Engines

**Files:**
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_detail_live.ex`

- [ ] **Step 1: Update Provisioner.activate_tenant**

```elixir
def activate_tenant(tenant_id) do
  case PlatformRepo.get(Tenant, tenant_id) do
    nil -> {:error, :not_found}
    tenant ->
      # Start tenant engine processes
      case TenantSupervisor.start_tenant(tenant) do
        {:ok, _pid} ->
          # Wait for repos to connect
          Process.sleep(1_000)

          # Update status
          tenant
          |> Tenant.changeset(%{status: "active"})
          |> PlatformRepo.update()

        {:error, reason} ->
          {:error, {:engine_start_failed, reason}}
      end
  end
end
```

- [ ] **Step 2: Update tenant_detail_live to create admins after activation**

The `handle_info(:do_activate)` function should use `TenantRegistry` to check if engines are running instead of HTTP health checks. After activation, create admins using the engine's user management module directly (via the tenant's Repo):

```elixir
# Replace engine_reachable? HTTP check with TenantRegistry lookup
defp engines_running?(tenant_id) do
  case PkiPlatformEngine.TenantRegistry.lookup(tenant_id) do
    {:ok, _refs} -> true
    {:error, :not_found} -> false
  end
end
```

The admin creation still uses HTTP calls for now (Phase 3 will replace with direct calls). But the engine health check uses TenantRegistry.

- [ ] **Step 3: Update suspend_tenant to stop engines**

```elixir
def suspend_tenant(tenant_id) do
  case PlatformRepo.get(Tenant, tenant_id) do
    nil -> {:error, :not_found}
    tenant ->
      TenantSupervisor.stop_tenant(tenant_id)

      tenant
      |> Tenant.changeset(%{status: "suspended"})
      |> PlatformRepo.update()
  end
end
```

- [ ] **Step 4: Commit**

```bash
git add lib/pki_platform_engine/provisioner.ex
git add src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_detail_live.ex
git commit -m "feat: wire tenant activation to start/stop engine processes"
```

---

## Phase 2: Engine Tenant-Awareness

### Task 5: Make CA Engine Modules Accept tenant_id and Use Dynamic Repo

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/ca_instance_management.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/issuer_key_management.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/keystore_management.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/user_management.ex`
- Create: `src/pki_ca_engine/lib/pki_ca_engine/tenant_repo.ex`

The pattern: each public function gets a `tenant_id` parameter (first arg). A helper resolves the dynamic Repo. The existing `PkiCaEngine.Repo` stays as a fallback for tests and backward compat.

- [ ] **Step 1: Create tenant_repo helper**

```elixir
# src/pki_ca_engine/lib/pki_ca_engine/tenant_repo.ex
defmodule PkiCaEngine.TenantRepo do
  @moduledoc """
  Resolves the correct Ecto Repo for a tenant.
  Falls back to PkiCaEngine.Repo when no tenant context is provided.
  """

  def ca_repo(nil), do: PkiCaEngine.Repo
  def ca_repo(tenant_id) do
    case PkiPlatformEngine.TenantRegistry.lookup(tenant_id) do
      {:ok, %{ca_repo: repo}} -> repo
      {:error, :not_found} -> PkiCaEngine.Repo
    end
  end

  def ra_repo(nil), do: PkiRaEngine.Repo
  def ra_repo(tenant_id) do
    case PkiPlatformEngine.TenantRegistry.lookup(tenant_id) do
      {:ok, %{ra_repo: repo}} -> repo
      {:error, :not_found} -> PkiRaEngine.Repo
    end
  end

  def audit_repo(nil), do: PkiAuditTrail.Repo
  def audit_repo(tenant_id) do
    case PkiPlatformEngine.TenantRegistry.lookup(tenant_id) do
      {:ok, %{audit_repo: repo}} -> repo
      {:error, :not_found} -> PkiAuditTrail.Repo
    end
  end
end
```

- [ ] **Step 2: Update CaInstanceManagement to use dynamic Repo**

Add `tenant_id` as first parameter to all public functions. Replace `Repo` with `repo = PkiCaEngine.TenantRepo.ca_repo(tenant_id)`. Keep `Repo` calls in private functions that receive `repo` as a parameter.

Example for `create_ca_instance`:

```elixir
def create_ca_instance(tenant_id, attrs, opts \\ []) do
  repo = PkiCaEngine.TenantRepo.ca_repo(tenant_id)
  max_depth = Keyword.get(opts, :max_ca_depth, 2)

  parent_id = Map.get(attrs, :parent_id) || Map.get(attrs, "parent_id")

  case parent_id do
    nil ->
      %CaInstance{} |> CaInstance.changeset(attrs) |> repo.insert()

    parent_id ->
      case repo.get(CaInstance, parent_id) do
        nil -> {:error, :parent_not_found}
        parent ->
          if depth(repo, parent) >= max_depth do
            {:error, :max_depth_exceeded}
          else
            %CaInstance{} |> CaInstance.changeset(attrs) |> repo.insert()
          end
      end
  end
end
```

Apply the same pattern to: `get_ca_instance`, `is_leaf?`, `depth`, `role`, `list_hierarchy`, `update_status`, `rename`, `leaf_ca_issuer_keys`, `active_leaf_issuer_keys`.

For functions that take a struct (like `is_leaf?(%CaInstance{})`), add an overload that also accepts `repo`:

```elixir
def is_leaf?(repo \\ Repo, %CaInstance{} = ca) do
  not repo.exists?(from c in CaInstance, where: c.parent_id == ^ca.id)
end
```

- [ ] **Step 3: Update other CA engine modules similarly**

Apply the same `tenant_id` → `repo` pattern to:
- `IssuerKeyManagement` — all public functions get `tenant_id`
- `KeystoreManagement` — `list_keystores`, `get_keystore`, `configure_keystore`
- `CertificateSigning` — `sign_certificate` gets `tenant_id`
- `UserManagement` — all public functions get `tenant_id`

- [ ] **Step 4: Commit**

```bash
git add src/pki_ca_engine/lib/
git commit -m "feat: make CA engine modules tenant-aware with dynamic Repo lookup"
```

---

### Task 6: Make RA Engine Modules Accept tenant_id

**Files:**
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/ra_instance_management.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/csr_validation.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/cert_profile_config.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/user_management.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/api_key_management.ex`

Same pattern as Task 5. Each public function gets `tenant_id` as first param. Use `PkiCaEngine.TenantRepo.ra_repo(tenant_id)` to resolve the dynamic Repo.

- [ ] **Step 1: Update all RA engine modules**

Apply `tenant_id` → `repo` pattern to all public functions in each module.

- [ ] **Step 2: Commit**

```bash
git add src/pki_ra_engine/lib/
git commit -m "feat: make RA engine modules tenant-aware with dynamic Repo lookup"
```

---

### Task 7: Update CA/RA Engine HTTP Controllers to Pass tenant_id

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/api/auth_plug.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/api/ca_instance_controller.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/api/issuer_key_controller.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/api/certificate_controller.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/api/ceremony_controller.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/api/keystore_controller.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/api/user_controller.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/api/auth_plug.ex`
- Modify: All RA engine controllers

- [ ] **Step 1: Update auth plugs to extract tenant_id from header**

```elixir
# In auth_plug.ex, after verifying the secret:
tenant_id = List.first(get_req_header(conn, "x-tenant-id"))
conn = assign(conn, :tenant_id, tenant_id)
```

- [ ] **Step 2: Update all controllers to pass tenant_id to engine modules**

```elixir
# Example in CaInstanceController:
def index(conn) do
  tenant_id = conn.assigns[:tenant_id]
  instances = CaInstanceManagement.list_hierarchy(tenant_id)
  json(conn, 200, Enum.map(instances, &serialize_tree/1))
end
```

Apply to all controllers in both CA and RA engines.

- [ ] **Step 3: Commit**

```bash
git add src/pki_ca_engine/lib/pki_ca_engine/api/ src/pki_ra_engine/lib/pki_ra_engine/api/
git commit -m "feat: pass tenant_id through HTTP controllers to engine modules"
```

---

### Task 8: Update Portal LiveViews to Pass tenant_id

**Files:**
- Modify: All CA portal LiveViews (`dashboard_live.ex`, `users_live.ex`, `keystores_live.ex`, `ceremony_live.ex`, `ca_instances_live.ex`, `audit_log_live.ex`, `quick_setup_live.ex`)
- Modify: All RA portal LiveViews
- Modify: CA/RA portal HTTP client to include `X-Tenant-ID` header

- [ ] **Step 1: Update CaEngineClient.Http to send X-Tenant-ID header**

The portal needs to know the tenant_id. It comes from the session. Update the `auth_get`/`auth_post` helpers to include the tenant header:

```elixir
defp auth_get(path, opts \\ []) do
  tenant_id = Keyword.get(opts, :tenant_id)
  headers = [{"authorization", "Bearer #{api_secret()}"}]
  headers = if tenant_id, do: [{"x-tenant-id", tenant_id} | headers], else: headers
  # ...
end
```

- [ ] **Step 2: Update LiveViews to read tenant_id from session and pass to client**

Each LiveView mount reads `tenant_id` from `socket.assigns.current_user` (set by AuthHook) and passes it to engine client calls.

- [ ] **Step 3: Commit**

```bash
git add src/pki_ca_portal/ src/pki_ra_portal/
git commit -m "feat: portal LiveViews pass tenant_id via HTTP headers to engines"
```

---

### Task 9: Test End-to-End

- [ ] **Step 1: Start the platform portal (all engines auto-start for active tenants)**

```bash
cd src/pki_platform_portal
POSTGRES_PORT=5434 SECRET_KEY_BASE=... mix phx.server
```

- [ ] **Step 2: Create a tenant via admin portal → tenant database is provisioned**

- [ ] **Step 3: Activate the tenant → engines start automatically (check TenantRegistry)**

- [ ] **Step 4: Login to CA portal → verify CA instances page works (uses dynamic Repo)**

- [ ] **Step 5: Run Quick Setup → verify key ceremony works against tenant's database**

- [ ] **Step 6: Create second tenant → activate → both tenants served simultaneously**

- [ ] **Step 7: Commit any fixes**

```bash
git add -A && git commit -m "fix: end-to-end fixes for multi-tenant engine provisioning"
```

---

## Summary

| Task | What it delivers |
|---|---|
| 1. TenantRegistry | ETS lookup: tenant_id → Repo PIDs |
| 2. TenantProcess | Per-tenant Supervisor with dynamic Repos |
| 3. TenantSupervisor | DynamicSupervisor + boot active tenants |
| 4. Activation wiring | Activate → start engines → create admins |
| 5. CA engine tenant-aware | All CA modules accept tenant_id |
| 6. RA engine tenant-aware | All RA modules accept tenant_id |
| 7. HTTP controllers | Pass tenant_id from headers to modules |
| 8. Portal LiveViews | Pass tenant_id from session to engines |
| 9. E2E test | Verify everything works together |

**Total: 9 tasks.** After this, one BEAM node serves all tenants. No more manually starting engines per tenant.

**Deferred to Plan B:**
- Replace HTTP client calls with direct Elixir calls in portals
- Full HTTP API tenant-awareness for external consumers
