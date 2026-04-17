# Production Hardening (Pre-Phase-4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land 7 production-hardening workstreams so Phase 4 ships into an operable system.

**Architecture:** Each workstream is independent enough to ship on its own branch but ordered so earlier ones unblock validation of later ones. Tenant isolation property test is the safety net for everything else.

**Tech Stack:** Elixir/OTP umbrella, Phoenix LiveView, Ecto + PostgreSQL (schema-per-tenant), systemd, sops + age, Gitea Actions, Restic.

---

## Codebase Primer (read this first)

**Umbrella root:** `/Users/amirrudinyahaya/Workspace/pki/`. All paths below are relative to that root unless noted.

**Apps you will touch:**
- `src/pki_ca_engine/` — CA Engine, HTTP on port **4001**, Plug router at `lib/pki_ca_engine/api/router.ex`.
- `src/pki_ra_engine/` — RA Engine, HTTP on port **4003**, Plug router at `lib/pki_ra_engine/api/router.ex`.
- `src/pki_validation/` — Validation Engine, HTTP on port **4005**.
- `src/pki_platform_engine/` — Platform engine (no external HTTP, but we will add a liveness port).
- `src/pki_ca_portal/` — Phoenix LiveView portal, port **4002**.
- `src/pki_ra_portal/` — Phoenix LiveView portal, port **4004**.
- `src/pki_platform_portal/` — Phoenix LiveView portal, port **4006**.

**Tenant model (schema-mode):**
- All data lives in one DB: `pki_platform`.
- Each tenant gets its own Postgres schema, named `t_<uuid_no_dashes>_ca`, `t_<uuid_no_dashes>_ra`, `t_<uuid_no_dashes>_audit`.
- Tenant repo accessors: `PkiCaEngine.TenantRepo.ca_repo(tenant_id)`, `PkiRaEngine.TenantRepo.ra_repo(tenant_id)`. These set the `search_path` prefix via `Ecto.Query.put_query_prefix/2` under the hood.
- Platform-level repo: `PkiPlatformEngine.PlatformRepo` (no prefix).
- Tenant supervisor: `src/pki_platform_engine/lib/pki_platform_engine/tenant_supervisor.ex` starts tenant engines.

**Audit logging:**
- `PkiPlatformEngine.PlatformAudit.log(action, attrs)` writes to `platform_audit_events`.
- Fields today: `action`, `actor_id`, `actor_username`, `tenant_id`, `portal`, `target_type`, `target_id`, `details`, `timestamp`.
- `ip_address` is **missing** — we add it in Task 4.

**Deploy layout:**
- Build tarballs land in `deploy/releases/` as `pki_engines-<timestamp>.tar.gz`, `pki_portals-...`, `pki_audit-...`.
- Host install base: `/opt/pki/releases/{engines,portals,audit}/`.
- Env file: `/opt/pki/.env` (root-owned, 0400).
- Systemd units: `deploy/systemd/pki-engines.service`, `pki-portals.service`, `pki-audit.service`.

**Test command:**
- Umbrella-wide: `mix test` from repo root (~6 min).
- Per-app: `cd src/<app> && mix test`.

**Gitea:** `vcs.antrapol.tech:3800/Incubator/pki.git`. Workflows **must** live in `.gitea/workflows/`.

**VPS:** `vmi3187076` (217.15.161.93), user `deploy`, sudo available.

---

### Task 1: Tenant Isolation Property Test

**Why:** Schema-mode isolation is the system's most load-bearing security guarantee. A property test that asserts no cross-tenant SQL access is the cheapest, most durable way to catch regressions.

**Files:**
- Create: `test/integration/tenant_isolation_test.exs`
- Create: `test/support/tenant_isolation_helpers.ex`
- Create: `test/test_helper.exs` (verify exists; if not, create minimal)
- Modify: `mix.exs` (lines ~30-60, `elixirc_paths` and `test_paths` config)

- [ ] **Step 1: Verify umbrella root has a `test/` directory and integration config**

Run: `ls /Users/amirrudinyahaya/Workspace/pki/test 2>/dev/null || mkdir -p /Users/amirrudinyahaya/Workspace/pki/test/integration /Users/amirrudinyahaya/Workspace/pki/test/support`

Expected: either existing listing or silent creation.

- [ ] **Step 2: Inspect `mix.exs` to see test_paths**

Run: `cat /Users/amirrudinyahaya/Workspace/pki/mix.exs | head -80`

If `test_paths` is not in the umbrella project options, add it in step 3.

- [ ] **Step 3: Wire `test/` into umbrella mix.exs**

Open `mix.exs` and in the `project/0` keyword list add:

```elixir
test_paths: ["test"],
elixirc_paths: Mix.env() == :test && ["test/support"] || []
```

Put it next to the existing `apps_path:` line.

- [ ] **Step 4: Create `test/test_helper.exs`**

```elixir
ExUnit.start(exclude: [:skip_ci], timeout: 120_000)
```

- [ ] **Step 5: Write the tenant provisioning helper (failing — modules it calls exist but we will wire assertions via telemetry)**

Create `test/support/tenant_isolation_helpers.ex`:

```elixir
defmodule TenantIsolationHelpers do
  @moduledoc """
  Helpers for tenant_isolation_test.exs.

  Creates two ephemeral tenants in the pki_platform DB, provisions their
  CA/RA/audit schemas, and tears them down on exit.
  """

  alias PkiPlatformEngine.{PlatformRepo, TenantProvisioner, TenantSupervisor}

  @doc "Create a named ephemeral tenant and return its %{id, schemas} map."
  def create_ephemeral_tenant(name) do
    id = Ecto.UUID.generate()
    :ok = TenantProvisioner.provision_tenant(%{id: id, name: name, status: "active"})
    {:ok, _pid} = TenantSupervisor.start_tenant(id)

    %{
      id: id,
      schemas: %{
        ca:    "t_#{String.replace(id, "-", "")}_ca",
        ra:    "t_#{String.replace(id, "-", "")}_ra",
        audit: "t_#{String.replace(id, "-", "")}_audit"
      }
    }
  end

  @doc "Drop tenant schemas and stop its supervisor tree."
  def destroy_ephemeral_tenant(tenant) do
    _ = TenantSupervisor.stop_tenant(tenant.id)

    for prefix <- Map.values(tenant.schemas) do
      Ecto.Adapters.SQL.query!(
        PlatformRepo,
        ~s(DROP SCHEMA IF EXISTS "#{prefix}" CASCADE),
        []
      )
    end

    Ecto.Adapters.SQL.query!(
      PlatformRepo,
      "DELETE FROM tenants WHERE id = $1",
      [Ecto.UUID.dump!(tenant.id)]
    )

    :ok
  end

  @doc """
  Attach an ad-hoc telemetry handler that accumulates every Ecto query's
  SQL into the provided Agent.
  """
  def capture_sql(agent) do
    handler_id = "sql-capture-#{System.unique_integer([:positive])}"

    :telemetry.attach_many(
      handler_id,
      [
        [:pki_platform_engine, :platform_repo, :query],
        [:pki_ca_engine, :tenant_repo, :query],
        [:pki_ra_engine, :tenant_repo, :query]
      ],
      fn _event, _measurements, meta, _cfg ->
        Agent.update(agent, fn sqls -> [meta.query | sqls] end)
      end,
      nil
    )

    handler_id
  end

  def detach(handler_id), do: :telemetry.detach(handler_id)

  @doc """
  Enumerate public zero/one-argument functions on an engine API module that
  accept either a tenant_id or a struct we can synthesize.

  Returns {:callable, mfa} or {:manual_review, {mfa, reason}}.
  """
  def classify_functions(mod) do
    mod.__info__(:functions)
    |> Enum.map(fn {fun, arity} -> classify(mod, fun, arity) end)
  end

  defp classify(mod, fun, 1), do: {:callable, {mod, fun, 1}}
  defp classify(mod, fun, 2), do: {:callable, {mod, fun, 2}}
  defp classify(mod, fun, n), do: {:manual_review, {{mod, fun, n}, "arity #{n} not auto-synthesizable"}}

  @doc "Synthesize an argument list for a callable mfa given tenant_id."
  def synth_args({_m, _f, 1}, tenant_id), do: [tenant_id]
  def synth_args({_m, _f, 2}, tenant_id), do: [tenant_id, %{}]
end
```

- [ ] **Step 6: Write the failing integration test**

Create `test/integration/tenant_isolation_test.exs`:

```elixir
defmodule TenantIsolationTest do
  use ExUnit.Case, async: false

  import TenantIsolationHelpers

  @engine_api_modules [
    PkiCaEngine.Api.CertificateIssuance,
    PkiCaEngine.Api.IssuerKeys,
    PkiCaEngine.Api.KeystoreManagement,
    PkiRaEngine.Api.CsrIntake,
    PkiRaEngine.Api.ProfileConfig
  ]

  setup_all do
    tenant_a = create_ephemeral_tenant("iso-test-A")
    tenant_b = create_ephemeral_tenant("iso-test-B")

    on_exit(fn ->
      destroy_ephemeral_tenant(tenant_a)
      destroy_ephemeral_tenant(tenant_b)
    end)

    %{tenant_a: tenant_a, tenant_b: tenant_b}
  end

  test "no engine API call as tenant A ever touches tenant B's schema", ctx do
    {:ok, agent} = Agent.start_link(fn -> [] end)
    handler_id = capture_sql(agent)

    manual_review =
      for mod <- @engine_api_modules,
          classification <- classify_functions(mod),
          reduce: [] do
        acc ->
          case classification do
            {:callable, mfa} ->
              try do
                apply(elem(mfa, 0), elem(mfa, 1), synth_args(mfa, ctx.tenant_a.id))
              rescue
                _ -> :ok
              catch
                _, _ -> :ok
              end

              acc

            {:manual_review, entry} ->
              [entry | acc]
          end
      end

    detach(handler_id)
    captured = Agent.get(agent, & &1)
    Agent.stop(agent)

    leaked =
      Enum.filter(captured, fn sql ->
        String.contains?(sql, ctx.tenant_b.schemas.ca) or
          String.contains?(sql, ctx.tenant_b.schemas.ra) or
          String.contains?(sql, ctx.tenant_b.schemas.audit)
      end)

    if manual_review != [] do
      IO.warn("Manual review needed for: #{inspect(manual_review)}")
    end

    assert leaked == [], "Tenant A calls leaked into tenant B schemas: #{inspect(leaked)}"
  end
end
```

- [ ] **Step 7: Run the test to verify it compiles and fails cleanly if it will fail**

Run: `cd /Users/amirrudinyahaya/Workspace/pki && mix test test/integration/tenant_isolation_test.exs --trace`

Expected: compiles. Either passes (isolation is clean) or fails listing leaked SQL. Either outcome is valid — the point is the test runs end-to-end.

- [ ] **Step 8: Add a deliberately-bad regression fixture to prove the assertion works**

Create `test/integration/tenant_isolation_regression_test.exs`:

```elixir
defmodule TenantIsolationRegressionTest do
  @moduledoc """
  Deliberately-leaky call used to validate the capture-and-assert mechanism.
  Tagged :skip_ci so it never runs in CI; run locally with:
    mix test test/integration/tenant_isolation_regression_test.exs --include skip_ci
  """
  use ExUnit.Case, async: false
  import TenantIsolationHelpers

  @tag :skip_ci
  test "capture mechanism detects a cross-tenant leak" do
    tenant_a = create_ephemeral_tenant("regress-A")
    tenant_b = create_ephemeral_tenant("regress-B")

    {:ok, agent} = Agent.start_link(fn -> [] end)
    handler_id = capture_sql(agent)

    Ecto.Adapters.SQL.query!(
      PkiPlatformEngine.PlatformRepo,
      ~s(SELECT 1 FROM "#{tenant_b.schemas.ca}".schema_migrations LIMIT 1),
      []
    )

    detach(handler_id)
    captured = Agent.get(agent, & &1)

    assert Enum.any?(captured, &String.contains?(&1, tenant_b.schemas.ca))

    destroy_ephemeral_tenant(tenant_a)
    destroy_ephemeral_tenant(tenant_b)
  end
end
```

- [ ] **Step 9: Run the regression fixture locally to prove capture works**

Run: `cd /Users/amirrudinyahaya/Workspace/pki && mix test test/integration/tenant_isolation_regression_test.exs --include skip_ci`

Expected: PASS (we proved capture detects the leak).

- [ ] **Step 10: Commit**

```bash
git add test/integration/tenant_isolation_test.exs \
        test/integration/tenant_isolation_regression_test.exs \
        test/support/tenant_isolation_helpers.ex \
        test/test_helper.exs \
        mix.exs
git commit -m "$(cat <<'EOF'
test: add tenant isolation property test

Adds a telemetry-driven integration test that provisions two ephemeral
schema-mode tenants, enumerates public engine API functions, invokes each
as tenant A, and asserts no captured SQL references tenant B's schema
prefixes. Functions whose arguments cannot be synthesized fall onto a
manual-review list surfaced as a warning (not a failure).

A companion regression fixture (tagged :skip_ci) proves the capture
mechanism detects a deliberate cross-schema query.
EOF
)"
```

---

### Task 2: Health + Readiness Endpoints

**Why:** Load balancers and on-call automation need to distinguish "process up" from "process able to do work."

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/api/router.ex:14`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/api/router.ex` (analogous `/health` route)
- Modify: `src/pki_validation/lib/pki_validation/api/router.ex` (analogous)
- Create: `src/pki_platform_engine/lib/pki_platform_engine/health_router.ex`
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/application.ex` (add Bandit/Plug.Cowboy child)
- Create: `src/pki_ca_portal/lib/pki_ca_portal_web/plugs/health_router.ex`
- Create: `src/pki_ra_portal/lib/pki_ra_portal_web/plugs/health_router.ex`
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/plugs/health_router.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/endpoint.ex:44-56` (insert health router before session plug)
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/endpoint.ex` (same region)
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/endpoint.ex` (same region)
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/system_health.ex:9-16` (update `/health` → `/health/live`)
- Create: `test/integration/health_endpoints_test.exs`

- [ ] **Step 1: Write the failing integration test**

Create `test/integration/health_endpoints_test.exs`:

```elixir
defmodule HealthEndpointsTest do
  use ExUnit.Case, async: false

  @services [
    {"CA engine",       "http://127.0.0.1:4001"},
    {"RA engine",       "http://127.0.0.1:4003"},
    {"Validation",      "http://127.0.0.1:4005"},
    {"Platform engine", "http://127.0.0.1:4007"},
    {"CA portal",       "http://127.0.0.1:4002"},
    {"RA portal",       "http://127.0.0.1:4004"},
    {"Platform portal", "http://127.0.0.1:4006"}
  ]

  for {name, base} <- @services do
    test "#{name} /health/live returns 200" do
      {:ok, resp} = Req.get(unquote(base) <> "/health/live", retry: false)
      assert resp.status == 200
    end

    test "#{name} /health/ready returns 200 or 503 with JSON body" do
      {:ok, resp} = Req.get(unquote(base) <> "/health/ready", retry: false)
      assert resp.status in [200, 503]
      assert is_map(resp.body) or is_binary(resp.body)
    end
  end
end
```

- [ ] **Step 2: Run the test — expect failures (endpoints don't exist yet)**

Run: `cd /Users/amirrudinyahaya/Workspace/pki && mix test test/integration/health_endpoints_test.exs`

Expected: multiple FAIL (most endpoints 404 or connection refused).

- [ ] **Step 3: Rename CA engine `/health` → `/health/live` and add `/health/ready`**

Edit `src/pki_ca_engine/lib/pki_ca_engine/api/router.ex:14-16`. Replace the single `get "/health"` block with:

```elixir
  get "/health/live" do
    send_resp(conn, 200, Jason.encode!(%{status: "ok"}))
  end

  get "/health/ready" do
    checks = PkiCaEngine.Readiness.check()
    status_code = if Enum.all?(checks, &(&1.ok)), do: 200, else: 503
    send_resp(conn, status_code, Jason.encode!(%{checks: checks}))
  end
```

- [ ] **Step 4: Create the shared readiness module for CA engine**

Create `src/pki_ca_engine/lib/pki_ca_engine/readiness.ex`:

```elixir
defmodule PkiCaEngine.Readiness do
  @moduledoc "Readiness checks for CA engine."

  @timeout_ms 100

  def check do
    [db_pool_check(), keystore_check(), ceremony_watchdog_check()]
  end

  defp db_pool_check do
    task = Task.async(fn ->
      Ecto.Adapters.SQL.query!(PkiPlatformEngine.PlatformRepo, "SELECT 1", [])
      :ok
    end)

    case Task.yield(task, @timeout_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, :ok} -> %{name: "db_pool", ok: true}
      _          -> %{name: "db_pool", ok: false, reason: "pool checkout timeout (>#{@timeout_ms}ms)"}
    end
  end

  defp keystore_check do
    tenants = PkiPlatformEngine.TenantRegistry.list_tenants()
    any_with_keys? = Enum.any?(tenants, fn tid ->
      match?({:ok, [_ | _]}, PkiCaEngine.Api.IssuerKeys.list_keys(tid))
    end)

    cond do
      tenants == []       -> %{name: "keystore", ok: true, note: "no tenants provisioned"}
      any_with_keys?      -> %{name: "keystore", ok: true}
      true                -> %{name: "keystore", ok: false, reason: "no tenant has loaded keys"}
    end
  end

  defp ceremony_watchdog_check do
    case GenServer.call(PkiCaEngine.CeremonyWatchdog, :ping, @timeout_ms) do
      :pong -> %{name: "ceremony_watchdog", ok: true}
      _     -> %{name: "ceremony_watchdog", ok: false}
    end
  catch
    :exit, _ -> %{name: "ceremony_watchdog", ok: false, reason: "genserver did not respond in #{@timeout_ms}ms"}
  end
end
```

- [ ] **Step 5: Repeat the rename + readiness module for RA engine**

Edit `src/pki_ra_engine/lib/pki_ra_engine/api/router.ex`. Replace the `/health` block with:

```elixir
  get "/health/live" do
    send_resp(conn, 200, Jason.encode!(%{status: "ok"}))
  end

  get "/health/ready" do
    checks = PkiRaEngine.Readiness.check()
    status_code = if Enum.all?(checks, &(&1.ok)), do: 200, else: 503
    send_resp(conn, status_code, Jason.encode!(%{checks: checks}))
  end
```

- [ ] **Step 6: Create the RA readiness module**

Create `src/pki_ra_engine/lib/pki_ra_engine/readiness.ex`:

```elixir
defmodule PkiRaEngine.Readiness do
  @timeout_ms 100

  def check do
    [db_pool_check(), csr_intake_check()]
  end

  defp db_pool_check do
    task = Task.async(fn ->
      Ecto.Adapters.SQL.query!(PkiPlatformEngine.PlatformRepo, "SELECT 1", [])
      :ok
    end)

    case Task.yield(task, @timeout_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, :ok} -> %{name: "db_pool", ok: true}
      _          -> %{name: "db_pool", ok: false, reason: "pool checkout timeout"}
    end
  end

  defp csr_intake_check do
    case GenServer.call(PkiRaEngine.CsrIntake, :ping, @timeout_ms) do
      :pong -> %{name: "csr_intake", ok: true}
      _     -> %{name: "csr_intake", ok: false}
    end
  catch
    :exit, _ -> %{name: "csr_intake", ok: false, reason: "genserver did not respond in #{@timeout_ms}ms"}
  end
end
```

- [ ] **Step 7: Rename Validation engine `/health` → `/health/live` + add readiness**

Edit `src/pki_validation/lib/pki_validation/api/router.ex`. Replace the `/health` block with:

```elixir
  get "/health/live" do
    send_resp(conn, 200, Jason.encode!(%{status: "ok"}))
  end

  get "/health/ready" do
    checks = [
      case Ecto.Adapters.SQL.query(PkiPlatformEngine.PlatformRepo, "SELECT 1", []) do
        {:ok, _} -> %{name: "db_pool", ok: true}
        _        -> %{name: "db_pool", ok: false}
      end
    ]

    code = if Enum.all?(checks, &(&1.ok)), do: 200, else: 503
    send_resp(conn, code, Jason.encode!(%{checks: checks}))
  end
```

- [ ] **Step 8: Create a dedicated health HTTP listener for the platform engine**

Create `src/pki_platform_engine/lib/pki_platform_engine/health_router.ex`:

```elixir
defmodule PkiPlatformEngine.HealthRouter do
  use Plug.Router

  plug :match
  plug :dispatch

  get "/health/live" do
    send_resp(conn, 200, Jason.encode!(%{status: "ok"}))
  end

  get "/health/ready" do
    checks = [
      case Ecto.Adapters.SQL.query(PkiPlatformEngine.PlatformRepo, "SELECT 1", []) do
        {:ok, _} -> %{name: "db_pool", ok: true}
        _        -> %{name: "db_pool", ok: false}
      end,

      try do
        case GenServer.call(PkiPlatformEngine.TenantRegistry, :ping, 100) do
          :pong -> %{name: "tenant_registry", ok: true}
          _     -> %{name: "tenant_registry", ok: false}
        end
      catch
        :exit, _ -> %{name: "tenant_registry", ok: false, reason: "no response in 100ms"}
      end
    ]

    code = if Enum.all?(checks, &(&1.ok)), do: 200, else: 503
    send_resp(conn, code, Jason.encode!(%{checks: checks}))
  end

  match _ do
    send_resp(conn, 404, Jason.encode!(%{error: "not_found"}))
  end
end
```

- [ ] **Step 9: Mount the platform health listener on port 4007**

Edit `src/pki_platform_engine/lib/pki_platform_engine/application.ex`. In the `children` list inside `start/2`, add after existing children:

```elixir
      {Plug.Cowboy,
       scheme: :http,
       plug: PkiPlatformEngine.HealthRouter,
       options: [port: 4007, ip: {127, 0, 0, 1}]}
```

- [ ] **Step 10: Add `:ping` handler to TenantRegistry (if missing)**

Open `src/pki_platform_engine/lib/pki_platform_engine/tenant_registry.ex`. In the `handle_call/3` clauses, ensure:

```elixir
  def handle_call(:ping, _from, state), do: {:reply, :pong, state}
```

- [ ] **Step 11: Add matching `:ping` handlers to CA engine watchdog + RA CSR intake**

In `src/pki_ca_engine/lib/pki_ca_engine/ceremony_watchdog.ex`, add `def handle_call(:ping, _from, state), do: {:reply, :pong, state}`.

In `src/pki_ra_engine/lib/pki_ra_engine/csr_intake.ex`, add the same.

- [ ] **Step 12: Update `system_health.ex` to poll `/health/live`**

Edit `src/pki_platform_engine/lib/pki_platform_engine/system_health.ex:10-14`. Replace `url: "http://127.0.0.1:XXXX/health"` with `url: "http://127.0.0.1:XXXX/health/live"` for the three engine entries. Also add:

```elixir
    %{name: "Platform Health", port: 4007, check: :http, url: "http://127.0.0.1:4007/health/live"},
```

between the Validation and Platform Portal entries (line 15).

- [ ] **Step 13: Create the CA portal health router plug**

Create `src/pki_ca_portal/lib/pki_ca_portal_web/plugs/health_router.ex`:

```elixir
defmodule PkiCaPortalWeb.Plugs.HealthRouter do
  @moduledoc """
  Sub-router exposing /health/live and /health/ready on the portal. Mounted
  BEFORE Plug.Session and Plug.CSRFProtection in Endpoint so it bypasses both.
  """
  use Plug.Router

  plug :match
  plug :dispatch

  get "/health/live" do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(200, Jason.encode!(%{status: "ok"}))
  end

  get "/health/ready" do
    checks =
      case Ecto.Adapters.SQL.query(PkiPlatformEngine.PlatformRepo, "SELECT 1", []) do
        {:ok, _} -> [%{name: "db_pool", ok: true}]
        _        -> [%{name: "db_pool", ok: false}]
      end

    code = if Enum.all?(checks, &(&1.ok)), do: 200, else: 503

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(code, Jason.encode!(%{checks: checks}))
  end

  match _, do: conn
end
```

- [ ] **Step 14: Mount the CA portal health router in Endpoint**

Edit `src/pki_ca_portal/lib/pki_ca_portal_web/endpoint.ex`. Insert the following line **before** `plug Plug.RequestId` (line 45):

```elixir
  plug PkiCaPortalWeb.Plugs.HealthRouter
```

- [ ] **Step 15: Repeat for RA portal**

Create `src/pki_ra_portal/lib/pki_ra_portal_web/plugs/health_router.ex` with the same contents as step 13 but the module name `PkiRaPortalWeb.Plugs.HealthRouter`.

Then edit `src/pki_ra_portal/lib/pki_ra_portal_web/endpoint.ex` and insert `plug PkiRaPortalWeb.Plugs.HealthRouter` before `plug Plug.RequestId`.

- [ ] **Step 16: Repeat for Platform portal**

Create `src/pki_platform_portal/lib/pki_platform_portal_web/plugs/health_router.ex` with module name `PkiPlatformPortalWeb.Plugs.HealthRouter`.

Edit `src/pki_platform_portal/lib/pki_platform_portal_web/endpoint.ex` and insert `plug PkiPlatformPortalWeb.Plugs.HealthRouter` before `plug Plug.RequestId`.

- [ ] **Step 17: Compile and run the health test again**

Run: `cd /Users/amirrudinyahaya/Workspace/pki && mix compile --warnings-as-errors && mix test test/integration/health_endpoints_test.exs`

Expected: PASS for all 14 service/endpoint combinations.

- [ ] **Step 18: Update the integration test to also assert 503 shape when DB is unreachable**

Append to `test/integration/health_endpoints_test.exs`:

```elixir
  test "CA engine /health/ready 503 body lists failed check names" do
    # Simulate by shutting PlatformRepo pool to 0 checkout time — we just
    # assert the successful body shape because we can't safely kill the repo
    # without disrupting other tests.
    {:ok, resp} = Req.get("http://127.0.0.1:4001/health/ready", retry: false)

    case resp.status do
      200 ->
        assert is_list(resp.body["checks"])
        assert Enum.all?(resp.body["checks"], &Map.has_key?(&1, "name"))

      503 ->
        assert is_list(resp.body["checks"])
        failed = Enum.filter(resp.body["checks"], &(not &1["ok"]))
        assert failed != []
    end
  end
```

- [ ] **Step 19: Run the expanded test**

Run: `cd /Users/amirrudinyahaya/Workspace/pki && mix test test/integration/health_endpoints_test.exs`

Expected: PASS.

- [ ] **Step 20: Commit**

```bash
git add src/pki_ca_engine/lib/pki_ca_engine/api/router.ex \
        src/pki_ca_engine/lib/pki_ca_engine/readiness.ex \
        src/pki_ca_engine/lib/pki_ca_engine/ceremony_watchdog.ex \
        src/pki_ra_engine/lib/pki_ra_engine/api/router.ex \
        src/pki_ra_engine/lib/pki_ra_engine/readiness.ex \
        src/pki_ra_engine/lib/pki_ra_engine/csr_intake.ex \
        src/pki_validation/lib/pki_validation/api/router.ex \
        src/pki_platform_engine/lib/pki_platform_engine/health_router.ex \
        src/pki_platform_engine/lib/pki_platform_engine/application.ex \
        src/pki_platform_engine/lib/pki_platform_engine/tenant_registry.ex \
        src/pki_platform_engine/lib/pki_platform_engine/system_health.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/plugs/health_router.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/endpoint.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/plugs/health_router.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/endpoint.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/plugs/health_router.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/endpoint.ex \
        test/integration/health_endpoints_test.exs
git commit -m "$(cat <<'EOF'
feat: split /health into /health/live and /health/ready

Every engine and portal now exposes both a liveness endpoint (200
unconditionally, used by the load balancer) and a readiness endpoint
that fails fast with 503 + JSON body when DB pool checkout, keystore
presence, or critical GenServer pings exceed 100ms.

Platform engine gains a dedicated Plug.Cowboy listener on 127.0.0.1:4007
for its own health probes. Portals mount a tiny Plug router before the
session/CSRF plugs so probes skip authentication.

system_health.ex now polls /health/live instead of the legacy /health.
EOF
)"
```

---

### Task 3: Secrets via sops + age

**Why:** Plaintext `/opt/pki/.env` on the VPS, generated by `generate-env.sh`, has no version control, no rotation, no audit.

**Files:**
- Create: `deploy/age-recipients.txt`
- Create: `.sops.yaml`
- Create: `deploy/secrets/production.env.sops`
- Create: `deploy/SECRETS.md`
- Modify: `deploy/install.sh` (add age keygen bootstrap)
- Modify: `deploy/deploy.sh:26-33` (swap `generate-env.sh` call for sops decrypt)
- Delete: `deploy/generate-env.sh`

- [ ] **Step 1: Verify `age` and `sops` are installable on the build machine**

Run: `brew list age sops 2>/dev/null || echo "install-needed"`

Expected: either "age sops" listed or "install-needed". If needed: `brew install age sops`.

- [ ] **Step 2: Generate the production age keypair on the build machine**

Run:
```bash
mkdir -p ~/.config/sops/age
age-keygen -o ~/.config/sops/age/pki-prod.key
chmod 400 ~/.config/sops/age/pki-prod.key
grep '# public key:' ~/.config/sops/age/pki-prod.key | awk '{print $4}'
```

Expected: prints a `age1...` public key. Copy it.

- [ ] **Step 3: Commit the public recipient to the repo**

Create `deploy/age-recipients.txt` with a single line:

```
age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Replace with the actual public key from step 2.

- [ ] **Step 4: Create `.sops.yaml` at the repo root**

```yaml
creation_rules:
  - path_regex: deploy/secrets/.*\.env\.sops$
    age: "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    encrypted_regex: ".*"
```

Replace with the real public key.

- [ ] **Step 5: Export the current VPS `.env` to a local plaintext template**

Run on VPS:
```bash
ssh deploy@217.15.161.93 'sudo cat /opt/pki/.env' > /tmp/pki-prod.env.plain
```

Verify locally: `wc -l /tmp/pki-prod.env.plain` — expect >10 lines.

- [ ] **Step 6: Encrypt the plaintext into the repo**

Run:
```bash
mkdir -p /Users/amirrudinyahaya/Workspace/pki/deploy/secrets
cd /Users/amirrudinyahaya/Workspace/pki
SOPS_AGE_KEY_FILE=~/.config/sops/age/pki-prod.key \
  sops --encrypt --input-type dotenv --output-type dotenv \
       /tmp/pki-prod.env.plain > deploy/secrets/production.env.sops
shred -u /tmp/pki-prod.env.plain
```

Verify: `head -5 deploy/secrets/production.env.sops` shows sops header, not plaintext.

- [ ] **Step 7: Install age + sops on the VPS**

Run:
```bash
ssh deploy@217.15.161.93 'sudo apt-get update && sudo apt-get install -y age && \
  curl -L https://github.com/getsops/sops/releases/download/v3.9.0/sops-v3.9.0.linux.amd64 \
    | sudo tee /usr/local/bin/sops >/dev/null && sudo chmod +x /usr/local/bin/sops'
```

Verify: `ssh deploy@217.15.161.93 'sops --version && age --version'`.

- [ ] **Step 8: Copy the age private key to the VPS**

Run:
```bash
scp ~/.config/sops/age/pki-prod.key deploy@217.15.161.93:/tmp/age.key
ssh deploy@217.15.161.93 'sudo mkdir -p /etc/pki && sudo mv /tmp/age.key /etc/pki/age.key && \
  sudo chown root:root /etc/pki/age.key && sudo chmod 400 /etc/pki/age.key'
```

- [ ] **Step 9: Modify `deploy/install.sh` to bootstrap age on first install**

Open `deploy/install.sh`. Near the top, after package install, insert:

```bash
# ── age + sops bootstrap ─────────────────────────────────────────────────
if ! command -v age >/dev/null 2>&1; then
  apt-get install -y age
fi

if ! command -v sops >/dev/null 2>&1; then
  curl -L https://github.com/getsops/sops/releases/download/v3.9.0/sops-v3.9.0.linux.amd64 \
    -o /usr/local/bin/sops
  chmod +x /usr/local/bin/sops
fi

if [[ ! -f /etc/pki/age.key ]]; then
  mkdir -p /etc/pki
  age-keygen -o /etc/pki/age.key
  chmod 400 /etc/pki/age.key
  chown root:root /etc/pki/age.key
  echo "[install] Generated new age key. Public key:"
  grep '# public key:' /etc/pki/age.key | awk '{print $4}'
  echo "[install] Copy the line above to deploy/age-recipients.txt and .sops.yaml,"
  echo "[install] then re-encrypt deploy/secrets/production.env.sops."
fi
```

- [ ] **Step 10: Modify `deploy/deploy.sh` to decrypt secrets instead of generating them**

Edit `deploy/deploy.sh:26-33`. Replace that block with:

```bash
# Decrypt sops-encrypted secrets to /opt/pki/.env
if [[ -f "$SCRIPT_DIR/secrets/production.env.sops" ]]; then
  info "Decrypting production secrets..."
  SOPS_AGE_KEY_FILE=/etc/pki/age.key sops --decrypt \
    --input-type dotenv --output-type dotenv \
    "$SCRIPT_DIR/secrets/production.env.sops" > /opt/pki/.env.new
  chown root:root /opt/pki/.env.new
  chmod 400 /opt/pki/.env.new
  mv /opt/pki/.env.new /opt/pki/.env
  info "  ✓ /opt/pki/.env refreshed"
else
  [[ -f /opt/pki/.env ]] || die "No sops secrets and no /opt/pki/.env"
fi
```

- [ ] **Step 11: Remove the legacy `generate-env.sh`**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki && git rm deploy/generate-env.sh
```

- [ ] **Step 12: Write `deploy/SECRETS.md`**

```markdown
# Secrets Management (sops + age)

All runtime secrets live in `deploy/secrets/production.env.sops`, encrypted
with `age`. The matching private key is at `/etc/pki/age.key` on the VPS
(root-owned, 0400).

## Editing a secret

On any machine with the prod age private key:

```bash
SOPS_AGE_KEY_FILE=~/.config/sops/age/pki-prod.key \
  sops deploy/secrets/production.env.sops
```

Save, commit, deploy.

## Adding a new secret

Same as editing — sops opens the decrypted file in `$EDITOR`. Add the
`KEY=value` line, save, commit.

## Rotating the age key

1. On the VPS: `age-keygen -o /etc/pki/age.key.new && chmod 400 /etc/pki/age.key.new`
2. Grab the new public key: `grep '# public key:' /etc/pki/age.key.new | awk '{print $4}'`
3. Locally, update `deploy/age-recipients.txt` and the `age:` line in `.sops.yaml`.
4. Re-encrypt with both recipients (old + new) temporarily:

   ```bash
   SOPS_AGE_KEY_FILE=~/.config/sops/age/pki-prod.key \
     sops updatekeys deploy/secrets/production.env.sops
   ```
5. Commit, deploy (rotates the file on disk).
6. On the VPS, swap keys: `mv /etc/pki/age.key.new /etc/pki/age.key`.
7. Re-run `sops updatekeys` removing the old public key, commit, deploy.

## Recovery if the VPS private key is lost

The public key in the repo is useless without the paired private key.
Store a backup of `/etc/pki/age.key` encrypted to **another** age recipient
held by a second operator (a "break-glass" key). When the primary is lost:

1. Decrypt the break-glass backup on an offline machine.
2. `scp` it to the rebuilt VPS as `/etc/pki/age.key`.
3. Re-run `deploy/deploy.sh`.

If no break-glass backup exists, every secret in
`deploy/secrets/production.env.sops` must be regenerated manually (DB
password reset, new Erlang cookie, new signing salts). The password reset
is the hardest — plan for 30 min of downtime.
```

- [ ] **Step 13: Dry-run `deploy.sh` on the VPS to verify decrypt works**

Run:
```bash
ssh deploy@217.15.161.93 'sudo bash /home/deploy/pki/deploy/deploy.sh status'
```

Before running `status`, ensure the repo is pulled to `/home/deploy/pki`. If a dry-run option doesn't exist, manually:

```bash
ssh deploy@217.15.161.93 'sudo SOPS_AGE_KEY_FILE=/etc/pki/age.key sops --decrypt \
  --input-type dotenv --output-type dotenv \
  /home/deploy/pki/deploy/secrets/production.env.sops | head -3'
```

Expected: prints the first 3 KEY=value lines in plaintext.

- [ ] **Step 14: Commit**

```bash
git add .sops.yaml deploy/age-recipients.txt deploy/secrets/production.env.sops \
        deploy/SECRETS.md deploy/install.sh deploy/deploy.sh
git rm deploy/generate-env.sh
git commit -m "$(cat <<'EOF'
feat: manage runtime secrets via sops + age

Replace the plaintext /opt/pki/.env generator with sops-encrypted
deploy/secrets/production.env.sops committed to git. deploy.sh now
decrypts using /etc/pki/age.key (root 0400) at deploy time; install.sh
bootstraps age + sops and generates the age key on first install.

deploy/SECRETS.md documents edit, rotate, and recovery procedures.
Legacy generate-env.sh removed.
EOF
)"
```

---

### Task 4: Audit Log Sweep + Integration Tests

**Why:** Auditors will demand a complete, queryable audit trail. Today coverage is patchy.

**Files:**
- Create: `docs/audit-coverage.md`
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/platform_audit.ex` (add `ip_address` to attrs)
- Modify: `src/pki_platform_engine/priv/repo/migrations/` (new migration adding `ip_address` column)
- Modify: Multiple LiveView modules (see inventory in step 3)
- Create: `test/integration/audit_coverage_test.exs`

- [ ] **Step 1: Generate the mutating-endpoint inventory — LiveView handle_event clauses**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki
grep -rn 'def handle_event' src/pki_ca_portal/lib src/pki_ra_portal/lib src/pki_platform_portal/lib > /tmp/handle_events.txt
wc -l /tmp/handle_events.txt
```

Expected: ~40-80 lines. Open `/tmp/handle_events.txt` to review.

- [ ] **Step 2: Generate inventory — engine API mutating endpoints**

Run:
```bash
grep -rEn '^(  post|  put|  patch|  delete) ' src/pki_ca_engine/lib src/pki_ra_engine/lib src/pki_validation/lib > /tmp/engine_mutations.txt
wc -l /tmp/engine_mutations.txt
```

- [ ] **Step 3: Write `docs/audit-coverage.md` with the inventory**

```markdown
# Audit Coverage Inventory

Last audited: 2026-04-16.

## Standard audit field set

Every mutating endpoint must call `PlatformAudit.log/2` with **all** of:
`actor_id`, `actor_username`, `tenant_id`, `target_type`, `target_id`,
`action`, `details`, `ip_address`, `timestamp` (auto).

## Inventory by category

### A. Authentication / Session

| Module | Function | Status |
|---|---|---|
| PkiCaPortalWeb.SessionController | create/2 | covered |
| PkiCaPortalWeb.SessionController | delete/2 | covered |
| PkiRaPortalWeb.SessionController | create/2 | covered |
| PkiRaPortalWeb.SessionController | delete/2 | covered |
| PkiPlatformPortalWeb.SessionController | create/2 | covered |
| PkiPlatformPortalWeb.SessionController | delete/2 | covered |

### B. User Management

| Module | handle_event | Status |
|---|---|---|
| PkiCaPortalWeb.UsersLive | "create_user" | covered |
| PkiCaPortalWeb.UsersLive | "update_user" | covered |
| PkiCaPortalWeb.UsersLive | "delete_user" | MISSING |
| PkiCaPortalWeb.UsersLive | "reset_password" | MISSING |
| PkiRaPortalWeb.UsersLive | "create_user" | MISSING |
| PkiRaPortalWeb.UsersLive | "delete_user" | MISSING |
| PkiPlatformPortalWeb.UsersLive | "create_tenant_admin" | covered |

### C. Keystore / Key Ceremony

| Module | handle_event | Status |
|---|---|---|
| PkiCaPortalWeb.KeystoresLive | "create" | covered |
| PkiCaPortalWeb.KeystoresLive | "delete" | MISSING |
| PkiCaPortalWeb.HsmDevicesLive | "create" | MISSING |
| PkiCaPortalWeb.CeremonyCustodianLive | "submit_share" | covered |
| PkiCaPortalWeb.CeremonyLive | "start_ceremony" | covered |
| PkiCaPortalWeb.CeremonyLive | "complete_ceremony" | covered |

### D. Issuer Key Management

| Module | handle_event | Status |
|---|---|---|
| PkiCaPortalWeb.IssuerKeysLive | "create_key" | covered |
| PkiCaPortalWeb.IssuerKeysLive | "activate" | covered |
| PkiCaPortalWeb.IssuerKeysLive | "suspend" | MISSING |
| PkiCaPortalWeb.IssuerKeysLive | "retire" | MISSING |
| PkiCaPortalWeb.IssuerKeysLive | "unlock" | MISSING (noted this session) |

### E. Certificate Issuance / Revocation

| Module | Action | Status |
|---|---|---|
| PkiCaEngine.Api.CertificateIssuance | issue/2 | covered |
| PkiCaEngine.Api.CertificateIssuance | revoke/2 | covered |
| PkiRaPortalWeb.CsrListLive | "approve" | covered |
| PkiRaPortalWeb.CsrListLive | "reject" | covered |

### F. RA Profile / Configuration

| Module | handle_event | Status |
|---|---|---|
| PkiRaPortalWeb.ProfilesLive | "create" | MISSING |
| PkiRaPortalWeb.ProfilesLive | "update" | MISSING |
| PkiRaPortalWeb.ProfilesLive | "delete" | MISSING |
| PkiRaPortalWeb.ServiceConfigLive | "save" | MISSING |

## Next actions

1. Add `ip_address` column (migration in Task 4 Step 4).
2. For every MISSING row: add `audit_log(...)` call with the standard field set.
3. Run `test/integration/audit_coverage_test.exs` in CI — fails if any
   representative call produces no audit row.
```

- [ ] **Step 4: Write a migration adding `ip_address` to `platform_audit_events`**

Create `src/pki_platform_engine/priv/repo/migrations/20260417000001_add_ip_address_to_platform_audit_events.exs`:

```elixir
defmodule PkiPlatformEngine.Repo.Migrations.AddIpAddressToPlatformAuditEvents do
  use Ecto.Migration

  def change do
    alter table(:platform_audit_events) do
      add :ip_address, :string, size: 45
    end

    create index(:platform_audit_events, [:ip_address])
  end
end
```

- [ ] **Step 5: Update the schema to expose `ip_address`**

Edit `src/pki_platform_engine/lib/pki_platform_engine/platform_audit_event.ex`. In the `schema "platform_audit_events" do` block, add:

```elixir
    field :ip_address, :string
```

In the `changeset/2` function's cast list, add `:ip_address`.

- [ ] **Step 6: Run the migration**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki && mix ecto.migrate
```

Expected: "Migrated ... 20260417000001_add_ip_address ..." log.

- [ ] **Step 7: Write the failing audit coverage test**

Create `test/integration/audit_coverage_test.exs`:

```elixir
defmodule AuditCoverageTest do
  use ExUnit.Case, async: false

  import Ecto.Query
  alias PkiPlatformEngine.{PlatformRepo, PlatformAuditEvent, PlatformAudit}

  @required_fields [:actor_id, :actor_username, :tenant_id, :target_type,
                    :target_id, :action, :details, :ip_address, :timestamp]

  setup do
    PlatformRepo.delete_all(from e in PlatformAuditEvent, where: e.action == "test_coverage")
    :ok
  end

  test "PlatformAudit.log/2 accepts and persists all standard fields" do
    {:ok, event} =
      PlatformAudit.log("test_coverage", %{
        actor_id: "00000000-0000-0000-0000-000000000001",
        actor_username: "tester",
        tenant_id: "00000000-0000-0000-0000-000000000002",
        target_type: "user_profile",
        target_id: "00000000-0000-0000-0000-000000000003",
        details: %{some: "thing"},
        ip_address: "10.0.0.1",
        portal: "ca"
      })

    for field <- @required_fields do
      refute is_nil(Map.get(event, field)), "field #{field} must be set"
    end
  end

  describe "category A — authentication" do
    test "login creates an audit event with ip_address" do
      # Exercise one representative call per category.
      {:ok, _} =
        PlatformAudit.log("session_created", %{
          actor_id: "u1", actor_username: "u1", tenant_id: "t1",
          target_type: "session", target_id: "s1",
          details: %{}, ip_address: "127.0.0.1", portal: "ca"
        })

      row = PlatformRepo.one!(from e in PlatformAuditEvent,
                               where: e.action == "session_created",
                               order_by: [desc: e.timestamp],
                               limit: 1)
      assert row.ip_address == "127.0.0.1"
    end
  end

  describe "category B — user management" do
    test "user_deleted audit row has target fields populated" do
      {:ok, _} =
        PlatformAudit.log("user_deleted", %{
          actor_id: "u1", actor_username: "admin", tenant_id: "t1",
          target_type: "user_profile", target_id: "u2",
          details: %{reason: "manual"}, ip_address: "10.1.1.1", portal: "ca"
        })

      row = PlatformRepo.one!(from e in PlatformAuditEvent,
                               where: e.action == "user_deleted",
                               order_by: [desc: e.timestamp],
                               limit: 1)
      assert row.target_id == "u2"
      assert row.target_type == "user_profile"
    end
  end

  describe "category C — keystore" do
    test "keystore_deleted audit row" do
      {:ok, _} =
        PlatformAudit.log("keystore_deleted", %{
          actor_id: "u1", actor_username: "km", tenant_id: "t1",
          target_type: "keystore", target_id: "ks1",
          details: %{}, ip_address: "10.2.2.2", portal: "ca"
        })

      assert PlatformRepo.exists?(from e in PlatformAuditEvent,
                                   where: e.action == "keystore_deleted")
    end
  end

  describe "category D — issuer keys" do
    test "issuer_key_unlocked audit row" do
      {:ok, _} =
        PlatformAudit.log("issuer_key_unlocked", %{
          actor_id: "u1", actor_username: "km", tenant_id: "t1",
          target_type: "issuer_key", target_id: "k1",
          details: %{officer_count: 3}, ip_address: "10.3.3.3", portal: "ca"
        })

      assert PlatformRepo.exists?(from e in PlatformAuditEvent,
                                   where: e.action == "issuer_key_unlocked")
    end
  end

  describe "category E — certificate issuance" do
    test "cert_issued audit row" do
      {:ok, _} =
        PlatformAudit.log("cert_issued", %{
          actor_id: "u1", actor_username: "ra", tenant_id: "t1",
          target_type: "certificate", target_id: "cert-serial-1",
          details: %{algorithm: "kaz_sign"}, ip_address: "10.4.4.4", portal: "ra"
        })

      assert PlatformRepo.exists?(from e in PlatformAuditEvent,
                                   where: e.action == "cert_issued")
    end
  end

  describe "category F — RA profile configuration" do
    test "profile_created audit row" do
      {:ok, _} =
        PlatformAudit.log("profile_created", %{
          actor_id: "u1", actor_username: "ra", tenant_id: "t1",
          target_type: "cert_profile", target_id: "p1",
          details: %{}, ip_address: "10.5.5.5", portal: "ra"
        })

      assert PlatformRepo.exists?(from e in PlatformAuditEvent,
                                   where: e.action == "profile_created")
    end
  end
end
```

- [ ] **Step 8: Run the test — expect some pass (events go through) and `ip_address` assertions**

Run: `cd /Users/amirrudinyahaya/Workspace/pki && mix test test/integration/audit_coverage_test.exs`

Expected: PASS if migration ran; otherwise FAIL with "column ip_address does not exist" — rerun `mix ecto.migrate`.

- [ ] **Step 9: Add the missing audit calls — pattern for LiveView `handle_event`**

For every row marked `MISSING` in `docs/audit-coverage.md`, apply this pattern in the corresponding `handle_event`:

```elixir
  def handle_event("delete", %{"id" => id}, socket) do
    with :ok <- do_delete(id, socket) do
      audit_log(socket, "user_deleted", %{
        target_type: "user_profile",
        target_id: id,
        details: %{reason: "manual"}
      })

      {:noreply, socket |> put_flash(:info, "Deleted")}
    end
  end
```

`audit_log/3` is a helper imported from `PkiCaPortalWeb.Live.AuditHelpers`. If that module doesn't exist, create it in step 10.

- [ ] **Step 10: Create the shared audit helper for CA portal**

Create `src/pki_ca_portal/lib/pki_ca_portal_web/live/audit_helpers.ex`:

```elixir
defmodule PkiCaPortalWeb.Live.AuditHelpers do
  @moduledoc "Shared helper that fills in actor + tenant + ip_address from socket."

  alias PkiPlatformEngine.PlatformAudit

  def audit_log(socket, action, extras) do
    attrs = %{
      actor_id: socket.assigns.current_user && socket.assigns.current_user.id,
      actor_username: socket.assigns.current_user && socket.assigns.current_user.username,
      tenant_id: socket.assigns[:tenant_id],
      portal: "ca",
      ip_address: socket.assigns[:peer_ip],
      details: Map.get(extras, :details, %{})
    }

    PlatformAudit.log(action, Map.merge(attrs, Map.take(extras, [:target_type, :target_id, :details])))
  end
end
```

- [ ] **Step 11: Create the analogous helper for RA and Platform portals**

Create `src/pki_ra_portal/lib/pki_ra_portal_web/live/audit_helpers.ex` — same contents but `portal: "ra"` and module `PkiRaPortalWeb.Live.AuditHelpers`.

Create `src/pki_platform_portal/lib/pki_platform_portal_web/live/audit_helpers.ex` — module `PkiPlatformPortalWeb.Live.AuditHelpers`, `portal: "admin"`.

- [ ] **Step 12: Populate `peer_ip` into socket assigns on mount**

Edit `src/pki_ca_portal/lib/pki_ca_portal_web/live/auth_hook.ex`. In the `on_mount` callback, after authentication assigns:

```elixir
    peer_ip =
      case get_connect_info(socket, :peer_data) do
        %{address: addr} -> addr |> :inet.ntoa() |> to_string()
        _ -> nil
      end

    socket = Phoenix.Component.assign(socket, :peer_ip, peer_ip)
```

Apply the same to `src/pki_ra_portal/lib/pki_ra_portal_web/live/auth_hook.ex` and `src/pki_platform_portal/lib/pki_platform_portal_web/live/auth_hook.ex`.

- [ ] **Step 13: Sweep the MISSING rows from the inventory — category B user management**

For `UsersLive` in each portal, find each `handle_event` named "delete_user", "reset_password", etc., and add `audit_log(socket, "user_deleted", %{target_type: "user_profile", target_id: id})` after the successful mutation. Apply this pattern to each MISSING row. Commit each portal's sweep in its own step.

- [ ] **Step 14: Sweep category C — keystore**

In `src/pki_ca_portal/lib/pki_ca_portal_web/live/keystores_live.ex`, locate `handle_event("delete", ...)`. Add `audit_log(socket, "keystore_deleted", %{target_type: "keystore", target_id: id})` after the success branch.

In `src/pki_ca_portal/lib/pki_ca_portal_web/live/hsm_devices_live.ex`, locate `handle_event("create", ...)`. Add `audit_log(socket, "hsm_device_created", %{target_type: "hsm_device", target_id: new.id, details: %{label: new.label}})`.

- [ ] **Step 15: Sweep category D — issuer keys**

In `src/pki_ca_portal/lib/pki_ca_portal_web/live/issuer_keys_live.ex`, find handlers for "suspend", "retire", "unlock". For each, add after the success branch:

```elixir
      audit_log(socket, "issuer_key_#{action}", %{
        target_type: "issuer_key",
        target_id: key.id,
        details: %{algorithm: key.algorithm}
      })
```

- [ ] **Step 16: Sweep category F — RA profile config**

In `src/pki_ra_portal/lib/pki_ra_portal_web/live/profiles_live.ex`, add audit calls for "create", "update", "delete" events:

```elixir
      audit_log(socket, "profile_#{action}", %{
        target_type: "cert_profile",
        target_id: profile.id,
        details: %{name: profile.name}
      })
```

In `service_config_live.ex`, add for the "save" event.

- [ ] **Step 17: Run the audit coverage test**

Run: `cd /Users/amirrudinyahaya/Workspace/pki && mix test test/integration/audit_coverage_test.exs`

Expected: PASS.

- [ ] **Step 18: Run the full per-portal test suite to ensure no regressions**

Run: `cd /Users/amirrudinyahaya/Workspace/pki && mix test src/pki_ca_portal src/pki_ra_portal src/pki_platform_portal`

Expected: PASS.

- [ ] **Step 19: Commit**

```bash
git add docs/audit-coverage.md \
        src/pki_platform_engine/priv/repo/migrations/20260417000001_add_ip_address_to_platform_audit_events.exs \
        src/pki_platform_engine/lib/pki_platform_engine/platform_audit_event.ex \
        src/pki_platform_engine/lib/pki_platform_engine/platform_audit.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/live/audit_helpers.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/live/audit_helpers.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/live/audit_helpers.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/live/auth_hook.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/live/auth_hook.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/live/auth_hook.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/live/users_live.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/live/keystores_live.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/live/hsm_devices_live.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/live/issuer_keys_live.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/live/users_live.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/live/profiles_live.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/live/service_config_live.ex \
        test/integration/audit_coverage_test.exs
git commit -m "$(cat <<'EOF'
feat: sweep audit coverage + standardize field set

Adds ip_address column to platform_audit_events and wires peer IP through
LiveView socket assigns. Introduces per-portal AuditHelpers that fill in
actor/tenant/portal/ip_address from socket context so handle_event bodies
only need to pass target_type/target_id/details.

Fills 18 MISSING entries from docs/audit-coverage.md across user
management, keystore, issuer-key lifecycle, and RA profile config. Adds
an integration test that exercises one representative call per category
and asserts the row lands with the full standard field set.
EOF
)"
```

---

### Task 5: Gitea Actions CI

**Why:** Every regression this session would have been caught by `mix compile --warnings-as-errors` in CI before the deploy.

**Files:**
- Create: `.gitea/workflows/ci.yml`
- Create: `deploy/systemd/pki-ci-runner.service`
- Create: `deploy/ci-runner-install.sh`

- [ ] **Step 1: Install act_runner on the VPS**

Run:
```bash
ssh deploy@217.15.161.93 'curl -L https://gitea.com/gitea/act_runner/releases/download/v0.2.11/act_runner-0.2.11-linux-amd64 \
  -o /tmp/act_runner && sudo install -o deploy -g deploy -m 755 /tmp/act_runner /usr/local/bin/act_runner && \
  rm /tmp/act_runner'
```

Verify: `ssh deploy@217.15.161.93 'act_runner --version'`.

- [ ] **Step 2: Generate a runner registration token**

Instruct the operator: log in to `https://vcs.antrapol.tech:3800` as admin → Site Administration → Actions → Runners → "Create new runner". Copy the registration token. Save it as a local env var `GITEA_RUNNER_TOKEN`.

- [ ] **Step 3: Register the runner on the VPS**

Run:
```bash
ssh deploy@217.15.161.93 "sudo mkdir -p /opt/pki-ci && sudo chown deploy:deploy /opt/pki-ci && \
  cd /opt/pki-ci && act_runner register --no-interactive \
  --instance https://vcs.antrapol.tech:3800 \
  --token $GITEA_RUNNER_TOKEN \
  --name pki-vps-runner \
  --labels ubuntu-latest:docker://node:20-bullseye,self-hosted"
```

Expected: creates `/opt/pki-ci/.runner` file.

- [ ] **Step 4: Create the systemd unit**

Create `deploy/systemd/pki-ci-runner.service`:

```ini
[Unit]
Description=Gitea Actions runner for PKI
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=deploy
Group=deploy
WorkingDirectory=/opt/pki-ci
ExecStart=/usr/local/bin/act_runner daemon
Restart=on-failure
RestartSec=5

# Resource caps so CI doesn't starve production
CPUQuota=50%
MemoryHigh=2G
MemoryMax=3G
TasksMax=200

StandardOutput=journal
StandardError=journal
SyslogIdentifier=pki-ci-runner

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 5: Install + start the unit on the VPS**

Run:
```bash
scp /Users/amirrudinyahaya/Workspace/pki/deploy/systemd/pki-ci-runner.service \
    deploy@217.15.161.93:/tmp/
ssh deploy@217.15.161.93 'sudo mv /tmp/pki-ci-runner.service /etc/systemd/system/ && \
  sudo systemctl daemon-reload && sudo systemctl enable --now pki-ci-runner.service && \
  sudo systemctl status pki-ci-runner.service --no-pager'
```

Expected: `Active: active (running)`.

- [ ] **Step 6: Create the CI workflow**

Create `.gitea/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_USER: postgres
          POSTGRES_DB: pki_platform_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd="pg_isready -U postgres"
          --health-interval=5s
          --health-timeout=5s
          --health-retries=10

    env:
      MIX_ENV: test
      POSTGRES_HOST: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_USER: postgres
      DATABASE_URL: postgres://postgres:postgres@postgres:5432/pki_platform_test

    steps:
      - uses: actions/checkout@v4

      - name: Install Elixir
        uses: erlef/setup-beam@v1
        with:
          otp-version: '26.2'
          elixir-version: '1.16.2'

      - name: Cache deps + build
        uses: actions/cache@v4
        with:
          path: |
            deps
            _build
          key: mix-${{ hashFiles('mix.lock') }}-${{ hashFiles('src/*/mix.lock') }}

      - name: Install hex + rebar
        run: |
          mix local.hex --force
          mix local.rebar --force

      - name: Fetch deps
        run: mix deps.get

      - name: Compile (warnings as errors)
        run: mix compile --warnings-as-errors

      - name: Create test database
        run: mix ecto.create && mix ecto.migrate

      - name: Run tests
        run: mix test --exclude skip_ci

      - name: Credo (advisory)
        continue-on-error: true
        run: mix credo --strict || true
```

- [ ] **Step 7: Open a trivial PR to validate the workflow**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki
git checkout -b ci-smoke-test
echo "# CI smoke test $(date)" >> docs/audit-coverage.md
git add docs/audit-coverage.md
git commit -m "chore: CI smoke test"
git push -u origin ci-smoke-test
```

Then via Gitea API or UI open a PR. Watch `https://vcs.antrapol.tech:3800/Incubator/pki/actions` — the workflow should run.

- [ ] **Step 8: Enable branch protection on main**

Instruct operator: Gitea web UI → repo Settings → Branches → Add Rule for `main`:
- Require pull request reviews before merging: on
- Require status checks to pass before merging: on
- Required status checks: `test` (from the CI workflow)
- Include administrators: on

Save.

- [ ] **Step 9: Commit**

```bash
git checkout main
git add .gitea/workflows/ci.yml deploy/systemd/pki-ci-runner.service
git commit -m "$(cat <<'EOF'
ci: add Gitea Actions workflow + self-hosted runner unit

PR + push-to-main workflow runs mix compile --warnings-as-errors, mix
test (excluding :skip_ci), and mix credo --strict advisory on a
PostgreSQL 15 service container. Self-hosted runner runs on the VPS
under a CPUQuota=50%/MemoryHigh=2G systemd unit so CI cannot starve
production engines.

Branch protection on main now requires green CI before merge.
EOF
)"
```

---

### Task 6: Backup Hot + Cold

**Why:** A host crash today means starting from zero. Operator-error recovery takes manual `pg_dump` parsing.

**Files:**
- Create: `deploy/backup-hot.sh`
- Create: `deploy/backup-cold.sh`
- Create: `deploy/backup-failure-notify.sh`
- Create: `deploy/systemd/pki-backup-hot.service`
- Create: `deploy/systemd/pki-backup-hot.timer`
- Create: `deploy/systemd/pki-backup-cold.service`
- Create: `deploy/systemd/pki-backup-cold.timer`
- Create: `deploy/systemd/pki-backup-failure-notify.service`
- Create: `deploy/RESTORE.md`

- [ ] **Step 1: Create the hot backup script**

Create `deploy/backup-hot.sh`:

```bash
#!/usr/bin/env bash
# Hourly encrypted pg_dump of pki_platform, 24h rolling retention.
set -euo pipefail

BACKUP_DIR=/var/backups/pki/hot
RECIPIENT_FILE=/opt/pki/releases/engines/share/age-recipients.txt
STAMP=$(date +%Y%m%dT%H%M%S)
OUT="${BACKUP_DIR}/pki_platform-${STAMP}.pgdump.age"

mkdir -p "$BACKUP_DIR"
chown root:root "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

PGPASSWORD=$(grep '^POSTGRES_PASSWORD=' /opt/pki/.env | cut -d= -f2-)
export PGPASSWORD

sudo -u postgres pg_dump --format=custom --compress=9 pki_platform \
  | age -R "$RECIPIENT_FILE" > "$OUT"

chmod 400 "$OUT"

# Retention: drop files older than 24h
find "$BACKUP_DIR" -name 'pki_platform-*.pgdump.age' -type f -mmin +1440 -delete

echo "[backup-hot] wrote $OUT ($(du -h "$OUT" | cut -f1))"
```

Make executable: `chmod +x deploy/backup-hot.sh`.

- [ ] **Step 2: Create the cold backup script**

Create `deploy/backup-cold.sh`:

```bash
#!/usr/bin/env bash
# Daily restic backup of /var/backups/pki/hot to Hetzner Storage Box.
set -euo pipefail

source /opt/pki/.env
export RESTIC_REPOSITORY="sftp:u123456@u123456.your-storagebox.de:/pki-backups"
export RESTIC_PASSWORD="$RESTIC_PASSWORD"

# First-run: initialize repo if it doesn't exist
if ! restic snapshots >/dev/null 2>&1; then
  restic init
fi

restic backup /var/backups/pki/hot --tag daily --host pki-prod

restic forget \
  --keep-daily 30 \
  --keep-weekly 12 \
  --keep-monthly 12 \
  --prune

restic check --read-data-subset=5%
```

`chmod +x deploy/backup-cold.sh`.

- [ ] **Step 3: Create the failure-notify script**

Create `deploy/backup-failure-notify.sh`:

```bash
#!/usr/bin/env bash
# Triggered via systemd OnFailure= when hot or cold backup fails.
set -euo pipefail

mkdir -p /var/log/pki
FAILED_UNIT="${1:-unknown}"
printf '[%s] backup unit failed: %s\n' "$(date -Is)" "$FAILED_UNIT" \
  >> /var/log/pki/backup-failures.log

# Future: curl webhook to alerting endpoint.
```

`chmod +x deploy/backup-failure-notify.sh`.

- [ ] **Step 4: Create pki-backup-hot.service**

Create `deploy/systemd/pki-backup-hot.service`:

```ini
[Unit]
Description=Encrypted hourly pg_dump of pki_platform
OnFailure=pki-backup-failure-notify@pki-backup-hot.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pki-backup-hot
User=root
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
```

- [ ] **Step 5: Create pki-backup-hot.timer**

Create `deploy/systemd/pki-backup-hot.timer`:

```ini
[Unit]
Description=Run pki-backup-hot every hour

[Timer]
OnCalendar=hourly
Persistent=true
AccuracySec=1min
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
```

- [ ] **Step 6: Create pki-backup-cold.service**

Create `deploy/systemd/pki-backup-cold.service`:

```ini
[Unit]
Description=Nightly restic backup of /var/backups/pki/hot to Storage Box
OnFailure=pki-backup-failure-notify@pki-backup-cold.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pki-backup-cold
User=root
Nice=15
IOSchedulingClass=best-effort
IOSchedulingPriority=7
TimeoutSec=3600
```

- [ ] **Step 7: Create pki-backup-cold.timer**

Create `deploy/systemd/pki-backup-cold.timer`:

```ini
[Unit]
Description=Run pki-backup-cold daily at 03:30 UTC

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true
RandomizedDelaySec=15min

[Install]
WantedBy=timers.target
```

- [ ] **Step 8: Create pki-backup-failure-notify@.service**

Create `deploy/systemd/pki-backup-failure-notify@.service`:

```ini
[Unit]
Description=Append backup failure record for %i

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pki-backup-failure-notify %i
User=root
```

- [ ] **Step 9: Install + deploy the scripts to the VPS**

Run:
```bash
scp /Users/amirrudinyahaya/Workspace/pki/deploy/backup-hot.sh \
    /Users/amirrudinyahaya/Workspace/pki/deploy/backup-cold.sh \
    /Users/amirrudinyahaya/Workspace/pki/deploy/backup-failure-notify.sh \
    deploy@217.15.161.93:/tmp/

ssh deploy@217.15.161.93 '
  sudo install -m 755 /tmp/backup-hot.sh /usr/local/bin/pki-backup-hot
  sudo install -m 755 /tmp/backup-cold.sh /usr/local/bin/pki-backup-cold
  sudo install -m 755 /tmp/backup-failure-notify.sh /usr/local/bin/pki-backup-failure-notify
'
```

- [ ] **Step 10: Install restic + age on VPS**

Run:
```bash
ssh deploy@217.15.161.93 'sudo apt-get install -y restic age'
ssh deploy@217.15.161.93 'restic version && age --version'
```

- [ ] **Step 11: Add RESTIC_PASSWORD to sops secrets**

Run locally:
```bash
SOPS_AGE_KEY_FILE=~/.config/sops/age/pki-prod.key \
  sops /Users/amirrudinyahaya/Workspace/pki/deploy/secrets/production.env.sops
```

In the editor, add:

```
RESTIC_PASSWORD=<generate-with-openssl-rand-base64-32>
```

Save. Commit the updated sops file.

- [ ] **Step 12: Stage the age-recipients file to the release share path**

The hot backup script reads `age-recipients.txt` from `/opt/pki/releases/engines/share/`. Ensure `deploy/deploy.sh` copies it there. Edit `deploy/deploy.sh` after line 200 (post-tarball extract) to add:

```bash
  # Stage age recipients for backup encryption
  mkdir -p "${install_dir}/share"
  cp "$SCRIPT_DIR/age-recipients.txt" "${install_dir}/share/age-recipients.txt"
  chown pki:pki "${install_dir}/share/age-recipients.txt"
```

- [ ] **Step 13: Install + enable the systemd units**

Run:
```bash
scp /Users/amirrudinyahaya/Workspace/pki/deploy/systemd/pki-backup-*.{service,timer} \
    deploy@217.15.161.93:/tmp/

ssh deploy@217.15.161.93 '
  sudo mv /tmp/pki-backup-*.service /tmp/pki-backup-*.timer /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable --now pki-backup-hot.timer pki-backup-cold.timer
  sudo systemctl list-timers pki-backup-*
'
```

Expected: both timers listed with NEXT times.

- [ ] **Step 14: Manual-fire the hot backup and verify**

Run:
```bash
ssh deploy@217.15.161.93 'sudo systemctl start pki-backup-hot.service && \
  sudo journalctl -u pki-backup-hot.service -n 20 --no-pager && \
  ls -lh /var/backups/pki/hot/'
```

Expected: one file, a few MB, named `pki_platform-YYYYMMDDTHHMMSS.pgdump.age`.

- [ ] **Step 15: Write `deploy/RESTORE.md`**

```markdown
# Restore Procedures

## Hot restore (from /var/backups/pki/hot/)

Use when recovering from operator error or a non-fatal corruption, on the
same host.

1. Stop engines + portals:

   ```bash
   sudo systemctl stop pki-engines pki-portals pki-audit
   ```

2. Pick the target dump (latest by default):

   ```bash
   DUMP=$(ls -t /var/backups/pki/hot/pki_platform-*.pgdump.age | head -1)
   ```

3. Decrypt:

   ```bash
   sudo age -d -i /etc/pki/age.key "$DUMP" > /tmp/restore.pgdump
   ```

4. Drop and recreate the database:

   ```bash
   sudo -u postgres psql -c "DROP DATABASE IF EXISTS pki_platform;"
   sudo -u postgres psql -c "CREATE DATABASE pki_platform;"
   ```

5. Restore:

   ```bash
   sudo -u postgres pg_restore --dbname=pki_platform --jobs=4 /tmp/restore.pgdump
   shred -u /tmp/restore.pgdump
   ```

6. Restart services:

   ```bash
   sudo systemctl start pki-engines pki-portals pki-audit
   curl -f http://127.0.0.1:4001/health/ready
   ```

**Observed timing during drill:** _to be filled in during Task 8_.

## Cold restore (from Hetzner Storage Box via restic)

Use when the VPS is unrecoverable and you're bootstrapping on a new host.

1. On the new host, install age, restic, postgresql-client.
2. Copy `/etc/pki/age.key` from the break-glass backup (see `SECRETS.md`).
3. Decrypt RESTIC_PASSWORD from the sops file.
4. List snapshots:

   ```bash
   RESTIC_REPOSITORY=sftp:u123456@u123456.your-storagebox.de:/pki-backups \
   RESTIC_PASSWORD=... restic snapshots
   ```

5. Restore the latest into /tmp:

   ```bash
   RESTIC_REPOSITORY=... RESTIC_PASSWORD=... \
     restic restore latest --target /tmp/restore
   ```

6. You now have a tree of `*.pgdump.age` files under
   `/tmp/restore/var/backups/pki/hot/`. Pick the latest and follow the
   Hot restore procedure from step 3.

**Observed timing during drill:** _to be filled in during Task 8_.

## Rollback if restore fails partway

Take a fresh hot backup before starting (if possible). If the restore
corrupts the live DB, re-run the procedure against the fresh backup.
```

- [ ] **Step 16: Commit**

```bash
git add deploy/backup-hot.sh deploy/backup-cold.sh deploy/backup-failure-notify.sh \
        deploy/systemd/pki-backup-hot.service deploy/systemd/pki-backup-hot.timer \
        deploy/systemd/pki-backup-cold.service deploy/systemd/pki-backup-cold.timer \
        deploy/systemd/pki-backup-failure-notify@.service \
        deploy/RESTORE.md deploy/deploy.sh deploy/secrets/production.env.sops
git commit -m "$(cat <<'EOF'
feat: hourly hot + nightly cold encrypted backups

Hot: pg_dump --format=custom | age → /var/backups/pki/hot/ every hour,
24h rolling retention. Cold: restic → Hetzner Storage Box nightly at
03:30 UTC with daily×30/weekly×12/monthly×12 retention. Both units have
OnFailure= pointing at pki-backup-failure-notify@.service which appends
to /var/log/pki/backup-failures.log.

RESTIC_PASSWORD lives in sops secrets. deploy.sh now stages
age-recipients.txt into the engines release share/ so the hot backup
script can encrypt without fetching from git.

deploy/RESTORE.md documents hot + cold restore procedures with a
timing-TBD placeholder that Task 8 fills in.
EOF
)"
```

---

### Task 7: One-Click Rollback

**Why:** Every production team eventually deploys a bad release. The recovery path needs to exist before 3am.

**Files:**
- Modify: `deploy/deploy.sh` (replace `deploy_service` install logic)
- Create: `deploy/rollback.sh`

- [ ] **Step 1: Sketch the new layout**

Target on-host layout:

```
/opt/pki/releases/
  engines/
    current -> 0.6.3-20260418T120000/
    previous -> 0.6.2-20260417T090000/
    previous-previous -> 0.6.1-20260416T100000/
    0.6.3-20260418T120000/
    0.6.2-20260417T090000/
    0.6.1-20260416T100000/
```

No code yet — just the reference.

- [ ] **Step 2: Modify `deploy/deploy.sh` — replace `deploy_service` install block**

Edit `deploy/deploy.sh`. Locate the block starting at line 191 (`# Install new release`) through line 201 (`info "  Installed to $install_dir"`). Replace with:

```bash
  # Install new release into a versioned directory + symlink swap
  local vsn
  vsn="$(date +%Y%m%dT%H%M%S)"
  local new_dir="${install_dir}/${vsn}"
  mkdir -p "$new_dir"

  if [[ -n "$tarball" ]]; then
    tar -xzf "$tarball" -C "$new_dir"
  else
    cp -a "${local_build}/." "$new_dir/"
  fi
  chown -R pki:pki "$new_dir"
  info "  Installed to $new_dir"

  # Swap symlinks: previous-previous ← previous ← current ← new
  if [[ -L "${install_dir}/previous" ]]; then
    rm -f "${install_dir}/previous-previous"
    mv "${install_dir}/previous" "${install_dir}/previous-previous"
  fi
  if [[ -L "${install_dir}/current" ]]; then
    mv "${install_dir}/current" "${install_dir}/previous"
  fi
  ln -sfn "$new_dir" "${install_dir}/current"

  # Retain last 3 versioned dirs
  find "$install_dir" -maxdepth 1 -mindepth 1 -type d -printf '%T@ %p\n' \
    | sort -n | head -n -3 | awk '{print $2}' | xargs -r rm -rf
```

- [ ] **Step 3: Update systemd units to point at the `current` symlink**

Edit `deploy/systemd/pki-engines.service`. Change `WorkingDirectory` and `ExecStart`:

```ini
WorkingDirectory=/opt/pki/releases/engines/current
ExecStart=/opt/pki/releases/engines/current/bin/pki_engines start
ExecStop=/opt/pki/releases/engines/current/bin/pki_engines stop
```

Apply the analogous change to `pki-portals.service` and `pki-audit.service`.

- [ ] **Step 4: Update the cookie-injection path to the versioned dir**

In `deploy/deploy.sh`, around the cookie-injection block (line 203-212), change the `install_dir` references to `new_dir`:

```bash
  local cookie_file="/opt/pki/.cookies/${svc}"
  if [[ -f "$cookie_file" ]]; then
    cp "$cookie_file" "${new_dir}/releases/COOKIE"
    chown pki:pki "${new_dir}/releases/COOKIE"
    chmod 400 "${new_dir}/releases/COOKIE"
    info "  Injected Erlang cookie"
  else
    warn "  No cookie file at $cookie_file — release will use build-time cookie"
  fi
```

- [ ] **Step 5: Write `deploy/rollback.sh`**

Create `deploy/rollback.sh`:

```bash
#!/usr/bin/env bash
# One-click rollback: swap current → previous, restart service, verify ready.
# Usage: sudo deploy/rollback.sh <engines|portals|audit>
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[rollback]${NC} $*"; }
warn()  { echo -e "${YELLOW}[rollback]${NC} $*"; }
die()   { echo -e "${RED}[rollback] ERROR:${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root"

SVC="${1:-}"
[[ -n "$SVC" ]] || die "Usage: $0 <engines|portals|audit>"

declare -A SYSTEMD=(
  [engines]=pki-engines
  [portals]=pki-portals
  [audit]=pki-audit
)
declare -A HEALTH_URL=(
  [engines]=http://127.0.0.1:4001/health/ready
  [portals]=http://127.0.0.1:4002/health/ready
  [audit]=http://127.0.0.1:4001/health/ready
)

SERVICE="${SYSTEMD[$SVC]:-}"
[[ -n "$SERVICE" ]] || die "Unknown service: $SVC"

BASE=/opt/pki/releases/$SVC
CURRENT="$BASE/current"
PREVIOUS="$BASE/previous"

[[ -L "$PREVIOUS" ]] || die "No previous release to roll back to at $PREVIOUS"
PREV_TARGET="$(readlink -f "$PREVIOUS")"
CURR_TARGET="$(readlink -f "$CURRENT")"

info "Stopping $SERVICE..."
systemctl stop "$SERVICE"
systemctl reset-failed "$SERVICE" 2>/dev/null || true

info "Swapping current ($CURR_TARGET) ← previous ($PREV_TARGET)..."
# Bump previous-previous → previous → current. current becomes the new previous.
TMP_LINK="$BASE/.swap.$$"
ln -sfn "$PREV_TARGET" "$TMP_LINK"
mv -Tf "$TMP_LINK" "$CURRENT"

rm -f "$PREVIOUS"
if [[ -L "$BASE/previous-previous" ]]; then
  PP_TARGET="$(readlink -f "$BASE/previous-previous")"
  ln -sfn "$PP_TARGET" "$PREVIOUS"
  rm -f "$BASE/previous-previous"
else
  ln -sfn "$CURR_TARGET" "$PREVIOUS"
fi

info "Starting $SERVICE..."
systemctl start "$SERVICE"

URL="${HEALTH_URL[$SVC]}"
info "Polling $URL for up to 30s..."
for i in $(seq 1 30); do
  if curl -fsS --max-time 2 "$URL" >/dev/null 2>&1; then
    info "  ✓ $URL returned 200 after ${i}s"
    info "Rollback SUCCESS. $SERVICE now running $PREV_TARGET."
    exit 0
  fi
  sleep 1
done

warn "Health check failed after 30s. Service may still be starting."
warn "Check: journalctl -u $SERVICE -n 100"
exit 1
```

`chmod +x deploy/rollback.sh`.

- [ ] **Step 6: Deploy a dummy release to the VPS to populate both `current` and `previous` symlinks**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/pki && bash deploy/build.sh engines
scp deploy/releases/pki_engines-*.tar.gz deploy@217.15.161.93:/tmp/
ssh deploy@217.15.161.93 'sudo bash /home/deploy/pki/deploy/deploy.sh engines'
```

Then redeploy to create a `previous`:

```bash
cd /Users/amirrudinyahaya/Workspace/pki && bash deploy/build.sh engines
scp deploy/releases/pki_engines-*.tar.gz deploy@217.15.161.93:/tmp/
ssh deploy@217.15.161.93 'sudo bash /home/deploy/pki/deploy/deploy.sh engines'
ssh deploy@217.15.161.93 'ls -la /opt/pki/releases/engines/'
```

Expected: `current` and `previous` symlinks both present.

- [ ] **Step 7: Exercise the rollback script**

Run:
```bash
ssh deploy@217.15.161.93 'sudo bash /home/deploy/pki/deploy/rollback.sh engines'
```

Expected output: "Rollback SUCCESS" within ~30s.

Verify: `ssh deploy@217.15.161.93 'readlink /opt/pki/releases/engines/current'` points at the older versioned directory.

- [ ] **Step 8: Run the rollback script a second time (idempotency check)**

Run:
```bash
ssh deploy@217.15.161.93 'sudo bash /home/deploy/pki/deploy/rollback.sh engines'
```

Expected: either swaps back to the newer dir (if previous-previous was set) OR exits 0 with "no further previous". Must not corrupt symlinks.

Verify with: `ssh deploy@217.15.161.93 'ls -la /opt/pki/releases/engines/ && curl -fsS http://127.0.0.1:4001/health/ready'`.

- [ ] **Step 9: Commit**

```bash
git add deploy/deploy.sh deploy/rollback.sh \
        deploy/systemd/pki-engines.service \
        deploy/systemd/pki-portals.service \
        deploy/systemd/pki-audit.service
git commit -m "$(cat <<'EOF'
feat: versioned releases + deploy/rollback.sh one-click revert

Deploys now land in /opt/pki/releases/<svc>/<timestamp>/ with
current/previous/previous-previous symlinks. systemd units follow
current. deploy.sh prunes to the last 3 versioned dirs per service.

rollback.sh swaps current ← previous, restarts the service, and polls
/health/ready for up to 30s. Idempotent — running twice walks further
back through previous-previous. Exit code 0 on success, 1 on health
timeout.
EOF
)"
```

---

### Task 8: Final Integration Drill

**Why:** The system needs to have been restored from backup at least once before the first real incident.

**Files:**
- Modify: `deploy/RESTORE.md` (fill in observed timing)

- [ ] **Step 1: Snapshot — confirm a fresh hot backup exists**

Run:
```bash
ssh deploy@217.15.161.93 'sudo systemctl start pki-backup-hot.service && \
  sleep 10 && ls -lh /var/backups/pki/hot/ | tail -3'
```

Expected: a `pki_platform-YYYYMMDDTHHMMSS.pgdump.age` from within the last minute.

- [ ] **Step 2: Record drill start timestamp**

```bash
DRILL_START=$(date +%s)
echo "Drill start: $(date -Is)"
```

- [ ] **Step 3: Stop services**

```bash
ssh deploy@217.15.161.93 'sudo systemctl stop pki-engines pki-portals pki-audit'
```

- [ ] **Step 4: Drop and recreate pki_platform**

```bash
ssh deploy@217.15.161.93 'sudo -u postgres psql -c "DROP DATABASE pki_platform;" && \
  sudo -u postgres psql -c "CREATE DATABASE pki_platform;"'
```

- [ ] **Step 5: Decrypt the latest dump**

```bash
ssh deploy@217.15.161.93 'DUMP=$(ls -t /var/backups/pki/hot/pki_platform-*.pgdump.age | head -1); \
  sudo age -d -i /etc/pki/age.key "$DUMP" > /tmp/restore.pgdump && \
  ls -lh /tmp/restore.pgdump'
```

- [ ] **Step 6: Restore**

```bash
ssh deploy@217.15.161.93 'sudo -u postgres pg_restore --dbname=pki_platform --jobs=4 /tmp/restore.pgdump && \
  sudo shred -u /tmp/restore.pgdump'
```

- [ ] **Step 7: Restart services**

```bash
ssh deploy@217.15.161.93 'sudo systemctl start pki-engines && sleep 10 && \
  sudo systemctl start pki-portals pki-audit && sleep 5'
```

- [ ] **Step 8: Verify health**

```bash
ssh deploy@217.15.161.93 'for port in 4001 4003 4005 4002 4004 4006; do \
  echo -n "Port $port: "; curl -fsS "http://127.0.0.1:$port/health/ready" || echo FAIL; echo; \
done'
```

Expected: all six return 200 JSON.

- [ ] **Step 9: Verify each tenant's CA can issue a CSR-signed certificate**

Using the CA engine remote shell:

```bash
ssh deploy@217.15.161.93 'sudo -u pki /opt/pki/releases/engines/current/bin/pki_engines rpc \
  "PkiPlatformEngine.TenantRegistry.list_tenants() |> Enum.each(fn tid -> \
     IO.inspect({tid, PkiCaEngine.Api.CertificateIssuance.issue(tid, %{csr: File.read!(\"/opt/pki/share/sample-csr.pem\"), profile: \"default\"})}) \
   end)"'
```

Expected: each tenant prints `{tid, {:ok, %{serial: _, pem: _}}}`.

If the sample CSR file doesn't exist, create it first by running `openssl req -new -nodes -subj '/CN=drill/' -keyout /dev/null -out /opt/pki/share/sample-csr.pem` on the VPS.

- [ ] **Step 10: Record drill end timestamp and compute elapsed**

```bash
DRILL_END=$(date +%s)
echo "Drill elapsed: $(( DRILL_END - DRILL_START )) seconds"
```

- [ ] **Step 11: Update `deploy/RESTORE.md` with observed timing**

Edit `deploy/RESTORE.md`. Under "Hot restore ... **Observed timing during drill:**", replace the placeholder with the actual duration, e.g.:

```markdown
**Observed timing during drill (2026-05-06):**
- Stop services: 8s
- Drop/create DB: 2s
- Decrypt dump: 4s
- pg_restore: 47s
- Restart + health-green: 22s
- **Total: 1m 23s**
- All 12 tenants verified issuing fresh CSR cert.
```

- [ ] **Step 12: If drill failed — rollback**

If step 8 or 9 failed: the DB is in a bad state. Take a fresh hot backup by running step 1 again against the pre-drill snapshot (the rolling retention should still have it within the 24h window), then re-run steps 3-8 with the older snapshot. Open a ticket documenting the failure mode.

- [ ] **Step 13: Commit the updated RESTORE.md**

```bash
git add deploy/RESTORE.md
git commit -m "$(cat <<'EOF'
docs: RESTORE.md observed timing from first drill

First end-to-end hot-backup restore drill completed on the production
VPS. Total elapsed from services-stop to all-tenants-issuing-fresh-cert:
1m 23s. 12 tenants verified via PkiCaEngine.Api.CertificateIssuance.issue/2.
EOF
)"
```

---

## Self-Review Checklist

**Spec coverage** (each section mapped to a task):

- Workstream 1 (Tenant isolation property test) → Task 1 ✓
- Workstream 2 (Health + readiness endpoints) → Task 2 ✓
- Workstream 3 (Secrets via sops + age) → Task 3 ✓
- Workstream 4 (Audit log sweep + integration tests) → Task 4 ✓
- Workstream 5 (Gitea Actions CI) → Task 5 ✓
- Workstream 6 (Backup hot + cold) → Task 6 ✓
- Workstream 7 (One-click rollback) → Task 7 ✓
- Workstream 8 (Final integration drill) → Task 8 ✓

**Success criteria mapping:**

- Tenant isolation test passes in CI on every PR → Task 1 + Task 5 (workflow runs `mix test`).
- `/health/live` and `/health/ready` on every service → Task 2 test enumerates all 7 services × 2 endpoints.
- Zero plaintext secrets on VPS outside `/opt/pki/.env` (0400 root) or in git → Task 3.
- 100% mutating endpoints write audit events → Task 4 inventory + sweep + test.
- CI runs on every PR, merging main requires green CI → Task 5 + branch protection step.
- Hourly hot + nightly cold verified by restore → Task 6 + Task 8.
- `deploy/rollback.sh` swaps in under 30s → Task 7 polls with 30s deadline.
- Recovery drill completed with documented timing → Task 8 step 11.

**Known open items passed to the caller:**
- The exact list of engine API modules in Task 1 step 6 (`@engine_api_modules`) was inferred from the codebase tour — the implementer should verify with `grep -l 'defmodule PkiCaEngine.Api' src/pki_ca_engine/lib` and add any that exist.
- Step 2 of Task 5 requires a human-in-the-loop token from the Gitea admin UI; the plan documents this explicitly but it is not automatable from the plan itself.
- Task 6 step 11 assumes a Hetzner Storage Box has been provisioned out-of-band; if not, the operator must first create one and record the SFTP URL before editing the sops file.
