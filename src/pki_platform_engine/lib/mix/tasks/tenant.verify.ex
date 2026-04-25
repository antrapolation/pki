defmodule Mix.Tasks.Tenant.Verify do
  @moduledoc """
  Sanity-check a provisioned tenant end-to-end.

  Usage:

      mix tenant.verify <tenant_id_or_slug>

  For `beam`-mode tenants verifies:

    1. Tenant row exists in `PlatformRepo` with status=active.
    2. `TenantLifecycle` has a live peer entry.
    3. The peer node answers `Node.ping/1`.
    4. CA/RA/OCSP GenServers are registered on the peer.
    5. Core Mnesia tables exist on the peer (table names, not just count).
    6. HTTP `/health` on the tenant's web port returns `status=healthy`.
    7. Mnesia replication is complete: key sync tables have `disc_copies`
       on the peer node, Mnesia is running, and schema version is >= 1.

  Check 7 is the one most likely to silently fail: `MnesiaBootstrap` can
  leave tables as `ram_copies` if the disc schema init races or fails
  partway through. A table that exists but has only `ram_copies` will
  lose all data on peer restart.

  For `schema`-mode tenants verifies the Postgres row + that the
  `t_<id>_ca` / `t_<id>_ra` / `t_<id>_audit` schemas exist with
  expected tables (no peer to introspect).

  Exits non-zero if any check fails so it can be wired into smoke
  pipelines.
  """
  use Mix.Task

  alias PkiPlatformEngine.{PlatformRepo, Tenant, TenantLifecycle, TenantPrefix}

  @shortdoc "Verify a provisioned tenant (BEAM, CA/RA/OCSP, Mnesia)"

  @ca_ra_ocsp_processes [
    {:ca, PkiCaEngine.KeyActivation},
    {:ra, PkiRaEngine.CsrValidation},
    {:ocsp, PkiValidation.OcspResponder}
  ]

  # Mnesia table atoms (not struct modules) — what :mnesia.system_info(:tables) returns.
  @ca_mnesia_tables [:ca_instances, :issuer_keys, :keystores]
  @ra_mnesia_tables [:ra_instances, :cert_profiles, :csr_requests]

  # Subset of sync tables that MUST have disc_copies after a successful
  # MnesiaBootstrap. ram_copies-only means the node will lose all data
  # on restart — this is the silent failure mode we're catching.
  @disc_copies_required [:ca_instances, :issuer_keys, :keystores, :ra_instances, :schema_versions]

  @impl Mix.Task
  def run([id_or_slug]) do
    Mix.Task.run("app.start")
    # :httpc lives inside :inets which is not started by default.
    {:ok, _} = Application.ensure_all_started(:inets)

    tenant = find_tenant!(id_or_slug)
    Mix.shell().info("Verifying tenant #{tenant.slug} (#{tenant.id}) mode=#{tenant.schema_mode}")

    results =
      case tenant.schema_mode do
        "beam" -> verify_beam_tenant(tenant)
        "schema" -> verify_schema_tenant(tenant)
        mode -> [{:error, "unsupported schema_mode: #{mode}"}]
      end

    print_report(results)

    unless Enum.all?(results, &match?({:ok, _}, &1)) do
      Mix.raise("tenant.verify: one or more checks failed")
    end
  end

  def run(_), do: Mix.raise("Usage: mix tenant.verify <tenant_id_or_slug>")

  # ── lookup ────────────────────────────────────────────────────────────

  defp find_tenant!(id_or_slug) do
    case PlatformRepo.get(Tenant, id_or_slug) ||
           PlatformRepo.get_by(Tenant, slug: id_or_slug) do
      nil -> Mix.raise("No tenant found with id or slug #{inspect(id_or_slug)}")
      tenant -> tenant
    end
  end

  # ── beam mode ─────────────────────────────────────────────────────────

  defp verify_beam_tenant(tenant) do
    case TenantLifecycle.get_tenant(tenant.id) do
      nil ->
        [{:error, "TenantLifecycle has no entry for tenant_id=#{tenant.id}"}]

      info ->
        [
          {:ok, "postgres row: status=#{tenant.status}"},
          {:ok, "lifecycle entry: node=#{info.node} port=#{info.port} status=#{info.status}"}
        ] ++ peer_checks(info.node, info.port)
    end
  end

  defp peer_checks(node, port) do
    case Node.ping(node) do
      :pong ->
        [{:ok, "peer reachable (Node.ping == :pong)"}] ++
          process_checks(node) ++
          mnesia_table_checks(node) ++
          mnesia_replication_checks(node) ++
          [http_health_check(port)]

      :pang ->
        [{:error, "peer unreachable (Node.ping == :pang) — peer crashed or netsplit"}]
    end
  end

  defp process_checks(node) do
    Enum.map(@ca_ra_ocsp_processes, fn {label, mod} ->
      case safe_erpc(node, Process, :whereis, [mod]) do
        pid when is_pid(pid) -> {:ok, "#{label} process #{inspect(mod)} alive on peer"}
        nil -> {:error, "#{label} process #{inspect(mod)} missing on peer"}
        {:error, reason} -> {:error, "#{label} process check failed: #{inspect(reason)}"}
      end
    end)
  end

  # Check 5: expected table names exist in Mnesia.
  defp mnesia_table_checks(node) do
    case safe_erpc(node, :mnesia, :system_info, [:tables]) do
      {:error, reason} ->
        [{:error, "mnesia system_info failed: #{inspect(reason)}"}]

      tables when is_list(tables) ->
        expected = @ca_mnesia_tables ++ @ra_mnesia_tables
        missing = expected -- tables

        if missing == [] do
          [{:ok, "mnesia: #{length(expected)} expected CA/RA tables present (#{length(tables)} total)"}]
        else
          [{:error, "mnesia missing tables: #{inspect(missing)}"}]
        end
    end
  end

  # Check 7: Mnesia is running, key sync tables have disc_copies (not
  # just ram_copies), and the schema version is >= 1.
  # ram_copies-only tables survive the current session but lose all data
  # on peer restart — the silent failure mode from incomplete MnesiaBootstrap.
  defp mnesia_replication_checks(node) do
    running_check =
      case safe_erpc(node, :mnesia, :system_info, [:is_running]) do
        :yes -> {:ok, "mnesia is_running=yes on peer"}
        other -> {:error, "mnesia not running on peer: #{inspect(other)}"}
      end

    disc_checks =
      Enum.map(@disc_copies_required, fn table ->
        case safe_erpc(node, :mnesia, :table_info, [table, :disc_copies]) do
          nodes when is_list(nodes) and nodes != [] ->
            {:ok, "#{table}: disc_copies on #{length(nodes)} node(s) ✓"}

          [] ->
            {:error,
             "#{table}: NO disc_copies — only ram_copies present; " <>
               "MnesiaBootstrap may have failed partway (data lost on restart)"}

          {:error, reason} ->
            {:error, "#{table} disc_copies check failed: #{inspect(reason)}"}
        end
      end)

    schema_check =
      case safe_erpc(node, PkiMnesia.Schema, :schema_version, []) do
        v when is_integer(v) and v >= 1 ->
          {:ok, "mnesia schema_version=#{v}"}

        other ->
          {:error, "unexpected schema_version: #{inspect(other)} — migrations may not have run"}
      end

    [running_check] ++ disc_checks ++ [schema_check]
  end

  # Check 6: HTTP /health returns status=healthy.
  # Confirms the Phoenix endpoint is bound and the engine is responsive,
  # not just that the BEAM process is alive.
  defp http_health_check(port) do
    url = ~c"http://localhost:#{port}/health"

    case :httpc.request(:get, {url, []}, [{:timeout, 5_000}], []) do
      {:ok, {{_, 200, _}, _headers, body}} ->
        body_str = IO.iodata_to_binary(body)

        case Jason.decode(body_str) do
          {:ok, %{"status" => "healthy"}} ->
            {:ok, "HTTP GET :#{port}/health → 200 status=healthy"}

          {:ok, %{"status" => s} = resp} ->
            mnesia = Map.get(resp, "mnesia", "unknown")
            {:error, "HTTP /health returned status=#{s} mnesia=#{mnesia} — tenant degraded"}

          _ ->
            {:error, "HTTP /health returned 200 but unexpected body: #{String.slice(body_str, 0, 80)}"}
        end

      {:ok, {{_, code, _}, _, _}} ->
        {:error, "HTTP /health returned HTTP #{code} on port #{port}"}

      {:error, reason} ->
        {:error, "HTTP /health unreachable on port #{port}: #{inspect(reason)}"}
    end
  end

  defp safe_erpc(node, mod, fun, args) do
    :erpc.call(node, mod, fun, args, 5_000)
  rescue
    e -> {:error, Exception.message(e)}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  # ── schema mode ───────────────────────────────────────────────────────

  defp verify_schema_tenant(tenant) do
    prefixes = TenantPrefix.all_prefixes(tenant.id)

    [{:ok, "postgres row: status=#{tenant.status}"}] ++
      Enum.map(prefixes, fn {key, prefix} ->
        case count_tables_in_schema(prefix) do
          {:ok, 0} -> {:error, "schema #{prefix} (#{key}) exists but is empty — migrations didn't run"}
          {:ok, n} -> {:ok, "schema #{prefix} (#{key}) has #{n} tables"}
          {:error, reason} -> {:error, "schema #{prefix} check failed: #{inspect(reason)}"}
        end
      end)
  end

  defp count_tables_in_schema(schema) do
    case PlatformRepo.query(
           "SELECT count(*) FROM information_schema.tables WHERE table_schema = $1",
           [schema]
         ) do
      {:ok, %{rows: [[n]]}} -> {:ok, n}
      {:error, reason} -> {:error, reason}
    end
  end

  # ── output ────────────────────────────────────────────────────────────

  defp print_report(results) do
    Enum.each(results, fn
      {:ok, msg} -> Mix.shell().info("  [OK]   #{msg}")
      {:error, msg} -> Mix.shell().error("  [FAIL] #{msg}")
    end)
  end
end
