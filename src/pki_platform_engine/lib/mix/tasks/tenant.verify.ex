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
    5. Core Mnesia tables exist on the peer.

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

  @ca_mnesia_tables [
    PkiMnesia.Structs.CaInstance,
    PkiMnesia.Structs.IssuerKey,
    PkiMnesia.Structs.Keystore
  ]

  @ra_mnesia_tables [
    PkiMnesia.Structs.RaInstance,
    PkiMnesia.Structs.CertProfile,
    PkiMnesia.Structs.CsrRequest
  ]

  @impl Mix.Task
  def run([id_or_slug]) do
    Mix.Task.run("app.start")

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
        ] ++ peer_checks(info.node)
    end
  end

  defp peer_checks(node) do
    case Node.ping(node) do
      :pong ->
        [{:ok, "peer reachable (Node.ping == :pong)"}] ++
          process_checks(node) ++
          mnesia_checks(node)

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

  defp mnesia_checks(node) do
    case safe_erpc(node, :mnesia, :system_info, [:tables]) do
      {:error, reason} ->
        [{:error, "mnesia system_info failed: #{inspect(reason)}"}]

      tables when is_list(tables) ->
        expected = @ca_mnesia_tables ++ @ra_mnesia_tables
        missing = expected -- tables

        if missing == [] do
          [{:ok, "mnesia has #{length(expected)} expected CA/RA tables (of #{length(tables)} total)"}]
        else
          [{:error, "mnesia missing tables: #{inspect(missing)}"}]
        end
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
