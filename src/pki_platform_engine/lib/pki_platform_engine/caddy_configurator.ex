defmodule PkiPlatformEngine.CaddyConfigurator do
  @moduledoc """
  Dynamic Caddy configuration via admin API.
  Adds/removes reverse proxy routes when tenants start/stop.
  """
  require Logger

  @caddy_admin_url "http://localhost:2019"

  @doc """
  Register a reverse-proxy route for a tenant.

  Idempotent: any existing route with the same `@id` (`route-<slug>`)
  is removed first so repeat calls (e.g. restart, auto-restart) don't
  stack duplicates. Caddy being unreachable surfaces as
  `{:error, :caddy_unavailable}` — callers treat that as non-fatal.
  """
  def add_route(slug, port) do
    route = build_route(slug, port)

    # Best-effort dedupe: remove any existing route carrying the same
    # @id so a restart with the same slug doesn't leave stale entries
    # in /config/apps/http/servers/srv0/routes. Ignore :not_found /
    # other delete errors — the subsequent POST is the source of truth.
    _ = delete_config("/id/route-#{slug}")

    case post_config("/config/apps/http/servers/srv0/routes", route) do
      :ok ->
        hosts = Enum.at(route["match"], 0)["host"]
        Logger.info("[caddy] Added route for #{slug} -> port #{port} (hosts: #{Enum.join(hosts, ", ")})")
        :ok

      {:error, reason} ->
        Logger.error("[caddy] Failed to add route for #{slug}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Pure route-object builder exposed for tests. Same shape Caddy's
  admin API expects on `/config/apps/http/servers/srv0/routes`.
  """
  @spec build_route(String.t(), integer()) :: map()
  def build_route(slug, port) do
    base_domain = Application.get_env(:pki_platform_engine, :base_domain, "straptrust.com")

    hosts = [
      "#{slug}.ca.#{base_domain}",
      "#{slug}.ra.#{base_domain}",
      "#{slug}.ocsp.#{base_domain}"
    ]

    %{
      "@id" => "route-#{slug}",
      "match" => [%{"host" => hosts}],
      "handle" => [
        %{
          "handler" => "reverse_proxy",
          "upstreams" => [%{"dial" => "localhost:#{port}"}]
        }
      ]
    }
  end

  def remove_route(slug) do
    Logger.info("[caddy] Removing route for #{slug}")

    case delete_config("/id/route-#{slug}") do
      :ok ->
        Logger.info("[caddy] Removed route for #{slug}")
        :ok

      {:error, reason} ->
        Logger.warning("[caddy] Failed to remove route for #{slug}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp delete_config(path) do
    url = @caddy_admin_url <> path

    case :httpc.request(
           :delete,
           {String.to_charlist(url), []},
           [],
           []
         ) do
      {:ok, {{_, status, _}, _, _}} when status in 200..299 -> :ok
      {:ok, {{_, status, _}, _, body}} -> {:error, {:http_error, status, body}}
      {:error, reason} -> {:error, reason}
    end
  rescue
    _ -> {:error, :caddy_unavailable}
  end

  defp post_config(path, body) do
    url = @caddy_admin_url <> path
    json = Jason.encode!(body)

    case :httpc.request(
           :post,
           {String.to_charlist(url), [], ~c"application/json", json},
           [],
           []
         ) do
      {:ok, {{_, status, _}, _, _}} when status in 200..299 -> :ok
      {:ok, {{_, status, _}, _, body}} -> {:error, {:http_error, status, body}}
      {:error, reason} -> {:error, reason}
    end
  rescue
    _ -> {:error, :caddy_unavailable}
  end
end
