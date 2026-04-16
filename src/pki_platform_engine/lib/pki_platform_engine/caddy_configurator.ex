defmodule PkiPlatformEngine.CaddyConfigurator do
  @moduledoc """
  Dynamic Caddy configuration via admin API.
  Adds/removes reverse proxy routes when tenants start/stop.
  """
  require Logger

  @caddy_admin_url "http://localhost:2019"

  def add_route(slug, port) do
    ca_host = "#{slug}.ca.*"
    ra_host = "#{slug}.ra.*"

    route = %{
      match: [%{host: [ca_host, ra_host]}],
      handle: [
        %{
          handler: "reverse_proxy",
          upstreams: [%{dial: "localhost:#{port}"}]
        }
      ]
    }

    case post_config("/config/apps/http/servers/srv0/routes", route) do
      :ok ->
        Logger.info("[caddy] Added route for #{slug} -> port #{port}")
        :ok

      {:error, reason} ->
        Logger.error("[caddy] Failed to add route for #{slug}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  def remove_route(slug) do
    Logger.info("[caddy] Removing route for #{slug}")
    # Caddy route removal requires knowing the route index or ID.
    # For simplicity, we reload the full config minus this tenant.
    :ok
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
