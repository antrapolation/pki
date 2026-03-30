defmodule PkiPlatformEngine.SystemHealth do
  @moduledoc """
  System health checks. Checks in-process BEAM engines via TenantRegistry
  and external services via HTTP health endpoints.
  """

  alias PkiPlatformEngine.TenantRegistry

  @services [
    %{name: "CA Engine", port: 4001, check: :beam_or_http, url: "http://127.0.0.1:4001/health"},
    %{name: "CA Portal", port: 4002, check: :http, url: "http://127.0.0.1:4002/"},
    %{name: "RA Engine", port: 4003, check: :beam_or_http, url: "http://127.0.0.1:4003/health"},
    %{name: "RA Portal", port: 4004, check: :http, url: "http://127.0.0.1:4004/"},
    %{name: "Validation", port: 4005, check: :http, url: "http://127.0.0.1:4005/health"},
    %{name: "Platform Portal", port: 4006, check: :self, url: nil}
  ]

  def services, do: @services

  def check_all do
    @services
    |> Task.async_stream(&Map.merge(&1, check_service(&1)), timeout: 5_000, on_timeout: :kill_task)
    |> Enum.zip(@services)
    |> Enum.map(fn
      {{:ok, result}, _} -> result
      {{:exit, _}, service} -> Map.merge(service, %{status: :unreachable, response_time_ms: 0, checked_at: DateTime.utc_now()})
    end)
  end

  def check_service(%{check: :self}) do
    %{status: :healthy, response_time_ms: 0, checked_at: DateTime.utc_now()}
  end

  def check_service(%{check: :beam_or_http} = service) do
    # Check if any tenants have engines running in-process first
    start = System.monotonic_time(:millisecond)

    status =
      case TenantRegistry.list_tenants() do
        tenants when length(tenants) > 0 -> :healthy
        _ -> check_http(service.url)
      end

    elapsed = System.monotonic_time(:millisecond) - start
    %{status: status, response_time_ms: elapsed, checked_at: DateTime.utc_now()}
  end

  def check_service(%{check: :http, url: url}) do
    start = System.monotonic_time(:millisecond)
    status = check_http(url)
    elapsed = System.monotonic_time(:millisecond) - start
    %{status: status, response_time_ms: elapsed, checked_at: DateTime.utc_now()}
  end

  defp check_http(nil), do: :unreachable
  defp check_http(url) do
    case Req.get(url, connect_options: [timeout: 2_000], receive_timeout: 2_000, retry: false) do
      {:ok, %{status: status}} when status in 200..399 -> :healthy
      _ -> :unreachable
    end
  rescue
    _ -> :unreachable
  end

  def check_database do
    try do
      Ecto.Adapters.SQL.query!(PkiPlatformEngine.PlatformRepo, "SELECT 1")
      %{status: :healthy}
    rescue
      _ -> %{status: :unreachable}
    end
  end

  def database_count do
    case Ecto.Adapters.SQL.query(PkiPlatformEngine.PlatformRepo, "SELECT count(*) FROM pg_database WHERE datname LIKE 'pki_%'") do
      {:ok, %{rows: [[count]]}} -> count
      _ -> 0
    end
  end
end
