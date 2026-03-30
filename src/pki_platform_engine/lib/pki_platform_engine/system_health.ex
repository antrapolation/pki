defmodule PkiPlatformEngine.SystemHealth do
  @services [
    %{name: "CA Engine", url: "http://127.0.0.1:4001/health", port: 4001},
    %{name: "CA Portal", url: "http://127.0.0.1:4002/", port: 4002},
    %{name: "RA Engine", url: "http://127.0.0.1:4003/health", port: 4003},
    %{name: "RA Portal", url: "http://127.0.0.1:4004/", port: 4004},
    %{name: "Validation", url: "http://127.0.0.1:4005/health", port: 4005},
    %{name: "Platform Portal", url: nil, port: 4006}
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

  def check_service(%{url: nil}) do
    %{status: :healthy, response_time_ms: 0, checked_at: DateTime.utc_now()}
  end

  def check_service(%{url: url}) do
    start = System.monotonic_time(:millisecond)

    result =
      try do
        case Req.get(url, connect_options: [timeout: 2_000], receive_timeout: 2_000, retry: false) do
          {:ok, %{status: status}} when status in 200..399 ->
            :healthy
          _ ->
            :unreachable
        end
      rescue
        _ -> :unreachable
      end

    elapsed = System.monotonic_time(:millisecond) - start
    %{status: result, response_time_ms: elapsed, checked_at: DateTime.utc_now()}
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
