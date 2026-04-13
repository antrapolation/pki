defmodule PkiRaEngine.Api.Router do
  @moduledoc """
  Main Plug.Router — public routes and forwards to authenticated router.
  """

  use Plug.Router

  plug PkiPlatformEngine.Plugs.ClearTenantPrefix
  plug Plug.RequestId
  plug Plug.Telemetry, event_prefix: [:pki, :ra, :endpoint]
  plug :match
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason, length: 2_000_000
  plug :dispatch

  get "/health" do
    db_ok =
      try do
        PkiRaEngine.Repo.query!("SELECT 1")
        true
      rescue
        _ -> false
      end

    ca_url = Application.get_env(:pki_ra_engine, :ca_engine_url)
    ca_ok =
      if ca_url do
        try do
          case :httpc.request(:get, {~c"#{ca_url}/health", []}, [timeout: 3000], []) do
            {:ok, {{_, 200, _}, _, _}} -> true
            _ -> false
          end
        rescue
          _ -> false
        end
      else
        nil
      end

    status = if db_ok, do: "ok", else: "degraded"
    http_status = if db_ok, do: 200, else: 503

    body = %{
      status: status,
      checks: %{
        database: if(db_ok, do: "ok", else: "error"),
        ca_engine: cond do
          ca_ok == nil -> "not_configured"
          ca_ok -> "ok"
          true -> "unreachable"
        end
      }
    }

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(http_status, Jason.encode!(body))
  end

  get "/metrics" do
    expected = Application.get_env(:pki_ra_engine, :internal_api_secret)

    provided =
      case get_req_header(conn, "authorization") do
        ["Bearer " <> token] -> token
        [token] -> token
        _ -> nil
      end

    if expected && provided && Plug.Crypto.secure_compare(provided, expected) do
      metrics = PkiRaEngine.Telemetry.get_metrics()

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(200, Jason.encode!(metrics))
    else
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(401, Jason.encode!(%{error: "unauthorized"}))
    end
  end

  # Auth endpoints (rate-limited, no token required)
  forward "/api/v1/auth", to: PkiRaEngine.Api.AuthRouter

  # Everything else under /api/v1 requires authentication
  forward "/api/v1", to: PkiRaEngine.Api.AuthenticatedRouter

  match _ do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(404, Jason.encode!(%{error: "not_found"}))
  end
end
